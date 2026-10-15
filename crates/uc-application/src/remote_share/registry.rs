//! 共享根清单的唯一写路径责任人（exec plan §2.5）。
//!
//! 约束登记表是纯内存结构：进程重启后里面没有根，`ListRoots` 却依然按持久化
//! 清单应答——没有登记步骤的话每个操作都会 `RootGone`。本模块把「清单内容 ⇄
//! 登记表成员」做成一个事务化收敛：
//!
//! - `reconcile_startup`：启动时 load → 按清单登记 enabled 根、撤销其余。
//! - `replace_doc`：save 成功后按新清单收敛（suspended 即全量撤销）；save
//!   失败则不收敛——清单没换，登记表也不许动。
//!
//! 登记表没有列举 API，本责任人自己记 `registered` 集合，收敛时凭它计算要
//! 撤销的旧根；集合与登记表同生共死（同一对象持有两端的引用）。
//!
//! 错误立场与 authorizer 相同：单个根登记失败（路径消失、保留名占用、I/O）
//! 只让该根缺席（`RootGone` fail-closed），不阻断其余根的登记；清单读不出来
//! 时全量撤销，绝不留着旧表继续服务一份读不出来的状态。

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use uc_core::ports::remote_share::{
    ConfineError, ShareConfinementPort, ShareRootId, ShareStoreDoc, SharedRootStoreError,
    SharedRootStorePort,
};
use uc_observability_contract::{uc_info, uc_warn};

/// 共享根清单 ↔ 约束登记表的收敛责任人。
pub struct ShareRootsRegistry {
    share_store: Arc<dyn SharedRootStorePort>,
    confinement: Arc<dyn ShareConfinementPort>,
    /// 本责任人登记过的根 id；登记表不给列举 API，撤销谁只能靠这份自记集合。
    /// `std::sync::Mutex` 足矣：持锁区间全是同步集合读写，从不跨 `.await`。
    registered: Mutex<HashSet<ShareRootId>>,
    /// 清单写路径的串行闸：load→save→收敛必须对其它写者整体互斥，否则
    /// 并发 PUT/suspend 会交错丢更新（读-改-写竞态）。
    doc_write: tokio::sync::Mutex<()>,
}

/// 一次收敛的稳定结果（供装配层记录/判定，不携带任何路径或根标识明细）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileReport {
    /// 本次成功登记（或保持登记）的启用根数。
    pub registered: usize,
    /// 清单内启用但登记失败的根数；这些根对 serve 表现为 `RootGone`。
    pub failed: usize,
    /// 被撤销的根数：禁用、被移出清单、挂起或清单不可读。
    pub unregistered: usize,
}

impl ShareRootsRegistry {
    pub fn new(
        share_store: Arc<dyn SharedRootStorePort>,
        confinement: Arc<dyn ShareConfinementPort>,
    ) -> Self {
        Self {
            share_store,
            confinement,
            registered: Mutex::new(HashSet::new()),
            doc_write: tokio::sync::Mutex::new(()),
        }
    }

    /// 启动收敛：清单读不出来就全量撤销（fail-closed，与 authorizer 对
    /// 清单读取失败的同一立场），单个根失败只影响该根自己。
    pub async fn reconcile_startup(&self) -> ReconcileReport {
        match self.share_store.load().await {
            Ok(doc) => self.reconcile_doc(&doc).await,
            Err(_) => {
                let unregistered = self.unregister_all().await;
                uc_warn!(
                    reason = "store_load",
                    "share roots: store unreadable; all registrations revoked"
                );
                ReconcileReport {
                    unregistered,
                    ..ReconcileReport::default()
                }
            }
        }
    }

    /// 会话结束收口：撤销本责任人登记过的全部根，释放根目录句柄。
    /// 不改清单——共享意愿是会话间持久的事实，登记表只是会话期投影。
    pub async fn revoke_all(&self) {
        let unregistered = self.unregister_all().await;
        uc_info!(
            removed = unregistered,
            "share roots: session ended; all registrations revoked"
        );
    }

    /// 清单读路径：本机共享管理面（`GET /remote-share/state`）的取数口。
    /// 文档归本责任人管，读取同样只走这里——登记表不对外列根。
    pub async fn current_doc(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
        self.share_store.load().await
    }

    /// 清单写路径：先持久化，落盘成功才按新清单收敛；save 失败原样上抛，
    /// 登记表保持与旧清单一致——两半状态机不允许各走各的。
    pub async fn replace_doc(
        &self,
        doc: &ShareStoreDoc,
    ) -> Result<ReconcileReport, SharedRootStoreError> {
        let _write = self.doc_write.lock().await;
        self.share_store.save(doc).await?;
        Ok(self.reconcile_doc(doc).await)
    }

    /// 读-改-写清单：写锁内 load→mutate→save→收敛。并发写者串行化，
    /// 不丢更新；`mutate` 只作用于内存文档，save 失败时登记表保持旧态。
    pub async fn update_doc(
        &self,
        mutate: impl FnOnce(&mut ShareStoreDoc),
    ) -> Result<ReconcileReport, SharedRootStoreError> {
        let _write = self.doc_write.lock().await;
        let mut doc = self.share_store.load().await?;
        mutate(&mut doc);
        self.share_store.save(&doc).await?;
        Ok(self.reconcile_doc(&doc).await)
    }

    /// 按一份已取出的清单收敛登记表：启用根登记、其余撤销；`suspended` 时
    /// 期望集为空，等价于全量撤销。
    async fn reconcile_doc(&self, doc: &ShareStoreDoc) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        let mut desired = HashSet::new();
        if !doc.suspended {
            for root in doc.roots.iter().filter(|root| root.enabled) {
                desired.insert(root.id);
            }
        }

        // 已登记但新清单不再期望的根：撤销。
        let stale: Vec<ShareRootId> = match self.registered.lock() {
            Ok(set) => set.difference(&desired).copied().collect(),
            Err(poisoned) => poisoned
                .into_inner()
                .difference(&desired)
                .copied()
                .collect(),
        };
        for root in stale {
            self.confinement.unregister_root(root).await;
            if let Ok(mut set) = self.registered.lock() {
                set.remove(&root);
            }
            report.unregistered += 1;
        }

        // 期望集里尚未登记的根：登记；失败只让该根缺席。
        for root in doc
            .roots
            .iter()
            .filter(|root| root.enabled && !doc.suspended && desired.contains(&root.id))
        {
            if self
                .registered
                .lock()
                .map(|set| set.contains(&root.id))
                .unwrap_or(false)
            {
                report.registered += 1;
                continue;
            }
            let confinement = Arc::clone(&self.confinement);
            let root_id = root.id;
            let path = std::path::PathBuf::from(&root.path);
            // 登记表动词是同步 fs 工作穿 async 外衣；整段登记（canonicalize +
            // 打开句柄 + 根内扫描）卸载到阻塞线程，不压 executor。
            let outcome = tokio::task::spawn_blocking(move || {
                futures::executor::block_on(confinement.register_root(root_id, &path))
            })
            .await;
            match outcome {
                Ok(Ok(())) => {
                    if let Ok(mut set) = self.registered.lock() {
                        set.insert(root_id);
                    }
                    report.registered += 1;
                }
                Ok(Err(error)) => {
                    report.failed += 1;
                    uc_warn!(
                        reason = confine_reason(&error),
                        "share roots: root registration failed; root left unregistered"
                    );
                }
                Err(_) => {
                    report.failed += 1;
                    uc_warn!(
                        reason = "join",
                        "share roots: root registration task failed; root left unregistered"
                    );
                }
            }
        }
        uc_info!(
            root_count = report.registered,
            failed = report.failed,
            removed = report.unregistered,
            "share roots: registry reconciled with the share document"
        );
        report
    }

    /// 撤销本责任人登记过的全部根（清单不可读或挂起时的收口）。
    async fn unregister_all(&self) -> usize {
        let stale: Vec<ShareRootId> = match self.registered.lock() {
            Ok(set) => set.iter().copied().collect(),
            Err(poisoned) => poisoned.into_inner().iter().copied().collect(),
        };
        let mut unregistered = 0;
        for root in stale {
            self.confinement.unregister_root(root).await;
            unregistered += 1;
        }
        if let Ok(mut set) = self.registered.lock() {
            set.clear();
        }
        unregistered
    }
}

/// 日志只记失败种类字面量：`ConfineError::Io` 的 source 是下层 io 错误，
/// 正文可能携带路径，绝不带进字段值（与 authorizer 的同一规则）。
fn confine_reason(error: &ConfineError) -> &'static str {
    match error {
        ConfineError::Denied => "denied",
        ConfineError::ReservedName => "reserved_name",
        ConfineError::NotFound => "not_found",
        ConfineError::Conflict => "conflict",
        ConfineError::NotADirectory => "not_a_directory",
        ConfineError::IsADirectory => "is_a_directory",
        ConfineError::RootGone => "root_gone",
        ConfineError::Io { .. } => "io",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use uc_core::ports::remote_share::{
        ConfinedDirEntry, ConfinedMetadata, ConfinedTarget, ConfinedTrashPage, ConflictPolicy,
        ShareGrants, ShareRoot, ShareStagedEntry,
    };

    // ----- test doubles ------------------------------------------------------

    /// `SharedRootStoreError` 不可 `Clone`，load 的"坏掉"状态用开关模拟。
    struct StubStore {
        doc: Mutex<ShareStoreDoc>,
        fail_load: AtomicBool,
        saves: AtomicUsize,
    }

    impl StubStore {
        fn with(doc: ShareStoreDoc) -> Arc<Self> {
            Arc::new(Self {
                doc: Mutex::new(doc),
                fail_load: AtomicBool::new(false),
                saves: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl SharedRootStorePort for StubStore {
        async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
            if self.fail_load.load(Ordering::Relaxed) {
                return Err(SharedRootStoreError::NotUnlocked);
            }
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            Ok(self.doc.lock().expect("doc").clone())
        }
        async fn save(&self, doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
            self.saves.fetch_add(1, Ordering::Relaxed);
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            *self.doc.lock().expect("doc") = doc.clone();
            Ok(())
        }
    }

    /// 记录登记/撤销集合的约束替身：`fail_on` 内的根登记返回 `NotFound`；
    /// 其余动词本测试不触达，一律固定 `Denied`（不是无操作，避免假成功）。
    struct StubConfinement {
        registered: Mutex<HashSet<ShareRootId>>,
        fail_on: HashSet<ShareRootId>,
    }

    impl StubConfinement {
        fn with(fail_on: HashSet<ShareRootId>) -> Arc<Self> {
            Arc::new(Self {
                registered: Mutex::new(HashSet::new()),
                fail_on,
            })
        }
        fn registered_set(&self) -> HashSet<ShareRootId> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("registered").clone()
        }
        fn set(&self) -> std::sync::MutexGuard<'_, HashSet<ShareRootId>> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("registered")
        }
    }

    fn deny<T>() -> Result<T, ConfineError> {
        Err(ConfineError::Denied)
    }

    #[async_trait]
    impl ShareConfinementPort for StubConfinement {
        async fn register_root(&self, root: ShareRootId, _path: &Path) -> Result<(), ConfineError> {
            if self.fail_on.contains(&root) {
                return Err(ConfineError::NotFound);
            }
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("registered").insert(root);
            Ok(())
        }
        async fn unregister_root(&self, root: ShareRootId) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("registered").remove(&root);
        }
        async fn is_registered(&self, root: ShareRootId) -> bool {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("registered").contains(&root)
        }
        async fn resolve(
            &self,
            _root: ShareRootId,
            _client_rel: &str,
        ) -> Result<ConfinedTarget, ConfineError> {
            deny()
        }
        async fn resolve_root(&self, _root: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
            deny()
        }
        async fn target_metadata(
            &self,
            _target: &ConfinedTarget,
        ) -> Result<ConfinedMetadata, ConfineError> {
            deny()
        }
        async fn target_child_metadata(
            &self,
            _target: &ConfinedTarget,
            _name: &str,
        ) -> Result<ConfinedMetadata, ConfineError> {
            deny()
        }
        async fn target_read_dir(
            &self,
            _target: &ConfinedTarget,
        ) -> Result<Vec<ConfinedDirEntry>, ConfineError> {
            deny()
        }
        async fn target_open_read(
            &self,
            _target: &ConfinedTarget,
        ) -> Result<std::fs::File, ConfineError> {
            deny()
        }
        async fn target_create_dir(&self, _target: &ConfinedTarget) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_rename(
            &self,
            _from: &ConfinedTarget,
            _to: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_copy_into(
            &self,
            _from: &ConfinedTarget,
            _to: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_move_to_trash(
            &self,
            _target: &ConfinedTarget,
        ) -> Result<String, ConfineError> {
            deny()
        }
        async fn list_trash(
            &self,
            _root: ShareRootId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ConfinedTrashPage, ConfineError> {
            deny()
        }
        async fn restore_from_trash(
            &self,
            _root: ShareRootId,
            _trash_id: &str,
            _to: &ConfinedTarget,
        ) -> Result<String, ConfineError> {
            deny()
        }
        async fn empty_trash(&self, _root: ShareRootId) -> Result<(), ConfineError> {
            deny()
        }
        async fn create_staging(&self, _root: ShareRootId) -> Result<String, ConfineError> {
            deny()
        }
        async fn staging_entry_path(
            &self,
            _root: ShareRootId,
            _staging_id: &str,
            _rel: &str,
            _is_dir: bool,
        ) -> Result<PathBuf, ConfineError> {
            deny()
        }
        async fn commit_staging(
            &self,
            _root: ShareRootId,
            _staging_id: &str,
            _dir: &ConfinedTarget,
            _entries: &[ShareStagedEntry],
            _policy: ConflictPolicy,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn abort_staging(
            &self,
            _root: ShareRootId,
            _staging_id: &str,
        ) -> Result<(), ConfineError> {
            deny()
        }
    }

    fn root(id_byte: u8, enabled: bool) -> ShareRoot {
        ShareRoot {
            id: root_id(id_byte),
            path: format!("/srv/root-{id_byte}"),
            label: format!("root {id_byte}"),
            grants: ShareGrants {
                read: true,
                write: true,
                delete: false,
            },
            enabled,
            added_at_ms: 0,
        }
    }

    fn doc(roots: Vec<ShareRoot>, suspended: bool) -> ShareStoreDoc {
        ShareStoreDoc {
            schema_version: ShareStoreDoc::CURRENT_SCHEMA_VERSION,
            suspended,
            roots,
        }
    }

    // ----- reconcile behaviour -----------------------------------------------

    fn port_store(store: &Arc<StubStore>) -> Arc<dyn SharedRootStorePort> {
        Arc::clone(store) as Arc<dyn SharedRootStorePort>
    }

    fn port_confinement(confinement: &Arc<StubConfinement>) -> Arc<dyn ShareConfinementPort> {
        Arc::clone(confinement) as Arc<dyn ShareConfinementPort>
    }

    fn root_id(id_byte: u8) -> ShareRootId {
        let mut bytes = [0u8; 16];
        bytes[0] = id_byte;
        ShareRootId::from_wire_bytes(bytes)
    }

    #[tokio::test]
    async fn startup_registers_enabled_roots_only() {
        let store = StubStore::with(doc(vec![root(1, true), root(2, false)], false));
        let confinement = StubConfinement::with(HashSet::new());
        let registry = ShareRootsRegistry::new(port_store(&store), port_confinement(&confinement));
        let report = registry.reconcile_startup().await;
        assert_eq!(
            report,
            ReconcileReport {
                registered: 1,
                failed: 0,
                unregistered: 0,
            }
        );
        assert_eq!(confinement.registered_set().len(), 1);
        assert!(confinement.registered_set().contains(&root_id(1)));
    }

    #[tokio::test]
    async fn unreadable_store_revokes_everything() {
        // 先有一份正常清单并收敛出登记，再让 store 变不可读重跑启动收敛。
        let store = StubStore::with(doc(vec![root(1, true)], false));
        let confinement = StubConfinement::with(HashSet::new());
        let registry = ShareRootsRegistry::new(port_store(&store), port_confinement(&confinement));
        registry.reconcile_startup().await;
        store.fail_load.store(true, Ordering::Relaxed);
        let report = registry.reconcile_startup().await;
        assert_eq!(report.unregistered, 1);
        assert!(confinement.registered_set().is_empty());
    }

    #[tokio::test]
    async fn replace_doc_saves_then_reconciles() {
        // 初始清单根 1、2 启用，启动收敛登记二者。
        let store = StubStore::with(doc(vec![root(1, true), root(2, true)], false));
        // 新清单里根 4 将登记失败。
        let failing: HashSet<_> = [root_id(4)].into_iter().collect();
        let confinement = StubConfinement::with(failing);
        let registry = ShareRootsRegistry::new(port_store(&store), port_confinement(&confinement));
        registry.reconcile_startup().await;

        // 新清单：根 1 禁用、根 2 保留、根 3 新增、根 4 启用但登记失败。
        let new_doc = doc(
            vec![root(1, false), root(2, true), root(3, true), root(4, true)],
            false,
        );
        let report = registry.replace_doc(&new_doc).await.expect("replace");
        assert_eq!(report.registered, 2); // 根 2 保持 + 根 3 新登记
        assert_eq!(report.failed, 1); // 根 4 登记失败
        assert_eq!(report.unregistered, 1); // 根 1 撤销
        let set = confinement.registered_set();
        assert!(set.contains(&new_doc.roots[1].id));
        assert!(set.contains(&new_doc.roots[2].id));
        assert!(!set.contains(&new_doc.roots[0].id));
        assert!(!set.contains(&new_doc.roots[3].id));
        assert!(store.saves.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn suspended_doc_revokes_all() {
        let store = StubStore::with(doc(vec![root(1, true), root(2, true)], false));
        let confinement = StubConfinement::with(HashSet::new());
        let registry = ShareRootsRegistry::new(port_store(&store), port_confinement(&confinement));
        registry.reconcile_startup().await;
        let report = registry
            .replace_doc(&doc(vec![root(1, true), root(2, true)], true))
            .await
            .expect("suspend");
        assert_eq!(report.unregistered, 2);
        assert!(confinement.registered_set().is_empty());
    }

    #[tokio::test]
    async fn failed_save_leaves_registry_untouched() {
        struct FailingStore;
        #[async_trait]
        impl SharedRootStorePort for FailingStore {
            async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
                Ok(doc(vec![root(1, true)], false))
            }
            async fn save(&self, _doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
                Err(SharedRootStoreError::NotUnlocked)
            }
        }
        let confinement = StubConfinement::with(HashSet::new());
        let registry =
            ShareRootsRegistry::new(Arc::new(FailingStore), port_confinement(&confinement));
        registry.reconcile_startup().await;
        assert_eq!(confinement.set().len(), 1);
        let outcome = registry.replace_doc(&doc(vec![], false)).await;
        assert!(outcome.is_err());
        // save 没成功，登记表保持旧状态：根 1 仍然登记着。
        assert_eq!(confinement.set().len(), 1);
    }
}
