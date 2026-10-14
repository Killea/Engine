//! 共享根授权判定。隐私边界在无法验证时不得放行（规格 §5.2、§13 I5）。
//!
//! 判定器只读密文清单（`SharedRootStorePort`），不碰文件系统：`Write` 与
//! `Overwrite` 的取舍由调用方按它收到的协议操作给出，这里的一次 `exists()`
//! 探测就是绕过 `delete` 授权的 TOCTOU 通道。

use std::sync::Arc;

use uc_observability_contract::{uc_info, uc_warn};

use uc_core::ids::DeviceId;
use uc_core::ports::remote_share::{
    ShareGrants, ShareOperation, ShareRootId, ShareStoreDoc, SharedRootStoreError,
    SharedRootStorePort,
};

/// 判定通过后的许可。上层在真正执行前应据此复核 grant 未被中途变更——今天这条复核就是
/// "再走一次 `authorize`"，因为每次判定都重新解密整份清单，缓存里不存在可过期的东西。
///
/// **这句话有一个已知的前提，缓存清单时就会失效（终评 Important 2 登记）。** `authorize`
/// 每次调用都要 `load()` 整份清单并做一次 AEAD 解密——grant 与根路径只存在于密文文档里，
/// 没有可局部查询的明文索引。P2 的 serve 路径大概率要按会话缓存这份清单，否则每个请求都
/// 付一次全量解密。而本类型只带 `root` 与判定时的 `grants` 快照，**没有任何代次标记**：
/// 一旦清单来自缓存，"执行前复核 grant 未被中途变更"就无从复核——用户在这两步之间撤掉
/// 或删除了这个根，缓存里那份 `SharePermit` 看上去仍然有效。
///
/// **定稿的处置（不是待选，P2 照此执行）：给许可加一个代次见证（generation witness）。**
/// 取整份清单明文的摘要（`uc-application` 已依赖 `blake3`，截断值即可），判定时算出、
/// 执行前对缓存清单重算并比对，不一致就把许可当作失效、重新判定。刻意**不**选另一种形态——
/// 在 `ShareStoreDoc` 里加一个递增的 `generation` 字段——因为 postcard 不是自描述格式，
/// 加字段必须升 `schema_version`，会撞上"同一未发布功能分支只新增一个最终持久格式版本"的
/// 约束，而摘要不需要任何持久改动。由此派生一条硬约束：**没有这个见证就不许缓存清单**，
/// 只能像上面那样每次重新 `load()`；若 P2 既缓存又不加见证，就必须把本段第一句的复核义务
/// 从本文档删掉——不许留一句已经不成立的承诺。
///
/// 字段私有、只经 accessor 读出：许可只能由本模块的判定产出，跨 crate 无法用
/// 结构体字面量伪造，于是"存在一个许可 ⇒ 门已经放行"这条保证由类型本身提供，
/// 而不是靠调用约定。先例见 `clipboard/sync/receive_gate.rs` 的
/// `MemberReceivePermit` 与 `space/membership/maintenance/model.rs` 的
/// `SpaceWorkPermit`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharePermit {
    root: ShareRootId,
    grants: ShareGrants,
}

impl SharePermit {
    /// 本次判定放行的共享根。
    #[must_use]
    pub fn root(&self) -> ShareRootId {
        self.root
    }

    /// 判定放行时该根实际生效的 grant 快照。
    #[must_use]
    pub fn grants(&self) -> ShareGrants {
        self.grants
    }
}

/// 拒绝的严重度档位，决定 `deny` 用哪一级日志。
#[derive(Clone, Copy)]
enum DenialSeverity {
    /// 对端随时可以反复触发的预期策略拒绝（暂停、根未知/禁用、grant 不足）。
    Policy,
    /// 清单读不出来，隐私边界无法验证——规格 §5.2 唯一点名 `warn!` 的一档。
    StoreUnreadable,
}

/// 共享白名单的 fail-closed 判定器。
///
/// 形状照搬 `clipboard/sync/receive_gate.rs`：拒绝与存储失败都是 `Option::None`，
/// 不区分原因也不引入错误类型。共享白名单是隐私边界，把它做成可分型的 `Result`
/// 只会给调用方留下"某个错误分支可以继续"的口子。
///
/// 本判定器的调用方是 P2 的 serve 适配器，P1 只有它自己。这里刻意以 `pub` 暴露，
/// 而不是用 `#[allow(dead_code)]` 压制"尚无调用方"这一事实。
pub struct ShareAuthorizer {
    store: Arc<dyn SharedRootStorePort>,
}

impl ShareAuthorizer {
    #[must_use]
    pub fn new(store: Arc<dyn SharedRootStorePort>) -> Self {
        Self { store }
    }

    /// 判定 `peer` 能否对 `root` 执行 `op`。任何拒绝与任何存储失败都是 `None`。
    #[must_use]
    pub async fn authorize(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        op: ShareOperation,
    ) -> Option<SharePermit> {
        // P1 的判定粒度是"根 + grant"，不按设备区分，因此本函数不消费 `peer`。
        // 这个形参出自**执行计划任务 6 的 Interfaces 段**（那里定下
        // `authorize(&self, peer: &DeviceId, root, op) -> Option<SharePermit>` 这条签名），
        // **不是**规格 §5.2：§5.2 规定的是 `Option<Permit>` 这个形状、第 3–5 步的判定顺序，
        // 并把对端身份解析放在 serve 适配器（它的第 1–2 步），并没有规定参数列表。
        // 保留它给 P2 的 serve 适配器（它要把判定与对端关联，也可能按设备粒度收紧）；
        // 若 P2 最终仍不使用它，就连带这个形参一起从签名里删掉，
        // 不要让一个空转形参长期留在授权入口上。
        let _ = peer;
        match self.store.load().await {
            Ok(doc) => self.decide(&doc, root, op),
            // 只有"清单读不出来"这一档记 warn：它是无法验证的状态（规格 §5.2）。
            Err(error) => deny(
                store_failure_reason(&error),
                DenialSeverity::StoreUnreadable,
            ),
        }
    }

    /// 规格 §5.2 的第 3–5 步：一键暂停 → 根存在且启用 → 本次操作所需 grant。
    fn decide(
        &self,
        doc: &ShareStoreDoc,
        root: ShareRootId,
        op: ShareOperation,
    ) -> Option<SharePermit> {
        if doc.suspended {
            return deny("suspended", DenialSeverity::Policy);
        }
        let Some(share) = doc.find(root) else {
            return deny("unknown_root", DenialSeverity::Policy);
        };
        if !share.enabled {
            return deny("root_disabled", DenialSeverity::Policy);
        }
        if !share.grants_allow(op) {
            return deny("grant_denied", DenialSeverity::Policy);
        }
        Some(SharePermit {
            root,
            grants: share.grants,
        })
    }
}

/// 存储失败的固定原因：只给失败种类的枚举字符串，绝不携带下层错误正文、路径或
/// 文件名（`AGENTS.md:24`）。
fn store_failure_reason(error: &SharedRootStoreError) -> &'static str {
    match error {
        SharedRootStoreError::NotUnlocked => "store_locked",
        SharedRootStoreError::Io { .. } => "store_io",
        SharedRootStoreError::Corrupt { .. } => "store_corrupt",
        SharedRootStoreError::CapacityExceeded => "store_capacity",
    }
}

/// 拒绝的唯一出口：只记一条固定原因，并按档位分级。
///
/// 分级照 `receive_gate.rs`：`suspended` / `unknown_root` / `root_disabled` /
/// `grant_denied` 是对端随时能反复触发的**预期策略事件**，记 info；只有清单读
/// 不出来（规格 §5.2 唯一点名 `warn!` 的一档）才记 warn。若策略拒绝也记 warn，
/// 一个持续探测的已配对对端就掌握了无限的 warn 洪泛杠杆。
///
/// 对端标识不进日志：观测标准要求任何输出都不出现原始 device ID 及其摘要或可恢复
/// 派生值（`docs/design-docs/observability.md`「业务记录组织标准」），
/// `scripts/architecture/check-engine-repository.mjs` 也拒绝 Application 层把对端
/// 标识按 Display 内插进 tracing 字段，而 `DeviceId` 只有 `Display` / `as_str()`
/// 两个全量出口，没有仓库认可的脱敏形式。因此这里与 `receive_gate.rs`、
/// `send_gate.rs` 一致：固定 reason 是唯一内容。按对端关联请求由持有会话的 Infra
/// serve 适配器在其自身日志中完成（规格 §5.3），它才同时握有对端身份与请求上下文。
fn deny(reason: &'static str, severity: DenialSeverity) -> Option<SharePermit> {
    match severity {
        DenialSeverity::Policy => {
            uc_info!(reason = reason, "share gate: denying inbound share request")
        }
        DenialSeverity::StoreUnreadable => {
            uc_warn!(
                reason = reason,
                "share gate: denying because shared roots cannot be read"
            )
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use std::io::{self, Write};
    use std::sync::Mutex;
    use tracing::instrument::WithSubscriber;
    use uc_core::ports::remote_share::{
        ShareGrants, ShareOperation, ShareRoot, ShareRootId, ShareStoreDoc, SharedRootStoreError,
        SharedRootStorePort,
    };

    /// 敏感哨兵：清单里写什么、对端是谁、下层错误正文里塞什么，拒绝日志都不许出现。
    const SENTINEL_PEER: &str = "sensitive-peer-device";
    const SENTINEL_PATH: &str = "/srv/sensitive-path";
    const SENTINEL_LABEL: &str = "sensitive-label";

    /// 存储失败的种类。
    ///
    /// `SharedRootStoreError` 的负载（`std::io::Error` / `anyhow::Error`）不是
    /// `Clone`，替身因此按种类存状态、每次 `load` 重新构造错误：同一个替身可被
    /// 反复调用且永远 fail-closed。Io 与 Corrupt 的正文里刻意塞进清单同款哨兵，
    /// 用来证明"把下层错误带进日志"这类回归写不出来。
    #[derive(Debug, Clone, Copy)]
    enum Failure {
        Locked,
        Io,
        Corrupt,
        Capacity,
    }

    impl Failure {
        fn error(self) -> SharedRootStoreError {
            match self {
                Self::Locked => SharedRootStoreError::NotUnlocked,
                Self::Io => SharedRootStoreError::Io {
                    source: io::Error::other(SENTINEL_PATH),
                },
                Self::Corrupt => SharedRootStoreError::Corrupt {
                    source: anyhow::anyhow!("payload of {SENTINEL_LABEL} is unreadable"),
                },
                Self::Capacity => SharedRootStoreError::CapacityExceeded,
            }
        }

        /// 该种类对应的固定日志原因，与 `store_failure_reason()` 一一对应。
        fn reason(self) -> &'static str {
            match self {
                Self::Locked => "store_locked",
                Self::Io => "store_io",
                Self::Corrupt => "store_corrupt",
                Self::Capacity => "store_capacity",
            }
        }

        /// 错误正文中应当出现的哨兵（`Locked` 与 `Capacity` 没有负载，故为空）。
        fn sentinel_in_payload(self) -> &'static str {
            match self {
                Self::Io => SENTINEL_PATH,
                Self::Corrupt => SENTINEL_LABEL,
                Self::Locked | Self::Capacity => "",
            }
        }
    }

    enum StubState {
        Doc(ShareStoreDoc),
        Fail(Failure),
    }

    struct StubStore {
        state: StubState,
    }

    impl StubStore {
        fn with(doc: ShareStoreDoc) -> Self {
            Self {
                state: StubState::Doc(doc),
            }
        }
        fn failing() -> Self {
            Self::failing_with(Failure::Locked)
        }
        fn failing_with(failure: Failure) -> Self {
            Self {
                state: StubState::Fail(failure),
            }
        }
    }

    #[async_trait]
    impl SharedRootStorePort for StubStore {
        async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
            match &self.state {
                StubState::Doc(doc) => Ok(doc.clone()),
                StubState::Fail(failure) => Err(failure.error()),
            }
        }
        async fn save(&self, _doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
            Ok(())
        }
    }

    /// 只把日志写进内存缓冲，用于断言拒绝的级别与内容（同 `clipboard/sync/send_gate.rs`）。
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(Arc::clone(&self.0))
        }
    }

    impl CapturedLogs {
        fn output(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    fn peer() -> DeviceId {
        DeviceId::new(SENTINEL_PEER)
    }

    fn doc_with(
        grants: ShareGrants,
        enabled: bool,
        suspended: bool,
    ) -> (ShareRootId, ShareStoreDoc) {
        let root = ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: SENTINEL_PATH.to_owned(),
            label: SENTINEL_LABEL.to_owned(),
            grants,
            enabled,
            added_at_ms: 0,
        };
        let id = root.id;
        let mut doc = ShareStoreDoc::new();
        doc.suspended = suspended;
        doc.roots.push(root);
        (id, doc)
    }

    /// 跑一次判定，返回决策与它写出的日志文本。
    async fn authorize_with_logs(
        gate: &ShareAuthorizer,
        root: ShareRootId,
        op: ShareOperation,
    ) -> (Option<SharePermit>, String) {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(logs.clone())
            .finish();
        let decision = gate
            .authorize(&peer(), root, op)
            .with_subscriber(subscriber)
            .await;
        (decision, logs.output())
    }

    /// 断言一条拒绝：决策是 `None`，日志里只有固定原因，级别落在 `expected_level`
    /// 这一档（另一档不得出现），且不含任何哨兵。
    async fn assert_denied(
        gate: &ShareAuthorizer,
        root: ShareRootId,
        op: ShareOperation,
        expected_reason: &str,
        expected_level: &str,
    ) {
        let (decision, output) = authorize_with_logs(gate, root, op).await;
        assert!(decision.is_none(), "`{expected_reason}` 必须拒绝");
        assert!(
            output.contains(expected_reason),
            "拒绝日志必须带固定原因 `{expected_reason}`，实际：{output}"
        );
        assert!(
            output.contains(expected_level),
            "拒绝 `{expected_reason}` 必须记在 {expected_level}，实际：{output}"
        );
        let other_level = if expected_level == "INFO" {
            "WARN"
        } else {
            "INFO"
        };
        assert!(
            !output.contains(other_level),
            "拒绝 `{expected_reason}` 不得记在 {other_level}，实际：{output}"
        );
        assert_no_sentinel(&output, expected_reason);
    }

    fn assert_no_sentinel(output: &str, context: &str) {
        for forbidden in [SENTINEL_PEER, SENTINEL_PATH, SENTINEL_LABEL] {
            assert!(
                !output.contains(forbidden),
                "{context} 的日志泄漏了 `{forbidden}`：{output}"
            );
        }
    }

    /// 规格 §13 I5：存储失败一律拒绝。
    #[tokio::test]
    async fn store_failure_fails_closed() {
        let gate = ShareAuthorizer::new(Arc::new(StubStore::failing()));
        assert!(gate
            .authorize(
                &peer(),
                ShareRootId(uuid::Uuid::new_v4()),
                ShareOperation::List
            )
            .await
            .is_none());
    }

    /// `SharedRootStoreError` 的四个变体都要走到拒绝路径，且各自记 warn + 固定原因，
    /// 并且不得把下层错误正文带进日志。
    #[tokio::test]
    async fn every_store_error_variant_fails_closed() {
        let unknown_root = ShareRootId(uuid::Uuid::new_v4());
        for failure in [
            Failure::Locked,
            Failure::Io,
            Failure::Corrupt,
            Failure::Capacity,
        ] {
            // 先确认哨兵确实存在于错误正文里，否则下面"日志里搜不到"就是空断言。
            let sentinel = failure.sentinel_in_payload();
            if !sentinel.is_empty() {
                assert!(
                    format!("{:?}", failure.error()).contains(sentinel),
                    "替身错误正文应含 `{sentinel}`，实际：{:?}",
                    failure.error()
                );
            }

            let gate = ShareAuthorizer::new(Arc::new(StubStore::failing_with(failure)));
            assert_denied(
                &gate,
                unknown_root,
                ShareOperation::List,
                failure.reason(),
                "WARN",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn suspended_store_denies_everything() {
        let (id, doc) = doc_with(
            ShareGrants {
                read: true,
                write: true,
                delete: true,
            },
            true,
            true,
        );
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert!(gate
            .authorize(&peer(), id, ShareOperation::List)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn disabled_root_is_denied() {
        let (id, doc) = doc_with(
            ShareGrants {
                read: true,
                write: true,
                delete: true,
            },
            false,
            false,
        );
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert!(gate
            .authorize(&peer(), id, ShareOperation::List)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn unknown_root_is_denied() {
        let (_id, doc) = doc_with(ShareGrants::default(), true, false);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert!(gate
            .authorize(
                &peer(),
                ShareRootId(uuid::Uuid::new_v4()),
                ShareOperation::List
            )
            .await
            .is_none());
    }

    #[tokio::test]
    async fn read_grant_does_not_imply_write() {
        let (id, doc) = doc_with(
            ShareGrants {
                read: true,
                write: false,
                delete: false,
            },
            true,
            false,
        );
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert!(gate
            .authorize(&peer(), id, ShareOperation::List)
            .await
            .is_some());
        assert!(gate
            .authorize(&peer(), id, ShareOperation::Write)
            .await
            .is_none());
    }

    /// 许可必须携带本次判定实际生效的 grants，供上层在提交点复核。
    #[tokio::test]
    async fn permit_carries_the_grants_that_authorized_it() {
        let grants = ShareGrants {
            read: true,
            write: true,
            delete: true,
        };
        let (id, doc) = doc_with(grants, true, false);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));

        let permit = gate
            .authorize(&peer(), id, ShareOperation::Rename)
            .await
            .expect("permit");
        assert_eq!(permit.root(), id);
        assert_eq!(permit.grants(), grants);
    }

    /// 策略性拒绝是对端可反复触发的预期事件，记 info（规格 §5.2 只把 warn 留给
    /// "清单读不出来"）。四条策略拒绝路径各自固定原因齐备。
    #[tokio::test]
    async fn policy_denials_log_at_info() {
        let read_only = ShareGrants {
            read: true,
            write: false,
            delete: false,
        };

        let (suspended_id, doc) = doc_with(read_only, true, true);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert_denied(
            &gate,
            suspended_id,
            ShareOperation::List,
            "suspended",
            "INFO",
        )
        .await;

        let (_known_root, doc) = doc_with(read_only, true, false);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert_denied(
            &gate,
            ShareRootId(uuid::Uuid::new_v4()),
            ShareOperation::List,
            "unknown_root",
            "INFO",
        )
        .await;

        let (disabled_id, doc) = doc_with(read_only, false, false);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert_denied(
            &gate,
            disabled_id,
            ShareOperation::List,
            "root_disabled",
            "INFO",
        )
        .await;

        let (granted_id, doc) = doc_with(read_only, true, false);
        let gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        assert_denied(
            &gate,
            granted_id,
            ShareOperation::Write,
            "grant_denied",
            "INFO",
        )
        .await;
    }

    /// 规格 §13 I4 与 `AGENTS.md:24`：拒绝日志只有固定原因——绝对路径、label、
    /// 对端标识，以及下层错误的正文一律不得出现。策略拒绝与存储失败两条线都要过：
    /// 后者正是最初被写成内插下层错误的那一行，最容易被改回去。
    #[tokio::test]
    async fn denial_logs_carry_only_a_fixed_reason() {
        let (id, doc) = doc_with(ShareGrants::default(), true, false);
        let policy_gate = ShareAuthorizer::new(Arc::new(StubStore::with(doc)));
        let (_, policy_output) = authorize_with_logs(&policy_gate, id, ShareOperation::List).await;
        assert!(
            policy_output.contains("grant_denied"),
            "拒绝必须可由固定原因观察到，实际：{policy_output}"
        );
        assert_no_sentinel(&policy_output, "策略拒绝");

        let store_gate = ShareAuthorizer::new(Arc::new(StubStore::failing_with(Failure::Io)));
        let (store_decision, store_output) =
            authorize_with_logs(&store_gate, id, ShareOperation::List).await;
        assert!(store_decision.is_none());
        assert!(
            store_output.contains("store_io"),
            "存储失败必须可由固定原因观察到，实际：{store_output}"
        );
        assert_no_sentinel(&store_output, "存储失败拒绝");
    }
}
