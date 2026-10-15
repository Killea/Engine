//! 设备文件共享的出站（请求方）流程负责人。
//!
//! `RemoteShareClient` 是"向某台已配对 peer 发起 remote-share 动作"的唯一完整
//! 负责人：浏览与变更动词原样委托 [`RemoteShareClientPort`]，两个传输动作
//! 由本模块编排完整生命周期——
//!
//! * **upload**：枚举本地来源 → `publish_path` 入本机 blob store 并签票 →
//!   按请求体预算分片 `stage_upload` → `commit_upload`；任一环节失败先把已
//!   建立的 staging 集 `abort_upload` 干净，落定后 `untag` 释放本机暂挂。
//! * **download**：`export` 拿对端签发的票据 → `fetch_to_path` 落地本机。
//!
//! `transfer_id` 由本模块按次铸出并回给调用方——holder 拉取进度经既有
//! transfer-progress 反向通道以此键关联，出站侧不需要本机再发进度帧。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use uc_core::ids::DeviceId;
use uc_core::ports::blob::{
    BlobDigest, BlobError, BlobProgressSink, BlobTicket, BlobTransferPort, TagReason,
};
use uc_core::ports::remote_share::{
    is_reserved_share_component, is_well_formed_relative, RemoteShareClientError,
    RemoteShareClientPort, ShareAvailability, ShareClientDeny, ShareDirectoryEntry,
    ShareDirectoryPage, ShareExportOutcome, ShareRootDescriptor, ShareRootId, ShareStageEntry,
    ShareStageOutcome, ShareTransferId, ShareTrashPage,
};

/// 单个 `stage_upload` 请求体的估算预算。线上请求硬顶 64KiB；留 16KiB 给
/// 信封/opcode/其它字段与 postcard 编码浮动，估算项取 `rel + ticket + 64B`。
const STAGE_MANIFEST_BUDGET: usize = 48 * 1024;

/// `upload` 动作的一个本地来源：由调用方（daemon/UI 选择器）给出的本地
/// 绝对路径。本机路径从不上 wire——只有它推导出的相对路径进清单。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareUploadSource {
    pub local: PathBuf,
}

/// `upload` 完成后的结算：调用方按 `transfer_id` 关联 holder 回报过来的
/// 拉取进度；计数用于 UI 呈现与审计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareUploadReport {
    /// 本次上传的进度关联键（UUID 字节），holder 的 pull 进度以此上报。
    pub transfer_id: ShareTransferId,
    /// 实际 staged+commit 的文件条目数。
    pub files: usize,
    /// 实际 staged+commit 的目录条目数。
    pub dirs: usize,
    /// 枚举时被跳过（symlink / 非 UTF-8 名 / 保留名 / 特殊文件）的条目数。
    pub skipped: usize,
    /// 全部文件条目的声明字节合计。
    pub total_bytes: u64,
}

/// 出站共享动作的稳定失败分类。下层错误一律保留 source chain。
#[derive(Debug, thiserror::Error)]
pub enum ShareOutboundError {
    /// 对端请求级失败（不可达 / deny / 协议违例 / 帧 IO）。
    #[error("remote share request failed")]
    Remote(#[source] RemoteShareClientError),
    /// 本机枚举 / 元数据读取失败。
    #[error("local source enumeration failed")]
    Enumerate(#[source] std::io::Error),
    /// 本机 blob 发布 / 票据签发 / 拉取失败。
    #[error("blob staging failed")]
    Blob(#[source] BlobError),
    /// 来源枚举后没有任何可上传条目。
    #[error("nothing to upload")]
    Empty,
}

/// 出站 remote-share 动作的唯一负责人。
pub struct RemoteShareClient {
    client: Arc<dyn RemoteShareClientPort>,
    blobs: Arc<dyn BlobTransferPort>,
    /// 在途上传持有的 blob 暂挂租约。任务被会话拆除打断时这些租约留在
    /// store 上成永久 pin——`release_inflight` 是会话关闭时的清算口。
    active_leases: Mutex<Vec<TagReason>>,
}

/// [`RemoteShareClient`] 的装配输入。
#[derive(Clone)]
pub struct RemoteShareClientDeps {
    pub client: Arc<dyn RemoteShareClientPort>,
    pub blobs: Arc<dyn BlobTransferPort>,
}

impl RemoteShareClient {
    pub fn new(deps: RemoteShareClientDeps) -> Self {
        Self {
            client: deps.client,
            blobs: deps.blobs,
            active_leases: Mutex::new(Vec::new()),
        }
    }

    /// 会话关闭清算：释放在途上传尚未走完流程的 blob 暂挂租约。
    ///
    /// `upload` 正常路径在 commit/abort 后自行 untag；任务若在会话拆除时被
    /// 丢弃，租约永远留在 store 上。这里把仍登记在册的租约全部释放——已经
    /// 完成的租约不在表里，重复释放是幂等的。
    pub async fn release_inflight(&self) {
        let leases: Vec<TagReason> = match self.active_leases.lock() {
            Ok(mut active) => std::mem::take(&mut *active),
            // discarded-source[lock-poisoned]: `PoisonError`: 租约表读不出就
            // 保守不动——残留租约只是延迟回收，不构成正确性问题。
            Err(_) => return,
        };
        for reason in leases {
            // discarded-source[best-effort-cleanup]: `BlobError`: 会话已死，
            // 释放失败只推迟回收，不影响其它清理。
            let _ = self.blobs.untag(reason).await;
        }
    }

    // ── 浏览 / 变更直通 ────────────────────────────────────────────────

    /// 探活对端共享服务。
    pub async fn hello(
        &self,
        peer: &DeviceId,
    ) -> Result<ShareAvailability, RemoteShareClientError> {
        self.client.hello(peer).await
    }

    /// 列出对端对本机可见的授权根。
    pub async fn list_roots(
        &self,
        peer: &DeviceId,
    ) -> Result<Vec<ShareRootDescriptor>, RemoteShareClientError> {
        self.client.list_roots(peer).await
    }

    /// 列出一页目录。
    pub async fn list(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareDirectoryPage, RemoteShareClientError> {
        self.client.list(peer, root, rel, after, limit).await
    }

    /// 读取单条目元数据。
    pub async fn stat(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareDirectoryEntry, RemoteShareClientError> {
        self.client.stat(peer, root, rel).await
    }

    /// 在对端 `rel` 建目录。
    pub async fn mkdir(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<(), RemoteShareClientError> {
        self.client.mkdir(peer, root, rel).await
    }

    /// 对端同根内移动。
    pub async fn rename(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        self.client.rename(peer, root, from, to).await
    }

    /// 把 `rel` 移入对端回收目录，返回 `trash_id`。
    pub async fn delete(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<String, RemoteShareClientError> {
        self.client.delete(peer, root, rel).await
    }

    /// 分页列出对端回收目录。
    pub async fn list_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareTrashPage, RemoteShareClientError> {
        self.client.list_trash(peer, root, after, limit).await
    }

    /// 还原回收条目到 `to`。
    pub async fn restore(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        trash_id: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        self.client.restore(peer, root, trash_id, to).await
    }

    /// 清空对端回收目录。
    pub async fn empty_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
    ) -> Result<(), RemoteShareClientError> {
        self.client.empty_trash(peer, root).await
    }

    /// 对端同根内服务端拷贝。
    pub async fn copy_within(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        self.client.copy_within(peer, root, from, to).await
    }

    // ── 传输编排 ──────────────────────────────────────────────────────

    /// 上传本地来源（文件或目录，目录递归）到对端 `root` 内的 `dest_dir`
    /// （空串 = 根顶层）。条目以其 basename 落位。
    ///
    /// 完整生命周期由本方法承担：枚举 → 发布+签票 → 分片 stage → commit；
    /// 任何阶段失败先 `abort_upload` 收回已建 staging，落定后释放本机
    /// blob 暂挂标签。`commit` 撞上 `TooLate` 视为成功——应答丢失后的
    /// 重试落在 holder 的 commit 墓碑上，内容实际已落盘。
    pub async fn upload(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dest_dir: &str,
        sources: &[ShareUploadSource],
    ) -> Result<ShareUploadReport, ShareOutboundError> {
        let local: Vec<PathBuf> = sources.iter().map(|s| s.local.clone()).collect();
        let (items, skipped) = tokio::task::spawn_blocking(move || enumerate_sources(&local))
            .await
            // discarded-source[no-information]: `JoinError`: 枚举 panic 时错误本体不可
            // 用也无恢复价值，按枚举失败归类。
            .map_err(|_| ShareOutboundError::Enumerate(std::io::Error::other("enum task")))?
            .map_err(ShareOutboundError::Enumerate)?;
        if items.is_empty() {
            return Err(ShareOutboundError::Empty);
        }
        self.upload_items(peer, root, dest_dir, items, skipped)
            .await
    }

    /// `upload` 的清单形态：调用方已构造好（本地路径, `dest_dir` 内相对路径,
    /// is_dir）三元组时直接使用，跳过枚举。仍由本方法承担发布/分片/落位/清理。
    pub async fn upload_items(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dest_dir: &str,
        items: Vec<ShareUploadItem>,
        skipped: usize,
    ) -> Result<ShareUploadReport, ShareOutboundError> {
        let transfer_id = ShareTransferId::from_bytes(*uuid::Uuid::new_v4().as_bytes());
        let lease = TagReason::RemoteShareExport(format!("upload-{}", uuid::Uuid::new_v4()));
        match self.active_leases.lock() {
            Ok(mut active) => active.push(lease.clone()),
            // discarded-source[lock-poisoned]: `PoisonError`: 租约登记失败只意味
            // 会话清算可能漏这一条；正常路径仍会显式 untag，继续执行。
            Err(_) => {}
        }

        let result = self
            .upload_inner(peer, root, dest_dir, items, skipped, transfer_id, &lease)
            .await;
        if let Ok(mut active) = self.active_leases.lock() {
            active.retain(|reason| *reason != lease);
        }
        // 无论成败都释放本机暂挂：holder 拉字节在 commit 之前完成，commit
        // 返回（或 abort 清理）后票据已无消费者。
        let _ = self.blobs.untag(lease).await;
        result
    }

    async fn upload_inner(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dest_dir: &str,
        items: Vec<ShareUploadItem>,
        skipped: usize,
        transfer_id: ShareTransferId,
        lease: &TagReason,
    ) -> Result<ShareUploadReport, ShareOutboundError> {
        // 1. 发布文件内容并签发 fetch 票据。
        let mut manifest: Vec<ShareStageEntry> = Vec::with_capacity(items.len());
        let mut total_bytes = 0u64;
        let mut files = 0usize;
        let mut dirs = 0usize;
        for item in &items {
            if item.is_dir {
                manifest.push(ShareStageEntry {
                    rel: item.rel.clone(),
                    is_dir: true,
                    size_bytes: 0,
                    ticket: None,
                });
                dirs += 1;
                continue;
            }
            let size_bytes = std::fs::metadata(&item.local)
                .map_err(ShareOutboundError::Enumerate)?
                .len();
            let digest = self
                .blobs
                .publish_path(&item.local, lease.clone())
                .await
                .map_err(ShareOutboundError::Blob)?;
            let ticket = self
                .blobs
                .issue_ticket(&digest)
                .await
                .map_err(ShareOutboundError::Blob)?;
            manifest.push(ShareStageEntry {
                rel: item.rel.clone(),
                is_dir: false,
                size_bytes,
                ticket: Some(ticket),
            });
            files += 1;
            total_bytes = total_bytes.saturating_add(size_bytes);
        }

        // 2. 按请求体预算分片 stage，累积 staging_id。所有分片共用同一
        //    `dest_dir`：holder 在 stage 时就验证目标目录存在且是目录。
        let mut staging_ids: Vec<String> = Vec::new();
        let mut pending: Vec<ShareStageEntry> = Vec::new();
        let mut pending_bytes = 0usize;
        for entry in manifest.iter() {
            let estimate = stage_entry_estimate(entry);
            if !pending.is_empty() && pending_bytes + estimate > STAGE_MANIFEST_BUDGET {
                match self
                    .flush_stage(peer, root, dest_dir, &pending, transfer_id)
                    .await
                {
                    Ok(outcome) => staging_ids.push(outcome.staging_id),
                    Err(error) => {
                        self.abort_best_effort(peer, &staging_ids).await;
                        return Err(ShareOutboundError::Remote(error));
                    }
                }
                pending.clear();
                pending_bytes = 0;
            }
            pending_bytes += estimate;
            pending.push(entry.clone());
        }
        if !pending.is_empty() || staging_ids.is_empty() {
            match self
                .flush_stage(peer, root, dest_dir, &pending, transfer_id)
                .await
            {
                Ok(outcome) => staging_ids.push(outcome.staging_id),
                Err(error) => {
                    self.abort_best_effort(peer, &staging_ids).await;
                    return Err(ShareOutboundError::Remote(error));
                }
            }
        }

        // 3. 提交：`TooLate` = 应答丢失重试落在墓碑上 = 已落盘。
        match self.client.commit_upload(peer, &staging_ids).await {
            Ok(()) => {}
            Err(RemoteShareClientError::Refused(ShareClientDeny::TooLate)) => {}
            Err(error) => {
                self.abort_best_effort(peer, &staging_ids).await;
                return Err(ShareOutboundError::Remote(error));
            }
        }
        Ok(ShareUploadReport {
            transfer_id,
            files,
            dirs,
            skipped,
            total_bytes,
        })
    }

    async fn flush_stage(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dest_dir: &str,
        entries: &[ShareStageEntry],
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, RemoteShareClientError> {
        self.client
            .stage_upload(peer, root, dest_dir, entries, transfer_id)
            .await
    }

    async fn abort_best_effort(&self, peer: &DeviceId, staging_ids: &[String]) {
        if staging_ids.is_empty() {
            return;
        }
        // discarded-source[best-effort-cleanup]: `RemoteShareClientError`: 清理性
        // abort 的胜负不掩盖原始失败，丢弃其结果。
        let _ = self.client.abort_upload(peer, staging_ids).await;
    }

    /// 把对端 `rel` 文件下载到本机 `target`。
    ///
    /// `export` 拿到的票据由 holder 的导出租约托底；`fetch_to_path` 按内容
    /// 寻址校验字节，公告大小只用于展示不需要复核。`progress` 由调用方
    /// （daemon 面向本机 UI）提供。
    pub async fn download(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        target: &Path,
        progress: Option<&dyn BlobProgressSink>,
    ) -> Result<BlobDigest, ShareOutboundError> {
        let ShareExportOutcome { ticket, .. } = self
            .client
            .export(peer, root, rel)
            .await
            .map_err(ShareOutboundError::Remote)?;
        self.blobs
            .fetch_to_path(&ticket, target, progress)
            .await
            .map_err(ShareOutboundError::Blob)
    }
}

/// 出站清单项：本地路径 + 远端根内相对路径 + 是否目录。
#[derive(Clone, PartialEq, Eq)]
pub struct ShareUploadItem {
    pub local: PathBuf,
    pub rel: String,
    pub is_dir: bool,
}

/// Hand-written `Debug`: both path fields are user content.
impl std::fmt::Debug for ShareUploadItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareUploadItem")
            .field("local", &"[REDACTED]")
            .field("rel", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .finish()
    }
}

/// 枚举本地来源为上传清单；条目的 `rel` 是相对 `dest_dir` 的路径（不含
/// `dest_dir` 前缀，holder 侧 `commit_staging` 落位时再拼上）。`symlink_metadata`
/// 识别链接——本机侧不跟随 symlink（与 holder 侧约束策略对偶，杜绝把链接
/// 目标内容当作清单本体送出）。
fn enumerate_sources(sources: &[PathBuf]) -> Result<(Vec<ShareUploadItem>, usize), std::io::Error> {
    let mut items = Vec::new();
    let mut skipped = 0usize;
    for source in sources {
        let meta = std::fs::symlink_metadata(source)?;
        let Some(name) = source.file_name().and_then(|n| n.to_str()) else {
            skipped += 1;
            continue;
        };
        if meta.is_dir() {
            items.push(ShareUploadItem {
                local: source.clone(),
                rel: name.to_string(),
                is_dir: true,
            });
            walk_dir(source, name, &mut items, &mut skipped)?;
        } else if meta.is_file() {
            items.push(ShareUploadItem {
                local: source.clone(),
                rel: name.to_string(),
                is_dir: false,
            });
        } else {
            skipped += 1;
        }
    }
    // 保留名与非法相对路径在 holder 侧一样会被拒；本侧提前剔除，避免整批
    // staging 因一条坏 rel 被打回。
    let before = items.len();
    items.retain(|item| {
        is_well_formed_relative(&item.rel)
            && item.rel.split('/').all(|c| !is_reserved_share_component(c))
    });
    skipped += before - items.len();
    Ok((items, skipped))
}

fn walk_dir(
    dir: &Path,
    rel_dir: &str,
    items: &mut Vec<ShareUploadItem>,
    skipped: &mut usize,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.file_type()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            *skipped += 1;
            continue;
        };
        let rel = join_rel(rel_dir, &name);
        if meta.is_dir() {
            items.push(ShareUploadItem {
                local: entry.path(),
                rel: rel.clone(),
                is_dir: true,
            });
            walk_dir(&entry.path(), &rel, items, skipped)?;
        } else if meta.is_file() && !meta.is_symlink() {
            items.push(ShareUploadItem {
                local: entry.path(),
                rel,
                is_dir: false,
            });
        } else {
            *skipped += 1;
        }
    }
    Ok(())
}

fn join_rel(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches('/');
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn stage_entry_estimate(entry: &ShareStageEntry) -> usize {
    entry.rel.len()
        + entry
            .ticket
            .as_ref()
            .map(|t: &BlobTicket| t.as_bytes().len())
            .unwrap_or(0)
        + 64
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytes::Bytes;
    use tokio::sync::Notify;

    /// `stage_upload` 的录制形态：目标目录、清单、关联键。
    #[derive(Default)]
    struct Recorded {
        staged: Vec<(String, usize, ShareTransferId)>,
        committed: Vec<Vec<String>>,
        aborted: Vec<Vec<String>>,
        exported: Vec<String>,
    }

    /// 录制型出站端口：每类请求记下参数，可按剧本返回 deny。
    struct RecordingClient {
        calls: Mutex<Recorded>,
        stage_error: Mutex<Option<fn() -> RemoteShareClientError>>,
        /// 第几次 stage 调用返回 `stage_error`（1-based）；`0` 全部成功。
        fail_stage_at: Mutex<usize>,
        commit_error: Mutex<Option<fn() -> RemoteShareClientError>>,
        /// 为真时 stage 在进入后挂起，直到 `stage_gate` 放行（并发清算测试）。
        block_stage: bool,
        stage_gate: Arc<Notify>,
        stage_started: Arc<Notify>,
    }

    impl RecordingClient {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Recorded::default()),
                stage_error: Mutex::new(None),
                fail_stage_at: Mutex::new(0),
                commit_error: Mutex::new(None),
                block_stage: false,
                stage_gate: Arc::new(Notify::new()),
                stage_started: Arc::new(Notify::new()),
            }
        }
        fn blocking() -> Self {
            let mut this = Self::new();
            this.block_stage = true;
            this
        }
    }

    #[async_trait]
    impl RemoteShareClientPort for RecordingClient {
        async fn hello(
            &self,
            _peer: &DeviceId,
        ) -> Result<ShareAvailability, RemoteShareClientError> {
            Ok(ShareAvailability::Ok)
        }
        async fn list_roots(
            &self,
            _peer: &DeviceId,
        ) -> Result<Vec<ShareRootDescriptor>, RemoteShareClientError> {
            Ok(Vec::new())
        }
        async fn list(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareDirectoryPage, RemoteShareClientError> {
            Ok(ShareDirectoryPage {
                entries: Vec::new(),
                next_after: None,
            })
        }
        async fn stat(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareDirectoryEntry, RemoteShareClientError> {
            Ok(ShareDirectoryEntry {
                name: "f".to_owned(),
                is_dir: false,
                is_symlink: false,
                size_bytes: 1,
                modified_at_ms: 0,
            })
        }
        async fn mkdir(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<(), RemoteShareClientError> {
            Ok(())
        }
        async fn rename(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), RemoteShareClientError> {
            Ok(())
        }
        async fn delete(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<String, RemoteShareClientError> {
            Ok("t".to_owned())
        }
        async fn list_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareTrashPage, RemoteShareClientError> {
            Ok(ShareTrashPage {
                entries: Vec::new(),
                next_after: None,
            })
        }
        async fn restore(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _trash_id: &str,
            _to: &str,
        ) -> Result<(), RemoteShareClientError> {
            Ok(())
        }
        async fn empty_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
        ) -> Result<(), RemoteShareClientError> {
            Ok(())
        }
        async fn copy_within(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), RemoteShareClientError> {
            Ok(())
        }
        async fn stage_upload(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            dir: &str,
            entries: &[ShareStageEntry],
            transfer_id: ShareTransferId,
        ) -> Result<ShareStageOutcome, RemoteShareClientError> {
            self.stage_started.notify_one();
            if self.block_stage {
                self.stage_gate.notified().await;
            }
            let nth = {
                // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
                let mut guard = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                guard
                    .staged
                    .push((dir.to_owned(), entries.len(), transfer_id));
                guard.staged.len()
            };
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let fail_at = *self.fail_stage_at.lock().unwrap_or_else(|e| e.into_inner());
            if fail_at == nth {
                // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
                let deny = *self.stage_error.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(deny) = deny {
                    return Err(deny());
                }
            }
            Ok(ShareStageOutcome {
                staging_id: format!("stg-{nth}"),
            })
        }
        async fn commit_upload(
            &self,
            _peer: &DeviceId,
            staging_ids: &[String],
        ) -> Result<(), RemoteShareClientError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .committed
                .push(staging_ids.to_vec());
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            match *self.commit_error.lock().unwrap_or_else(|e| e.into_inner()) {
                Some(deny) => Err(deny()),
                None => Ok(()),
            }
        }
        async fn abort_upload(
            &self,
            _peer: &DeviceId,
            staging_ids: &[String],
        ) -> Result<(), RemoteShareClientError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .aborted
                .push(staging_ids.to_vec());
            Ok(())
        }
        async fn export(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            rel: &str,
        ) -> Result<ShareExportOutcome, RemoteShareClientError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .exported
                .push(rel.to_owned());
            Ok(ShareExportOutcome {
                ticket: BlobTicket::from_bytes(vec![0x11, 0x22]),
                size_bytes: 3,
            })
        }
    }

    /// 精简 blob 桩：发布返回派生 digest，签票回包 digest 字节，记录 untag
    /// 与 fetch_to_path 参数。
    #[derive(Default)]
    struct StubBlobs {
        untagged: Mutex<Vec<TagReason>>,
        fetched: Mutex<Vec<(Vec<u8>, PathBuf)>>,
        publish_calls: Mutex<usize>,
    }

    #[async_trait]
    impl BlobTransferPort for StubBlobs {
        async fn publish(&self, _c: Bytes, _r: TagReason) -> Result<BlobDigest, BlobError> {
            Ok(BlobDigest::from_bytes([1; 32]))
        }
        async fn publish_path(&self, _p: &Path, _r: TagReason) -> Result<BlobDigest, BlobError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let mut guard = self.publish_calls.lock().unwrap_or_else(|e| e.into_inner());
            *guard += 1;
            let mut digest = [0u8; 32];
            digest[0] = *guard as u8;
            Ok(BlobDigest::from_bytes(digest))
        }
        async fn publish_reader(
            &self,
            _s: std::fs::File,
            _r: TagReason,
        ) -> Result<BlobDigest, BlobError> {
            Ok(BlobDigest::from_bytes([2; 32]))
        }
        async fn issue_ticket(&self, digest: &BlobDigest) -> Result<BlobTicket, BlobError> {
            Ok(BlobTicket::from_bytes(digest.as_bytes().to_vec()))
        }
        async fn fetch(
            &self,
            ticket: &BlobTicket,
            _progress: Option<&dyn BlobProgressSink>,
        ) -> Result<Bytes, BlobError> {
            Ok(Bytes::copy_from_slice(ticket.as_bytes()))
        }
        async fn fetch_to_path(
            &self,
            ticket: &BlobTicket,
            target_path: &Path,
            _progress: Option<&dyn BlobProgressSink>,
        ) -> Result<BlobDigest, BlobError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.fetched
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((ticket.as_bytes().to_vec(), target_path.to_path_buf()));
            self.digest_of(ticket)
        }
        async fn shutdown_inflight_fetch(&self, _t: &BlobTicket) -> Result<(), BlobError> {
            Ok(())
        }
        async fn has(&self, _d: &BlobDigest) -> Result<bool, BlobError> {
            Ok(false)
        }
        async fn tag(&self, _d: &BlobDigest, _r: TagReason) -> Result<(), BlobError> {
            Ok(())
        }
        async fn untag(&self, reason: TagReason) -> Result<(), BlobError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.untagged
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(reason);
            Ok(())
        }
        fn digest_of(&self, ticket: &BlobTicket) -> Result<BlobDigest, BlobError> {
            let mut digest = [0u8; 32];
            let bytes = ticket.as_bytes();
            let n = bytes.len().min(32);
            digest[..n].copy_from_slice(&bytes[..n]);
            Ok(BlobDigest::from_bytes(digest))
        }
    }

    fn harness(client: Arc<RecordingClient>, blobs: Arc<StubBlobs>) -> RemoteShareClient {
        RemoteShareClient::new(RemoteShareClientDeps { client, blobs })
    }

    fn peer() -> DeviceId {
        DeviceId::new("peer-a")
    }

    fn root() -> ShareRootId {
        ShareRootId::from_wire_bytes([9; 16])
    }

    /// 上传完整生命周期：枚举 → 发布+签票 → stage → commit → untag 租约。
    #[tokio::test]
    async fn upload_publishes_stages_commits_and_untags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::write(dir.path().join("a.txt"), b"aa").expect("write a");
        std::fs::write(sub.join("b.txt"), b"bbbb").expect("write b");

        let client = Arc::new(RecordingClient::new());
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs.clone());

        let report = share
            .upload(
                &peer(),
                root(),
                "drop",
                &[ShareUploadSource {
                    local: dir.path().to_path_buf(),
                }],
            )
            .await
            .expect("upload succeeds");

        assert_eq!(report.files, 2);
        assert!(report.dirs >= 1);
        assert_eq!(report.total_bytes, 6);
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.staged.len(), 1);
        assert_eq!(calls.staged[0].0, "drop");
        assert_eq!(calls.staged[0].1, report.files + report.dirs);
        assert_eq!(calls.committed, vec![vec!["stg-1".to_string()]]);
        assert!(calls.aborted.is_empty());
        drop(calls);
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let untagged = blobs.untagged.lock().unwrap_or_else(|e| e.into_inner());
        assert!(matches!(
            untagged.as_slice(),
            [TagReason::RemoteShareExport(_)]
        ));
    }

    /// 空来源集 → `Empty`，不发任何远端请求。
    #[tokio::test]
    async fn upload_with_no_items_is_empty() {
        let client = Arc::new(RecordingClient::new());
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs);

        let err = share
            .upload(&peer(), root(), "", &[])
            .await
            .expect_err("empty sources must error");
        assert!(matches!(err, ShareOutboundError::Empty));
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert!(calls.staged.is_empty() && calls.committed.is_empty());
    }

    /// 第二段 stage 失败 → 已建立的第一段被 abort，返回 Remote 失败。
    #[tokio::test]
    async fn stage_failure_aborts_established_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"x").expect("write");

        let client = Arc::new(RecordingClient::new());
        *client.stage_error.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(|| RemoteShareClientError::Refused(ShareClientDeny::TooLarge));
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        *client
            .fail_stage_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = 2;
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs);

        // 两条 rel 各自超过 48KiB 分片预算，强制切成两个 stage 段。
        let items = vec![
            ShareUploadItem {
                local: file.clone(),
                rel: "a".repeat(60 * 1024),
                is_dir: false,
            },
            ShareUploadItem {
                local: file.clone(),
                rel: "b".repeat(60 * 1024),
                is_dir: false,
            },
        ];
        let err = share
            .upload_items(&peer(), root(), "dest", items, 0)
            .await
            .expect_err("failing stage must error");
        assert!(matches!(err, ShareOutboundError::Remote(_)));

        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.staged.len(), 2);
        assert_eq!(calls.aborted, vec![vec!["stg-1".to_string()]]);
        assert!(calls.committed.is_empty());
    }

    /// `commit` 撞上 `TooLate` = 应答丢失重试落墓碑 = 按已落盘成功返回。
    #[tokio::test]
    async fn commit_too_late_counts_as_landed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"x").expect("write");

        let client = Arc::new(RecordingClient::new());
        *client
            .commit_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some(|| RemoteShareClientError::Refused(ShareClientDeny::TooLate));
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs);

        let report = share
            .upload(&peer(), root(), "", &[ShareUploadSource { local: file }])
            .await
            .expect("TooLate commit is a landed upload");
        assert_eq!(report.files, 1);
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.committed.len(), 1);
        assert!(calls.aborted.is_empty());
    }

    /// `commit` 其他失败 → 已建立的 staging 集被 abort，错误原样冒泡。
    #[tokio::test]
    async fn commit_failure_aborts_and_bubbles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"x").expect("write");

        let client = Arc::new(RecordingClient::new());
        *client
            .commit_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some(|| RemoteShareClientError::Refused(ShareClientDeny::NotFound));
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs);

        let err = share
            .upload(&peer(), root(), "", &[ShareUploadSource { local: file }])
            .await
            .expect_err("failing commit must error");
        assert!(matches!(err, ShareOutboundError::Remote(_)));
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.aborted, vec![vec!["stg-1".to_string()]]);
    }

    /// `download`：export 拿票 → fetch_to_path 用同一张票落地。
    #[tokio::test]
    async fn download_exports_ticket_then_fetches_to_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("out.bin");

        let client = Arc::new(RecordingClient::new());
        let blobs = Arc::new(StubBlobs::default());
        let share = harness(client.clone(), blobs.clone());

        let digest = share
            .download(&peer(), root(), "docs/f.bin", &target, None)
            .await
            .expect("download succeeds");

        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let calls = client.calls.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(calls.exported, vec!["docs/f.bin".to_string()]);
        drop(calls);
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let fetched = blobs.fetched.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].0, vec![0x11, 0x22]);
        assert_eq!(fetched[0].1, target);
        assert_eq!(digest.as_bytes()[0], 0x11);
    }

    /// 会话清算：上传卡在 stage 时 `release_inflight` 释放在册租约。
    #[tokio::test]
    async fn release_inflight_untags_pending_upload_lease() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f.bin");
        std::fs::write(&file, b"x").expect("write");

        let client = Arc::new(RecordingClient::blocking());
        // gate 不放行 → upload 停在 stage 里，租约仍在册。
        let blobs = Arc::new(StubBlobs::default());
        let share = Arc::new(harness(client.clone(), blobs.clone()));

        let task = {
            let share = share.clone();
            tokio::spawn(async move {
                share
                    .upload(&peer(), root(), "", &[ShareUploadSource { local: file }])
                    .await
            })
        };
        // 等到 stage 被调用（租约已登记）。
        client.stage_started.notified().await;
        share.release_inflight().await;
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        let released = blobs
            .untagged
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(released, 1, "release_inflight must untag the pending lease");

        client.stage_gate.notify_waiters();
        task.abort();
    }
}
