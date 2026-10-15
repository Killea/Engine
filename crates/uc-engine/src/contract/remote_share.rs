//! remote-share（设备文件共享）的稳定操作契约。
//!
//! DTO 与 spec §9.1 的 op 表一一对应。`rel`/`label`/`trash_id`/`root_id`
//! 是协议内容而非本机绝对路径，用普通 `String`；本机路径（上传源、下载
//! 目标、本机共享根路径）按 §9.1 约定走 `HostFileHandle` 或 `PathBuf`，
//! 一律不写进日志（手写 `Debug` 脱敏）。

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::HostFileHandle;

// ── 入参：peer 侧 ────────────────────────────────────────────────────

/// `QueryPeerShareState`：探活对端共享服务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerShareRequest {
    pub peer_id: String,
}

/// `ListPeerShareRoots` 用 [`PeerShareRequest`]。目录分页输入。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareListInput {
    pub peer_id: String,
    pub root_id: String,
    /// 根内相对目录（空串 = 根顶层）。
    pub rel: String,
    /// 上一页 `next_after` 游标。
    pub after: Option<String>,
    pub limit: u32,
}

/// `StatPeerShareEntry`：单条目元数据。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareRelInput {
    pub peer_id: String,
    pub root_id: String,
    pub rel: String,
}

/// `ListPeerShareTrash`：回收目录分页。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareTrashListInput {
    pub peer_id: String,
    pub root_id: String,
    pub after: Option<String>,
    pub limit: u32,
}

/// `MutatePeerShare` 的变更动作（先例：`MutateCustomRelay`）。
#[derive(Clone, PartialEq, Eq)]
pub enum PeerShareAction {
    Mkdir {
        rel: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Delete {
        rel: String,
    },
    CopyWithin {
        from: String,
        to: String,
    },
    /// `to` 必填（spec §9.1）；「还原到 original_rel」由调用方先 ListTrash 自取。
    Restore {
        trash_id: String,
        to: String,
    },
    EmptyTrash,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MutatePeerShareInput {
    pub peer_id: String,
    pub root_id: String,
    pub action: PeerShareAction,
}

/// `UploadPeerShare`：本机来源（文件/目录）送入对端 `root` 内 `dest_dir`。
/// `transfer_id` 由调用方签发，同一 id 关联进度事件与取消。
#[derive(Clone, PartialEq, Eq)]
pub struct UploadPeerShareInput {
    pub peer_id: String,
    pub root_id: String,
    /// 根内相对目标目录（空串 = 根顶层）。
    pub dest_dir: String,
    pub transfer_id: String,
    /// 本机文件/目录路径（handle 即宿主文件系统路径）。
    pub sources: Vec<HostFileHandle>,
}

/// `DownloadPeerShare`：对端 `rel` 文件拉到本机 `target`。
#[derive(Clone, PartialEq, Eq)]
pub struct DownloadPeerShareInput {
    pub peer_id: String,
    pub root_id: String,
    pub rel: String,
    pub transfer_id: String,
    /// 本机目标文件路径。
    pub target: HostFileHandle,
}

/// `CancelPeerShareTransfer`：按 `transfer_id` 寻址在途上传/下载。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelPeerShareTransferInput {
    pub transfer_id: String,
}

// ── 入参：本机共享管理 ───────────────────────────────────────────────

/// `ReplaceRemoteShareRoots` 的根条目。`id` 为空 = 新根（Engine 分配）。
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteShareRootInput {
    /// 既有根的不透明 id（`PeerShareRootSummary.id` / `RemoteShareRootSummary.id`）。
    pub id: Option<String>,
    /// 本机根目录绝对路径。
    pub path: PathBuf,
    /// 对 peer 展示的标签。
    pub label: String,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub enabled: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReplaceRemoteShareRootsInput {
    pub roots: Vec<RemoteShareRootInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetRemoteShareSuspendedInput {
    pub suspended: bool,
}

// ── 出参：本机共享管理 ───────────────────────────────────────────────

/// `QueryRemoteShareState` 的结果。锁定形态（`{locked, root_count: null,
/// suspended: null}`）由 daemon 结合加密态自行拼装，Engine 只给解锁后的事实。
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteShareStateSummary {
    pub suspended: bool,
    pub roots: Vec<RemoteShareRootSummary>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RemoteShareRootSummary {
    pub id: String,
    pub path: PathBuf,
    pub label: String,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub enabled: bool,
}

/// `ReplaceRemoteShareRoots` / `SetRemoteShareSuspended` 共用的收敛摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteShareReconcileSummary {
    pub registered: u32,
    pub failed: u32,
    pub unregistered: u32,
}

// ── 出参：peer 侧 ────────────────────────────────────────────────────

/// 对端共享服务的可达性（wire `Hello.state` 的稳定映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerShareState {
    Ok,
    Locked,
    Unsupported,
    Suspended,
}

/// 对端对本机可见的授权根（不含 holder 本地路径，spec §13 I2）。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareRootSummary {
    pub id: String,
    pub label: String,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub enabled: bool,
}

/// 对端目录条目。`name` 是单段条目名（用户内容）。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareEntrySummary {
    pub name: String,
    pub is_dir: bool,
    /// 符号链接条目如实列出但不可寻址（holder 约束层拒绝对其做任何动词）。
    pub is_symlink: bool,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

/// 一页目录；`cursor` 即续页游标（最后一条的条目名）。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareDirectoryPage {
    pub entries: Vec<PeerShareEntrySummary>,
    pub cursor: Option<String>,
    /// 是否还有下一页（`cursor.is_some()` 的同义便捷位）。
    pub truncated: bool,
}

/// 回收目录条目。`original_rel` 是被删前的根内相对路径。
#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareTrashEntrySummary {
    pub trash_id: String,
    pub original_rel: String,
    pub deleted_at_ms: i64,
    pub is_dir: bool,
    pub size_bytes: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PeerShareTrashPage {
    pub entries: Vec<PeerShareTrashEntrySummary>,
    pub cursor: Option<String>,
    pub truncated: bool,
}

/// `MutatePeerShare` 的稳定结果。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PeerShareMutationOutcome {
    /// mkdir / rename / copy_within / restore / empty_trash 的纯确认。
    Ack,
    /// delete 的返回值：holder 回收目录里的不透明条目 id。
    Deleted { trash_id: String },
}

/// `UploadPeerShare` 的结算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerShareUploadSummary {
    pub transfer_id: String,
    pub files: u64,
    pub dirs: u64,
    /// 枚举时被跳过的条目（symlink / 非法名 / 保留名 / 特殊文件）。
    pub skipped: u64,
    pub total_bytes: u64,
}

/// `DownloadPeerShare` 的结算。`size_bytes` 为 holder 公告的目标大小。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerShareDownloadSummary {
    pub transfer_id: String,
    pub size_bytes: u64,
}

/// `CancelPeerShareTransfer` 的稳定结果（spec §9.1 取消语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerShareTransferCancelOutcome {
    Cancelled,
    NotInflight,
    TooLate,
}

// ── Debug 脱敏：路径 / rel / 条目名 / 标签属用户内容 ──────────────────

impl fmt::Debug for PeerShareListInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareListInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("rel", &"[REDACTED]")
            .field("limit", &self.limit)
            .finish()
    }
}

impl fmt::Debug for PeerShareRelInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareRelInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("rel", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for PeerShareTrashListInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareTrashListInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("limit", &self.limit)
            .finish()
    }
}

impl fmt::Debug for PeerShareAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("PeerShareAction");
        match self {
            Self::Mkdir { .. } => debug.field("kind", &"mkdir"),
            Self::Rename { .. } => debug.field("kind", &"rename"),
            Self::Delete { .. } => debug.field("kind", &"delete"),
            Self::CopyWithin { .. } => debug.field("kind", &"copy_within"),
            Self::Restore { .. } => debug.field("kind", &"restore"),
            Self::EmptyTrash => debug.field("kind", &"empty_trash"),
        };
        debug.finish()
    }
}

impl fmt::Debug for MutatePeerShareInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutatePeerShareInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("action", &self.action)
            .finish()
    }
}

impl fmt::Debug for UploadPeerShareInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPeerShareInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("dest_dir", &"[REDACTED]")
            .field("transfer_id", &self.transfer_id)
            .field("source_count", &self.sources.len())
            .finish()
    }
}

impl fmt::Debug for DownloadPeerShareInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadPeerShareInput")
            .field("peer_id", &self.peer_id)
            .field("root_id", &"[REDACTED]")
            .field("rel", &"[REDACTED]")
            .field("transfer_id", &self.transfer_id)
            .finish()
    }
}

impl fmt::Debug for RemoteShareRootInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteShareRootInput")
            .field("has_id", &self.id.is_some())
            .field("path", &"[REDACTED]")
            .field("label", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl fmt::Debug for ReplaceRemoteShareRootsInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplaceRemoteShareRootsInput")
            .field("root_count", &self.roots.len())
            .finish()
    }
}

impl fmt::Debug for RemoteShareStateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteShareStateSummary")
            .field("suspended", &self.suspended)
            .field("root_count", &self.roots.len())
            .finish()
    }
}

impl fmt::Debug for RemoteShareRootSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteShareRootSummary")
            .field("id", &self.id)
            .field("path", &"[REDACTED]")
            .field("label", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl fmt::Debug for PeerShareRootSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareRootSummary")
            .field("id", &self.id)
            .field("label", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl fmt::Debug for PeerShareEntrySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareEntrySummary")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

impl fmt::Debug for PeerShareDirectoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareDirectoryPage")
            .field("entry_count", &self.entries.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl fmt::Debug for PeerShareTrashEntrySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareTrashEntrySummary")
            .field("trash_id", &self.trash_id)
            .field("original_rel", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .finish()
    }
}

impl fmt::Debug for PeerShareTrashPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerShareTrashPage")
            .field("entry_count", &self.entries.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl fmt::Debug for PeerShareMutationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ack => f.write_str("PeerShareMutationOutcome::Ack"),
            Self::Deleted { trash_id } => f
                .debug_struct("PeerShareMutationOutcome")
                .field("kind", &"deleted")
                .field("trash_id", trash_id)
                .finish(),
        }
    }
}
