//! 设备文件共享的 client（请求方）端口。
//!
//! 本端口是 `remote-share/1` 控制面的出站侧契约：实现（`uc-infra-p2p` 的 iroh
//! client 适配器）负责解析对端地址、拨号、编码请求、解码应答并把
//! `DenyCode` 翻译回领域分类。返回类型复用 serve 侧的领域模型——
//! `ShareRootDescriptor`/`ShareDirectoryPage`/`ShareTrashPage` 等类型
//! 本身已经保证不含 holder 本地绝对路径（spec §13 I2）。
//!
//! 与 serve 侧的对称边界：[`RemoteShareClientError::Refused`] 携带的
//! [`ShareClientDeny`] 是线上 `DenyCode` 的领域镜像——`uc-core` 不依赖
//! `uc-sync-protocol`，与 serve 侧 `ShareServeError` ↔ `DenyCode` 的分离同理。

use async_trait::async_trait;

use crate::ids::DeviceId;

use super::serve::{
    ShareAvailability, ShareDirectoryEntry, ShareDirectoryPage, ShareExportOutcome,
    ShareRootDescriptor, ShareStageEntry, ShareStageOutcome, ShareTransferId, ShareTrashPage,
};
use super::ShareRootId;

/// 对端以类型化 deny 回绝请求时的领域分类。
///
/// 与线上 `DenyCode` 一一对应（spec §12）；刻意与 `ShareServeError` 分离：
/// serve 侧错误是"holder 本地归类的对外说辞"，client 侧 deny 是"对端已经
/// 说出口的结论"，两个集合的演化方向不同（例如 `Revoked`/`Interrupted`
/// 只在线上存在）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareClientDeny {
    /// 对端会话锁定。
    Locked,
    /// 对端不支持本功能。
    Unsupported,
    /// 对端不认识该请求形状或 opcode。
    UnsupportedRequest,
    /// 对端已挂起共享总开关。
    Suspended,
    /// 本机在连接后被移出对端的准入集。
    Revoked,
    /// 未授权 / 目标类型与动词不匹配。
    Denied,
    /// 路径分量撞上保留名。
    ReservedName,
    /// 根 / 条目 / trash_id / staging_id 不存在。
    NotFound,
    /// 需要新名的目的地已存在。
    Conflict,
    /// 已登记根在 holder 磁盘上被挪走或替换。
    RootGone,
    /// 超出配额。
    Quota,
    /// 暂存集或传输超出大小上限。
    TooLarge,
    /// 目录页或清单超出条目数上限。
    TooManyEntries,
    /// 对端本地 I/O 失败。
    Io,
    /// 传输被取消。
    Cancelled,
    /// 请求到达时已错过可执行窗口（如 commit 已落盘后再次 commit）。
    TooLate,
    /// 交换被中断。
    Interrupted,
}

impl ShareClientDeny {
    /// §12 稳定字符串码——daemon/前端错误通道的词表，与 wire `DenyCode`
    /// 的编码一一对应。
    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unsupported => "unsupported",
            Self::UnsupportedRequest => "unsupported_request",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Denied => "denied",
            Self::ReservedName => "reserved_name",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RootGone => "root_gone",
            Self::Quota => "quota",
            Self::TooLarge => "too_large",
            Self::TooManyEntries => "too_many_entries",
            Self::Io => "io",
            Self::Cancelled => "cancelled",
            Self::TooLate => "too_late",
            Self::Interrupted => "interrupted",
        }
    }
}

/// Client 侧一次远端共享请求的失败分类。
#[derive(Debug, thiserror::Error)]
pub enum RemoteShareClientError {
    /// 对端不可达：无已存地址、拨号失败、握手不含本 ALPN，或对端在读窗口
    /// 内没有给出应答。
    #[error("peer is unreachable")]
    Unreachable,
    /// 对端以类型化 deny 回绝。
    #[error("request refused")]
    Refused(ShareClientDeny),
    /// 应答与所发请求的期望形状不符（协议违例）。
    #[error("reply does not match the request")]
    UnexpectedReply,
    /// 流写入 / 读取 / 帧编解码失败。
    #[error("remote share io failure")]
    Io(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// `remote-share/1` 的出站请求端口：面向单台已配对 peer 发起全部控制面
/// 操作。
///
/// 每个方法对应线上一个 op；`peer` 是目标设备（holder）。返回类型即 serve
/// 侧领域模型——浏览与变更操作由适配器原样转发，传输动词
/// （`stage_upload`/`commit_upload`/`abort_upload`/`export`）是
/// Application 层编排原语：清单发布、票据签发与两阶段提交由
/// `uc-application` 的 client 流程负责，本端口只做单请求语义。
///
/// 传输类请求（`StageUpload`/`CommitUpload`/`AbortUpload`/`Export`）在
/// holder 侧可能等待在途 blob 拉取收敛后才回应答；实现不套用固定的整体
/// 超时，只按逐次 IO 的停顿窗口判定 `Unreachable`。
#[async_trait]
pub trait RemoteShareClientPort: Send + Sync {
    /// 探活：对端当前可否提供共享服务。
    async fn hello(&self, peer: &DeviceId) -> Result<ShareAvailability, RemoteShareClientError>;

    /// 列出对端对本机可见的授权根。
    async fn list_roots(
        &self,
        peer: &DeviceId,
    ) -> Result<Vec<ShareRootDescriptor>, RemoteShareClientError>;

    /// 列出 `rel` 目录的一页（空串 = 根顶层），`after`/`limit` 分页。
    async fn list(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareDirectoryPage, RemoteShareClientError>;

    /// 读取单个条目的元数据（空串 = 根本身）。
    async fn stat(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareDirectoryEntry, RemoteShareClientError>;

    /// 在 `rel` 建目录（需对端 `write` 授权）。
    async fn mkdir(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<(), RemoteShareClientError>;

    /// 同根内 `from` → `to` 移动（需 `write` + `delete`）。
    async fn rename(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError>;

    /// 把 `rel` 移入对端回收目录（需 `delete`），返回 `trash_id` 还原句柄。
    async fn delete(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<String, RemoteShareClientError>;

    /// 分页列出对端根的回收目录（需 `delete`）。
    async fn list_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareTrashPage, RemoteShareClientError>;

    /// 把回收条目还原到 `to`（需 `write` + `delete`）。
    async fn restore(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        trash_id: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError>;

    /// 清空对端根的回收目录（需 `delete`）。
    async fn empty_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
    ) -> Result<(), RemoteShareClientError>;

    /// 对端同根内服务端拷贝 `from` → `to`（需 `write`）。
    async fn copy_within(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError>;

    /// 在 `dir` 下开一段上传暂存：清单中每个文件条目必须已携带本机签发的
    /// `BlobTicket`；holder 立即开始拉取并把进度回报到 `transfer_id` 关联键
    /// 下。返回 `staging_id` 供 commit/abort 寻址。清单超限时可分段多次调用，
    /// 同一传输任务累积多个 `staging_id`。
    async fn stage_upload(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dir: &str,
        entries: &[ShareStageEntry],
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, RemoteShareClientError>;

    /// 把已暂存的集合落位到目标目录。未知/异主的 `staging_id` 得
    /// `NotFound`；已提交的 id 得 `TooLate`（重试安全——视为已落盘）。
    /// holder 会先在途 fetch 收敛再逐条原子 rename。
    async fn commit_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), RemoteShareClientError>;

    /// 丢弃暂存集。幂等：未知 id 被忽略；已提交的 id 得 `TooLate`。
    async fn abort_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), RemoteShareClientError>;

    /// 让对端把 `rel` 发布为 blob 并回发 fetch 票据 + 公告大小（需 `read`）。
    /// 票据带 holder 的导出租约时限，调用方应尽快拉取。
    async fn export(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareExportOutcome, RemoteShareClientError>;
}
