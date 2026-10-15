//! 路径约束端口：把对端给出的相对路径关进已授权的共享根，并在同一道边界上完成
//! 其后的全部文件操作。
//!
//! 本端口交出的是**能力边界**，不是路径快照：[`ConfinedTarget`] 内嵌一个对外不透明的
//! 句柄（[`ConfinedTargetToken`]），由约束实现保存已验证的目录 fd、末段名与登记代次。
//! 解析之后的每个动词（`target_metadata` / `target_read_dir` / `target_rename` / …）
//! 都先复核"这个 token 是否仍属于当前登记代次、根是否还活着"，再相对句柄内的目录
//! fd 操作——"检查过的对象"与"被操作的对象"在类型上是同一个 fd。
//!
//! 判定失败一律不透明（规格 §6）：`Denied` / `ReservedName` / `RootGone` 不带任何载荷，
//! `#[error(...)]` 是无占位符的静态串，因此不可能回显路径片段。`Io { source }` 是唯一
//! 例外——它的显示文本由 `std::io::Error` 自己决定，端口层管不住，所以适配器**不得**
//! 构造消息里含路径的 `io::Error`（固定动作文本，或只带 `raw_os_error()` 分类）。
//! `ConfinedTarget` 与一切携带文件名/相对路径的类型都手写 `Debug` 打 `[REDACTED]`。

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use super::{is_windows_reserved_device_name, normalize_share_component, ShareRootId};

#[derive(Debug, thiserror::Error)]
pub enum ConfineError {
    /// 不透明拒绝：不回显任何路径片段（规格 §6）。
    #[error("path rejected by share confinement")]
    Denied,
    /// 段名撞了内核保留命名空间（回收目录 / 上传暂存目录前缀）。
    #[error("path uses a reserved share namespace component")]
    ReservedName,
    /// 根已消失、被替换、未登记/已撤销，或 token 属于被作废的登记代次。
    #[error("shared root directory is gone")]
    RootGone,
    /// 目标（或其中间段）不存在。与 `Denied` 分开：授权根内的"存在与否"
    /// 信息对端本就可经列举获得，不构成额外泄漏。
    #[error("confined target does not exist")]
    NotFound,
    /// 目标已存在但操作要求新建（如 `Rename`/`CopyWithin` 的目标名冲突）。
    #[error("confined destination already exists")]
    Conflict,
    /// 操作要求目录但目标是普通文件（或反之见 `IsADirectory`）。
    #[error("confined target is not a directory")]
    NotADirectory,
    /// 操作要求普通文件但目标是目录。
    #[error("confined target is a directory")]
    IsADirectory,
    #[error("confinement io failure")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

/// 根的文件系统身份：从**已打开的句柄**取得的设备号 + 文件索引
/// （Linux `dev`/`ino`，Windows `volume_serial_number`/`file_index`）。
///
/// 它与路径统计值互证后写入登记表，之后每次存活检查复核二者是否仍相等：
/// 根被改名挪走、删除后在同路径重建、或同路径被替换成指向他处的链接，
/// 统计出来的身份都会与登记值失配，`fail-closed` 成 `RootGone`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootIdentity {
    pub device: u64,
    pub index: u64,
}

/// 对外不透明的目标句柄。只有约束实现能构造与向下转型它；
/// 任何外部伪造的实现在端口操作的向下转型处就会失败，无法被使用。
pub trait ConfinedTargetToken: Send + Sync {
    /// 供约束实现向下转型的唯一入口。
    fn as_any(&self) -> &dyn Any;
}

/// 约束成功后的目标：根 id、相对路径与一个不透明句柄。
///
/// 它**不再**携带本机绝对路径（`real_path` 已随句柄化移除）：`relative` 只用于
/// 审计指纹与"根内的同根移动"语义比对，不作为打开依据。一切对目标的操作都经
/// [`ShareConfinementPort`] 上的动词完成，由实现先复核登记代次再相对句柄内 fd 执行。
///
/// 撤销根（`unregister_root`）或根在磁盘上被替换之后，既有 `ConfinedTarget` 在
/// 下一个动词处即被代次/身份复核拒绝为 `RootGone`——这正是快照模型给不出的保证。
pub struct ConfinedTarget {
    pub root: ShareRootId,
    /// 对端 supplied 的相对路径。共享根**自身**（经
    /// [`ShareConfinementPort::resolve_root`]）此处为空。
    /// 它是审计与语义比对字段，不是打开依据。
    pub relative: PathBuf,
    token: Arc<dyn ConfinedTargetToken>,
}

impl ConfinedTarget {
    /// 由约束实现构造。外部代码可以造出它，但伪造的 token 过不了
    /// 实现内部的向下转型，因此不构成越权通道。
    #[must_use]
    pub fn new(root: ShareRootId, relative: PathBuf, token: Arc<dyn ConfinedTargetToken>) -> Self {
        Self {
            root,
            relative,
            token,
        }
    }

    /// 取出不透明句柄；只有原约束实现能解释它。
    #[must_use]
    pub fn token(&self) -> &Arc<dyn ConfinedTargetToken> {
        &self.token
    }
}

/// 手写 `Debug`：`relative` 是用户内容（规格 §13 I4）。
impl core::fmt::Debug for ConfinedTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedTarget")
            .field("root", &self.root)
            .field("relative", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// 单条目的元数据（对端可见的部分）。`name` 是条目自身的名字
/// （末段名，或根自身的 basename），不是路径。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfinedMetadata {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

impl core::fmt::Debug for ConfinedMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedMetadata")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("is_file", &self.is_file)
            .field("size_bytes", &self.size_bytes)
            .field("modified_at_ms", &self.modified_at_ms)
            .finish()
    }
}

/// 目录列举的一条记录：名字 + 廉价的类型位（来自 `getdents`，不含 stat）。
/// `is_symlink` 如实上报——链接条目在协议上不可寻址，但隐藏它反而让用户困惑。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfinedDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

impl core::fmt::Debug for ConfinedDirEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedDirEntry")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("is_file", &self.is_file)
            .field("is_symlink", &self.is_symlink)
            .finish()
    }
}

/// 回收站里的一条条目。`original_rel` 是它在根内的原相对路径
/// （回写线上由规格 §7 的 `ListTrash` 规定），`trash_id` 是内核发的不透明名。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfinedTrashEntry {
    pub trash_id: String,
    pub original_rel: String,
    pub deleted_at_ms: i64,
    pub is_dir: bool,
    pub size_bytes: u64,
}

impl core::fmt::Debug for ConfinedTrashEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedTrashEntry")
            .field("trash_id", &self.trash_id)
            .field("original_rel", &"[REDACTED]")
            .field("deleted_at_ms", &self.deleted_at_ms)
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

/// 回收站分页结果，游标语义与目录列举一致（按 `trash_id` 名字序）。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfinedTrashPage {
    pub entries: Vec<ConfinedTrashEntry>,
    pub next_after: Option<String>,
}

impl core::fmt::Debug for ConfinedTrashPage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedTrashPage")
            .field("entries", &self.entries)
            .field(
                "next_after",
                &self.next_after.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// 上传清单的一项：相对暂存目录的相对路径、形状与声明大小。
/// 声明大小在落位时与磁盘实况核对，不一致即拒绝落位。
#[derive(Clone, PartialEq, Eq)]
pub struct ShareStagedEntry {
    pub rel: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

impl core::fmt::Debug for ShareStagedEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareStagedEntry")
            .field("rel", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

/// 落位/还原遇到既有名字时的处置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// 自动生成 `name (N).ext` 式的不冲突名。
    AutoRename,
    /// 允许覆盖既有普通文件；覆盖目录或非文件目标仍拒绝。
    Overwrite,
}

/// 共享根的路径约束、目标操作与根生命周期，全部集中在同一道端口边界上。
///
/// 与旧的"返回 `real_path` 快照"形态相比，本端口把两个语义钉死在类型里：
///
/// 1. **检查过的对象 = 被操作的对象。** `resolve` 交出的 `ConfinedTarget` 内嵌
///    已验证父目录 fd + 末段名的 token；每个动词先复核 token 的登记代次与根身份，
///    再相对 token 内 fd 操作。中间没有字符串路径可供重解析。
/// 2. **末段 no-follow。** 对末段的读取/下行都经 `cap-fs-ext` 的 `follow(No)` /
///    `open_dir_nofollow`，"解析期非符号链接、操作期被换成符号链接"的末段窗口关闭。
///
/// 仍如实记录的残留：跨目录 rename 与回收站移动经 `renameat` 语义以两端 fd 为锚，
/// 末段名不重新走路径解析，因此没有中间段竞态；`Dir::copy` 式的源符号链接检查
/// 是先 lstat 再打开，残窗内最坏读到根内另一文件，不出授权边界。
///
/// 端口方法 `async` 而预期实现走同步 cap-std 系统调用；调用方不得假设已被卸载到
/// 阻塞线程池，必要时自行 `spawn_blocking`。
#[async_trait]
pub trait ShareConfinementPort: Send + Sync {
    // ── 生命周期 ─────────────────────────────────────────────────────────

    /// 注册一个共享根：定稿路径、打开句柄、句柄身份与路径统计互证、
    /// 扫描保留命名空间占用。任一失败即拒绝且不注册，绝不降级为全盘可见。
    async fn register_root(&self, root: ShareRootId, path: &Path) -> Result<(), ConfineError>;
    /// 撤销注册：此后新解析与该代 token 上的动词一律 `RootGone`。
    async fn unregister_root(&self, root: ShareRootId);
    #[must_use]
    async fn is_registered(&self, root: ShareRootId) -> bool;

    // ── 解析 ─────────────────────────────────────────────────────────────

    /// 把对端 supplied 的相对路径关进已授权的共享根。
    ///
    /// `client_rel` 必须是符合线文法（见 [`is_well_formed_relative`]）的**非空**
    /// 相对路径：`""` 与 `"."` 一律 `Denied`，共享根**自身**经 [`Self::resolve_root`]
    /// 寻址。**本方法不构成授权**：放行一次操作必须是清单侧授权判定与本端口
    /// 约束的合取，该合取由调用方按"先 authorize 再 resolve"的顺序保证。
    async fn resolve(
        &self,
        root: ShareRootId,
        client_rel: &str,
    ) -> Result<ConfinedTarget, ConfineError>;
    /// 解析共享根**自身**。线文法禁掉了 `""`/`"."` 两种哨兵写法，故根自身
    /// 需要一个显式入口，与 `resolve` 共用同一套登记查找与失败分类。
    async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError>;

    // ── 目标动词 ─────────────────────────────────────────────────────────
    //
    // 每个动词先复核 token 的登记代次与根身份（撤销/重建即 `RootGone`），
    // 再相对 token 内已持有的目录 fd 操作；末段打开一律 no-follow。

    /// 目标自身的元数据（lstat 语义；根目标返回根自身）。
    async fn target_metadata(
        &self,
        target: &ConfinedTarget,
    ) -> Result<ConfinedMetadata, ConfineError>;
    /// 目标目录内单个子项的元数据（`name` 为单段名；目标必须是目录）。
    async fn target_child_metadata(
        &self,
        target: &ConfinedTarget,
        name: &str,
    ) -> Result<ConfinedMetadata, ConfineError>;
    /// 列举目标目录：名字与类型位，不含逐条 stat；保留命名空间条目被过滤。
    async fn target_read_dir(
        &self,
        target: &ConfinedTarget,
    ) -> Result<Vec<ConfinedDirEntry>, ConfineError>;
    /// 以 no-follow 打开目标文件供读取（目录/链接拒绝）。
    async fn target_open_read(
        &self,
        target: &ConfinedTarget,
    ) -> Result<std::fs::File, ConfineError>;
    /// 在目标处新建目录（目标即末段名；已存在即 `Conflict`）。
    async fn target_create_dir(&self, target: &ConfinedTarget) -> Result<(), ConfineError>;
    /// 同根内把 `from` 移到 `to`：两端的父目录 fd 都是解析时已验证的对象，
    /// 末段名不再重新走路径解析。`to` 已存在即 `Conflict`；根自身不可被移动。
    async fn target_rename(
        &self,
        from: &ConfinedTarget,
        to: &ConfinedTarget,
    ) -> Result<(), ConfineError>;
    /// 同根内把 `from` 复制到 `to`：文件逐 fd 复制，目录递归；
    /// 源内符号链接条目跳过（它们在协议上本即不可寻址）。
    /// `to` 已存在即 `Conflict`。
    async fn target_copy_into(
        &self,
        from: &ConfinedTarget,
        to: &ConfinedTarget,
    ) -> Result<(), ConfineError>;
    /// 把目标移入根内回收目录，返回内核发的 `trash_id`。根自身不可被删除。
    async fn target_move_to_trash(&self, target: &ConfinedTarget) -> Result<String, ConfineError>;

    // ── 回收站 ───────────────────────────────────────────────────────────
    //
    // 回收目录位于根内 `.uniclipboard-trash-<root_id>`，属内核保留命名空间，
    // 只能经这里寻址；条目按 `trash_id` 名字序分页。

    async fn list_trash(
        &self,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ConfinedTrashPage, ConfineError>;
    /// 把回收条目移回 `to` 指向的位置（冲突时自动改名），返回最终落位的末段名。
    async fn restore_from_trash(
        &self,
        root: ShareRootId,
        trash_id: &str,
        to: &ConfinedTarget,
    ) -> Result<String, ConfineError>;
    /// 永久清空该根的回收目录内容（回收目录自身保留）。
    async fn empty_trash(&self, root: ShareRootId) -> Result<(), ConfineError>;

    // ── 上传暂存 ─────────────────────────────────────────────────────────
    //
    // 暂存目录 `.uniclipboard-staging-<staging_id>` 位于根内保留命名空间，
    // 只能经这里寻址；`staging_id` 由内核发放，不可由客户端构造。

    /// 开一个新暂存目录，返回 `staging_id`。
    async fn create_staging(&self, root: ShareRootId) -> Result<String, ConfineError>;
    /// 为清单项 `rel` 在暂存目录内备好父目录（`is_dir` 时备好目录本体），
    /// 返回该项的宿主侧落盘路径。返回值仅供持有方把内容写进暂存——它出不了
    /// 保留命名空间，也绝不会出现在线上载荷里。
    async fn staging_entry_path(
        &self,
        root: ShareRootId,
        staging_id: &str,
        rel: &str,
        is_dir: bool,
    ) -> Result<PathBuf, ConfineError>;
    /// 校验清单（文件项存在且大小匹配）后把暂存目录的内容原子落位到 `dir`；
    /// 任意一步失败即丢弃整个暂存目录，目标目录不留半成品。
    async fn commit_staging(
        &self,
        root: ShareRootId,
        staging_id: &str,
        dir: &ConfinedTarget,
        entries: &[ShareStagedEntry],
        policy: ConflictPolicy,
    ) -> Result<(), ConfineError>;
    /// 丢弃一个暂存目录（不存在视为已丢弃）。
    async fn abort_staging(&self, root: ShareRootId, staging_id: &str) -> Result<(), ConfineError>;
}

/// 协议相对路径的**宿主无关**字面筛查。
///
/// 线格式的相对路径部分定义为 `/` 分隔、仅限 POSIX 风格的一段名字，因此本函数
/// 在所有平台上给出同一答案——这正是 ADR-034 需要的性质（cap-std 在 Windows 与
/// macOS 上未实测，第二道边界不能跟着宿主变）。
///
/// 上跳判定经 [`normalize_share_component`] 折叠大小写与结尾点/空格后再比对，与保留名
/// 判定共用同一条"这个组件究竟指向哪个名字"的定义（Ruling 19/20）：`.. `、`...`、`. `
/// 在 Windows 上分别折叠成 `..`（父目录）与空名（非法），而只比对字面 `.`/`..` 会放行它们。
/// 于是折叠后为空（即纯点/纯空格段）一律拒绝。
///
/// 这里**不**笼统拒绝"任何以点或空格结尾的段"：那样会把 `.uniclipboard-trash-<id>.` 这类
/// 结尾点/空格的保留名变体在本道就挡成 `Denied`，抢在行走层的 `ReservedName` 判定之前，
/// 破坏规格 §6.1 要求的可区分提示。非上跳的结尾点段（如 Linux 上的 `report.`）本就不是
/// 穿越，交给逐段行走在目标宿主上判定。
///
/// 每个段还经 [`is_windows_reserved_device_name`] 挡下 Windows 保留设备名（`CON`、`PRN`、
/// `AUX`、`NUL`、`CLOCK$`、`COM1`–`COM9`、`LPT1`–`LPT9`）。这类名字的危险不是"上跳"而是
/// **命名空间切换**：Win32 名称解析把 `<root>\CON` 交给设备，共享树整个被绕过。库自己的
/// 设备名过滤只作用于库的 open，而本层从不打开末段，那条过滤在本路径上一次都不会执行；
/// Windows 上本层又是唯一边界（ADR-034：两平台未实测），所以这道筛查不得留给库。
/// 代价与禁 `:`/`\` 同族，已写进规格 §7。
///
/// 它**不是**包含性边界本身：真正的逃出由逐段行走与库层拒绝负责。本函数只保证
/// 一批依赖平台解析器的写法在任何平台上都进不去。代价是明确拒绝含 `\` 或 `:` 的
/// 文件名（如 Linux 上合法的 `notes:backup.txt`），该限制写进规格 §7。
#[must_use]
pub fn is_well_formed_relative(client_rel: &str) -> bool {
    if client_rel.is_empty() || client_rel.starts_with('/') {
        return false;
    }
    client_rel.split('/').all(|segment| {
        // 折叠大小写与结尾点/空格后必须仍是一个非空的合法单段名字：
        // 空的折叠结果即 `.`/`..`/`...`/`.. `/`. ` 这一批上跳与别名写法，
        // 只比对字面 `.`/`..` 在 Windows 上挡不住带结尾点/空格的上跳。
        !normalize_share_component(segment).is_empty()
            && !segment.contains('\\')
            && !segment.contains(':')
            && !segment.chars().any(|c| c.is_control())
            // 设备名判定同样是宿主无关的纯字符串比较：三平台同一个答案，
            // Linux 上合法的 `CON` 因此一并不可经协议访问（代价已写进规格 §7）。
            && !is_windows_reserved_device_name(segment)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格 §6 语料里所有依赖平台解析器的写法，必须在任何宿主上都被挡下。
    #[test]
    fn host_independent_screen_rejects_windows_spellings() {
        for rejected in [
            "C:foo",
            "C:\\foo",
            "\\\\server\\share\\file",
            "\\\\?\\C:\\Windows",
            "file:stream",
            "notes:backup.txt",
            "a\\b",
            "../outside",
            "a/../b",
            // Ruling 19/20：Windows 吃掉结尾点/空格后即为上跳或非法名，字面筛查必须在
            // 任何宿主上都挡下（此前只比对 `.`/`..`，放行了这几个）。
            ".. ",
            "...",
            ". ",
            "/etc/passwd",
            "",
            "a//b",
            "./a",
            "a/./b",
            "a/\0",
            // 终评 Important 3：Windows 保留设备名。内核从不打开末段，所以 cap-std 自己的
            // 设备名过滤（`src/windows/fs/open_impl.rs`）在这里根本不生效——调用方随后那次
            // 环境权限打开会落进 Win32 命名空间的设备，而不是共享树。这道宿主无关的筛查是
            // Windows 上唯一的保证（ADR-034），因此必须在任何宿主上都挡下。
            "CON",
            "con",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM9",
            "LPT1",
            "LPT9",
            "CLOCK$",
            "nul.log",
            "COM1 .txt",
            "a/CON/b",
        ] {
            assert!(
                !is_well_formed_relative(rejected),
                "应被字面筛查拒绝：{rejected:?}"
            );
        }
    }

    #[test]
    fn ordinary_relative_paths_pass() {
        for accepted in ["a", "a/b", "a/b/c.md", ".hidden", "备注 (1).txt"] {
            assert!(is_well_formed_relative(accepted), "应放行：{accepted:?}");
        }
    }

    /// 保留设备名判定只禁**折叠后恰好等于**保留名（及其扩展名前缀）的段：
    /// `cone.txt`、`nulled`、`com1x`、`lpt10` 在 Windows 上同样是合法文件名，
    /// 把它们一起挡下会把筛查变成任意扩张的黑盒，代价不可接受。
    #[test]
    fn names_that_merely_contain_a_reserved_stem_pass() {
        for accepted in [
            "cone.txt",
            "nulled.log",
            "com1x",
            "lpt10",
            "a-com1",
            "helper-con",
            "aux1",
        ] {
            assert!(
                is_well_formed_relative(accepted),
                "不该被保留名判定误挡：{accepted:?}"
            );
        }
    }
}
