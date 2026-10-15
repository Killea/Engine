//! 共享根的路径约束内核——设备文件共享唯一的信任边界。
//!
//! 保证强度取自 `tests/share_confinement_escape_probe.rs` 与 ADR-034：`cap-std`
//! 4.0.3 在 Linux 上经 openat2 的 `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` 提供
//! 目录树包含，指向根外的符号链接被拒为 `PermissionDenied`。但库会跟随**根内**
//! 符号链接（`inside -> public` 解析成功），而共享授权是按 `root_id` + 相对路径
//! 给出的，跟随一根链接等于把"对 `public/` 的授权"外扩成"对链接所指子树的授权"，
//! 读、改名、删除都会落到用户没预期的位置。因此本层在库之上逐段拒绝**任何**符号链接：
//! 这是策略，不是重复劳动（ADR-034「决定」第 2 条）。
//!
//! ## 句柄化后的对象模型
//!
//! `resolve` 交回的 `ConfinedTarget` 内嵌 [`CapTargetToken`]：**已验证父目录 fd +
//! 末段名 + 登记代次**。此后的每个动词（`target_*`）都先经 `live_token` 复核——
//! 登记代次匹配（撤销或重登记立即作废旧 token）且登记路径统计出的 `dev`/`ino`
//! 仍等于登记身份（根被挪走/同路径重建即 `RootGone`）——然后相对 token 内 fd 操作，
//! "检查过的对象"与"被操作的对象"是同一个 fd。
//!
//! 逐段下行用 `open_dir_nofollow`（`cap-fs-ext`，原子地拒绝符号链接段），末段的
//! 读取/下行用 `follow(FollowSymlinks::No)`，"判定与下行之间被换成符号链接"的最后
//! 一缝在段级也被关闭。同根移动（`target_rename`/回收站进出/暂存落位）以两端目录
//! fd 为锚调 `Dir::rename`，末段名不重新走路径解析，因此没有中间段竞态。
//!
//! 如实记录的残留：`Dir::copy` 语义的源检查是"先 lstat 再打开"，残窗内最坏读到
//! 根内另一文件（不出授权边界）；登记路径的父目录可写这一前提在威胁模型之外。
//!
//! 错误的不透明性：`Denied` / `ReservedName` / `RootGone` 都是无载荷变体，不可能回显
//! 路径片段（规格 §6）。`Io { source }` 的文本由下层决定，所以本层只把 `cap-std`/OS
//! 自己产生的 `io::Error` 原样带上（其显示文本不含路径），**绝不**自己构造含路径的
//! 错误消息。

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use uc_core::ports::remote_share::{
    is_reserved_share_component, is_reserved_staging_component, is_reserved_trash_component,
    is_well_formed_relative, is_windows_reserved_device_name, ConfineError, ConfinedDirEntry,
    ConfinedMetadata, ConfinedTarget, ConfinedTargetToken, ConfinedTrashEntry, ConfinedTrashPage,
    ConflictPolicy, RootIdentity, ShareConfinementPort, ShareRootId, ShareStagedEntry,
};

/// 单次解析允许的最大层数，比客户端树深度上限（8）留足余量。
const MAX_COMPONENTS: usize = 32;

/// 相对路径原文的字节上限。ADR-034 把"超长"列为库不提供、本层必须自己定的规则之一；
/// 这里先把病态长的输入挡在系统调用之前。4 KiB 已贴着 POSIX `PATH_MAX`，
/// 比这更长的相对路径在三个目标平台上都落不了盘。
const MAX_RELATIVE_BYTES: usize = 4096;

/// 回收目录名模板：`.uniclipboard-trash-<root_id>`（规格 §6.1）。
const TRASH_PREFIX: &str = ".uniclipboard-trash-";
/// 上传暂存目录名模板：`.uniclipboard-staging-<staging_id>`（规格 §6.1）。
const STAGING_PREFIX: &str = ".uniclipboard-staging-";
/// 回收条目在回收目录内的载体文件名与元数据文件名。
const TRASH_PAYLOAD_NAME: &str = "payload";
const TRASH_META_NAME: &str = "meta.json";
/// 回收条目的保留期：七天（规格 §11.7）。
const TRASH_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 自动改名探测的上界，超过即放弃而不是无限试探。
const MAX_AUTO_RENAME_ATTEMPTS: u32 = 10_000;

/// `meta.json` 的落盘形状：回收条目的原相对路径、删除时刻与形状摘要。
/// 它写在根内保留命名空间，属于内核自有元数据；相对路径不含宿主绝对路径。
#[derive(Debug, Serialize, Deserialize)]
struct TrashMeta {
    original_rel: String,
    deleted_at_ms: i64,
    is_dir: bool,
    size_bytes: u64,
}

/// 已登记的根：能力句柄 + 该句柄所指目录的绝对路径 + 文件系统身份 + 登记代次。
///
/// `path` 在登记时经 `canonicalize` 定稿，`identity` 从**已打开的 `dir`** 取
/// `dev`/`ino` 并与 `std::fs::metadata(path)` 的统计值互证——两个独立解析若指向
/// 不同的树，互证失配即拒绝登记。此后每次存活检查复核路径身份仍等于 `identity`。
struct RootHandle {
    dir: Dir,
    path: PathBuf,
    identity: RootIdentity,
    generation: u64,
}

/// [`ConfinedTargetToken`] 的具体形态：`resolve` 时刻已验证的**父目录 fd +
/// 末段名 + 登记代次**；末段为 `None` 即目标即根自身，`parent` 此时就是根 fd。
struct CapTargetToken {
    parent: Dir,
    leaf: Option<OsString>,
    root: ShareRootId,
    generation: u64,
}

impl ConfinedTargetToken for CapTargetToken {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl CapTargetToken {
    fn try_clone(&self) -> Result<Self, ConfineError> {
        Ok(Self {
            parent: self.parent.try_clone().map_err(confine_io_error)?,
            leaf: self.leaf.clone(),
            root: self.root,
            generation: self.generation,
        })
    }
}

/// [`ShareConfinementPort`] 的 cap-std 实现。
///
/// 内部只有一张 `root_id -> RootHandle` 表加一个代次计数器；克隆出来的实例
/// 共享同一张表，因此可以在装配层按 `Arc` 传递。
///
/// 所有方法走的都是同步 cap-std/`std::fs` 系统调用：调用方不得假设它们已被
/// 卸载到阻塞线程池，必要时自行 `spawn_blocking`。
#[derive(Clone, Default)]
pub struct CapStdConfinement {
    roots: Arc<RwLock<HashMap<ShareRootId, RootHandle>>>,
    next_generation: Arc<AtomicU64>,
}

/// 段名字的本层规则。刻意不依赖"调用方已经筛查过整条路径"，也不依赖库在三个平台上
/// 各自的路径解析行为：`is_well_formed_relative`、`is_windows_reserved_device_name`
/// 与保留命名空间谓词都是宿主无关的纯字符串判定（前者经 `normalize_share_component`
/// 折叠大小写与结尾点/空格）。谓词只有 core 一个来源，本层不再各自裁剪。
fn check_name(name: &str) -> Result<(), ConfineError> {
    if !is_well_formed_relative(name) || is_windows_reserved_device_name(name) {
        return Err(ConfineError::Denied);
    }
    if is_reserved_share_component(name) {
        return Err(ConfineError::ReservedName);
    }
    Ok(())
}

/// 段的符号链接检查（`symlink_metadata` 不跟随）。段不存在不算失败：末段允许
/// 尚未创建（`Mkdir`/`StageUpload` 的目标），中间段随后必然在 `open_dir_nofollow`
/// 上失败并被归类。
fn check_not_symlink(dir: &Dir, name: &OsStr) -> Result<(), ConfineError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfineError::Denied),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(confine_io_error(source)),
    }
}

/// 逐段下行并**捕获**末段父目录 fd：中间段经 `open_dir_nofollow` 原子拒绝
/// 符号链接（检查即下行，没有"先判定再打开"的缝），末段只做名字与符号链接判定，
/// 真正打开留给各动词自己的 no-follow 路径。
///
/// 返回 `(末段父目录 fd, 末段名)`。
fn confine_and_capture(root: &Dir, client_rel: &str) -> Result<(Dir, OsString), ConfineError> {
    let mut names = client_rel.split('/').peekable();
    let mut opened: Option<Dir> = None;

    while let Some(name) = names.next() {
        let parent = match &opened {
            Some(dir) => dir,
            None => root,
        };
        check_name(name)?;
        // 还有后续段才需要把它当目录打开；末段只约束到此为止。
        if names.peek().is_some() {
            let descended = parent.open_dir_nofollow(name).map_err(confine_walk_error)?;
            opened = Some(descended);
        } else {
            check_not_symlink(parent, OsStr::new(name))?;
            let leaf = OsString::from(name);
            let parent_fd = match opened {
                Some(dir) => dir,
                None => root.try_clone().map_err(confine_io_error)?,
            };
            return Ok((parent_fd, leaf));
        }
    }
    // 循环至少返回一次（`client_rel` 非空且文法已筛），走到这里说明输入为空，
    // 而空输入在 `resolve` 入口已被文法拒绝——这一支不可达，归 `Denied` 兜底。
    Err(ConfineError::Denied)
}

/// 把目标当作目录打开：根目标返回根 fd 的克隆；末段目标先 lstat 分类
/// （不存在/符号链接/非目录），再 `open_dir_nofollow` 原子下行。
fn open_target_dir(token: &CapTargetToken) -> Result<Dir, ConfineError> {
    match &token.leaf {
        None => token.parent.try_clone().map_err(confine_io_error),
        Some(leaf) => {
            match token.parent.symlink_metadata(leaf) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(ConfineError::Denied);
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(ConfineError::NotADirectory);
                }
                Ok(_) => {}
                Err(source) if source.kind() == ErrorKind::NotFound => {
                    return Err(ConfineError::NotFound);
                }
                Err(source) => return Err(confine_io_error(source)),
            }
            token
                .parent
                .open_dir_nofollow(leaf)
                .map_err(confine_io_error)
        }
    }
}

/// 目标自身的元数据（lstat 语义；根目标取根 fd 的元数据）。
fn metadata_of(dir: &Dir, name: Option<&OsStr>) -> Result<(bool, bool, u64, i64), ConfineError> {
    let metadata = match name {
        Some(leaf) => dir.symlink_metadata(leaf).map_err(leaf_walk_error)?,
        None => dir.dir_metadata().map_err(confine_io_error)?,
    };
    // cap-std 的 `modified()` 返回自有 `SystemTime`，`into_std` 换成标准库类型。
    let modified = metadata.modified().ok().map(|t| t.into_std());
    Ok((
        metadata.is_dir(),
        metadata.is_file(),
        metadata.len(),
        mtime_ms(modified),
    ))
}

/// 末段目标的元数据分类：不存在/符号链接照实分类，其余 errno 进不透明归类。
fn leaf_walk_error(source: std::io::Error) -> ConfineError {
    match source.kind() {
        ErrorKind::NotFound => ConfineError::NotFound,
        ErrorKind::PermissionDenied | ErrorKind::NotADirectory | ErrorKind::InvalidFilename => {
            ConfineError::Denied
        }
        _ => ConfineError::Io { source },
    }
}

/// `ELOOP`：符号链接命中 no-follow 打开的错误形状（unix）。`io::ErrorKind` 尚未把
/// `FilesystemLoop` 稳定出来，按原始 errno 判定；非 unix 平台返回 `false`，
/// 命中即落入 `Io`（前置的 lstat 分类已覆盖常规符号链接，这一支只兜竞态）。
#[cfg(unix)]
fn is_loop_error(source: &std::io::Error) -> bool {
    source.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_loop_error(_source: &std::io::Error) -> bool {
    false
}

/// 中间段 `open_dir_nofollow` 一路的 errno 归类：段缺失/穿过普通文件是不透明拒绝
/// （与 `confine_io_error` 的语义一致），符号链接命中 `openat2` 呈 `ELOOP` 归拒绝。
fn confine_walk_error(source: std::io::Error) -> ConfineError {
    if is_loop_error(&source) {
        return ConfineError::Denied;
    }
    match source.kind() {
        ErrorKind::NotFound => ConfineError::NotFound,
        ErrorKind::PermissionDenied | ErrorKind::NotADirectory | ErrorKind::InvalidFilename => {
            ConfineError::Denied
        }
        _ => ConfineError::Io { source },
    }
}

/// `register_root` 一路（环境权限打开根）上的 errno 归类。
fn root_io_error(source: std::io::Error) -> ConfineError {
    match source.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::PermissionDenied => {
            ConfineError::RootGone
        }
        _ => ConfineError::Io { source },
    }
}

/// 逐段行走一路的 errno 归类（叶子动词用 `leaf_walk_error`/`confine_walk_error`）。
fn confine_io_error(source: std::io::Error) -> ConfineError {
    if is_loop_error(&source) {
        return ConfineError::Denied;
    }
    match source.kind() {
        ErrorKind::PermissionDenied
        | ErrorKind::NotFound
        | ErrorKind::NotADirectory
        | ErrorKind::InvalidFilename => ConfineError::Denied,
        ErrorKind::AlreadyExists => ConfineError::Conflict,
        _ => ConfineError::Io { source },
    }
}

/// `SystemTime` → unix 毫秒（早于 epoch 或不支持时归零，不值得把 mtime 当错误上报）。
fn mtime_ms(modified: Option<SystemTime>) -> i64 {
    modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    mtime_ms(Some(SystemTime::now()))
}

/// 从 `std::fs` 元数据取文件系统身份（dev/ino；Windows 上为卷序列号 + file index）。
#[cfg(unix)]
fn identity_of(meta: &std::fs::Metadata) -> RootIdentity {
    use std::os::unix::fs::MetadataExt;
    RootIdentity {
        device: meta.dev(),
        index: meta.ino(),
    }
}

#[cfg(windows)]
fn identity_of(meta: &std::fs::Metadata) -> RootIdentity {
    use std::os::windows::fs::MetadataExt;
    let index = (u64::from(meta.file_index_high()) << 32) | u64::from(meta.file_index_low());
    RootIdentity {
        device: u64::from(meta.volume_serial_number()),
        index,
    }
}

/// 非 unix/windows 平台没有可复核的身份字段——但根身份的 fail-closed 语义要求
/// 一个确定值，这里固定返回同一占位值并在 `root_live` 里退化为"路径还是目录"，
/// 与旧实现等价。三个目标平台都落在 unix/windows 上，此分支是保守兜底。
#[cfg(not(any(unix, windows)))]
fn identity_of(_meta: &std::fs::Metadata) -> RootIdentity {
    RootIdentity {
        device: 0,
        index: 0,
    }
}

/// 根当前还在不在且**还是登记时的那棵树**：路径统计出的身份仍等于登记身份。
/// "改名挪走不重植"（stat 失败）、"同路径重建"、"替换为指向他处的链接"
/// （身份失配）三种形态在这里都归 `false`。
fn root_live(path: &Path, identity: RootIdentity) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_dir() && identity_of(&meta) == identity,
        Err(_) => false,
    }
}

/// 把 `OsStr` 段名转成 String 供文法与保留名谓词判定（与列举输出的无损口径一致）。
fn name_str(name: &OsStr) -> String {
    name.to_string_lossy().into_owned()
}

/// 回收目录名（本根自己的那个）。
fn trash_dir_name(root: ShareRootId) -> String {
    format!("{TRASH_PREFIX}{}", root.0)
}

/// 暂存目录名。
fn staging_dir_name(staging_id: &str) -> String {
    format!("{STAGING_PREFIX}{staging_id}")
}

/// `trash_id`/`staging_id` 这类内核发的不透明名的入参校验：必须是单段、
/// 合文法、且不得伪装进保留命名空间。
fn check_opaque_id(id: &str) -> Result<(), ConfineError> {
    if id.is_empty()
        || id.contains('/')
        || !is_well_formed_relative(id)
        || is_reserved_share_component(id)
        || id.len() > 64
    {
        return Err(ConfineError::Denied);
    }
    Ok(())
}

/// 在一个已打开的目录 fd 内按相对路径下行，逐段拒绝符号链接。
/// 用于暂存目录与回收目录内部的路径解析——它们的 rel 是内核自有命名空间，
/// 仍过同一套逐段规则（多一重防线，不许依赖调用方）。
fn descend_within(base: &Dir, parents: &[&str]) -> Result<Dir, ConfineError> {
    let mut current = base.try_clone().map_err(confine_io_error)?;
    for segment in parents {
        check_name(segment)?;
        current = current
            .open_dir_nofollow(segment)
            .map_err(confine_walk_error)?;
    }
    Ok(current)
}

/// 在一个已打开的目录 fd 内按相对路径**建目录链**（`mkdir -p` 语义），
/// 逐段拒绝符号链接。已存在的目录段照常下行；撞普通文件即拒绝。
fn ensure_dir_within(base: &Dir, parents: &[&str]) -> Result<Dir, ConfineError> {
    let mut current = base.try_clone().map_err(confine_io_error)?;
    for segment in parents {
        check_name(segment)?;
        match current.create_dir(segment) {
            Ok(()) => {}
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
            Err(source) => return Err(confine_io_error(source)),
        }
        current = current
            .open_dir_nofollow(segment)
            .map_err(confine_walk_error)?;
    }
    Ok(current)
}

/// 拆开 `a/b/c.txt` 为 `(&["a","b"], "c.txt")`。调用方保证 `rel` 已过文法筛查。
fn split_rel(rel: &str) -> (Vec<&str>, &str) {
    match rel.rfind('/') {
        Some(index) => (rel[..index].split('/').collect(), &rel[index + 1..]),
        None => (Vec::new(), rel),
    }
}

/// 为末段生成不冲突名：`name`、`name (1).ext`、`name (2).ext`…
/// 探测用 `symlink_metadata`（lstat），与创建路径的 no-follow 语义一致。
fn unique_leaf(parent: &Dir, leaf: &OsStr) -> Result<OsString, ConfineError> {
    match parent.symlink_metadata(leaf) {
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(leaf.to_os_string()),
        Ok(_) => {}
        Err(source) => return Err(confine_io_error(source)),
    }
    let text = name_str(leaf);
    let (stem, ext) = match text.rfind('.') {
        Some(index) if index > 0 => (&text[..index], &text[index..]),
        _ => (text.as_str(), ""),
    };
    for n in 1..MAX_AUTO_RENAME_ATTEMPTS {
        let candidate = OsString::from(format!("{stem} ({n}){ext}"));
        match parent.symlink_metadata(&candidate) {
            Err(source) if source.kind() == ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(source) => return Err(confine_io_error(source)),
        }
    }
    Err(ConfineError::Conflict)
}

/// 文件内容逐 fd 复制：两端都是相对各自已持有 fd 的 no-follow 打开/新建。
fn copy_file_within(
    from_parent: &Dir,
    from_leaf: &OsStr,
    to_parent: &Dir,
    to_leaf: &OsStr,
) -> Result<(), ConfineError> {
    let mut source = from_parent
        .open_with(
            from_leaf,
            OpenOptions::new().read(true).follow(FollowSymlinks::No),
        )
        .map_err(leaf_walk_error)?
        .into_std();
    let mut target = to_parent
        .open_with(
            to_leaf,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No),
        )
        .map_err(confine_io_error)?
        .into_std();
    std::io::copy(&mut source, &mut target).map_err(confine_io_error)?;
    Ok(())
}

/// 目录树递归复制：源 fd 与目标 fd 都是 `open_dir_nofollow` 得来的；
/// 符号链接条目跳过（它们在协议上本即不可寻址，复制其指向内容反而越权）。
fn copy_tree_within(from_dir: &Dir, to_dir: &Dir, depth: usize) -> Result<(), ConfineError> {
    if depth > MAX_COMPONENTS {
        return Err(ConfineError::Denied);
    }
    for entry in from_dir.entries().map_err(confine_io_error)? {
        let entry = entry.map_err(confine_io_error)?;
        let file_type = entry.file_type().map_err(confine_io_error)?;
        let name = entry.file_name();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            match to_dir.create_dir(&name) {
                Ok(()) => {}
                Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
                Err(source) => return Err(confine_io_error(source)),
            }
            let from_sub = from_dir
                .open_dir_nofollow(&name)
                .map_err(confine_walk_error)?;
            let to_sub = to_dir
                .open_dir_nofollow(&name)
                .map_err(confine_walk_error)?;
            copy_tree_within(&from_sub, &to_sub, depth + 1)?;
        } else {
            copy_file_within(from_dir, &name, to_dir, &name)?;
        }
    }
    Ok(())
}

/// 序列化 `meta.json`；失败归入 `Io`（不落半份元数据——`write` 是整文件的）。
fn write_trash_meta(entry_dir: &Dir, meta: &TrashMeta) -> Result<(), ConfineError> {
    let bytes = serde_json::to_vec(meta).map_err(|source| ConfineError::Io {
        source: std::io::Error::other(source),
    })?;
    entry_dir
        .write(TRASH_META_NAME, bytes)
        .map_err(confine_io_error)
}

/// 读一个回收子目录的 `meta.json`；缺失或损坏返回 `Ok(None)`（该条目对
/// 对端不可见、也不阻塞其余条目——损坏的元数据不该拖垮整页）。
fn read_trash_meta(entry_dir: &Dir) -> Result<Option<TrashMeta>, ConfineError> {
    let bytes = match entry_dir.read(TRASH_META_NAME) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(confine_io_error(source)),
    };
    match serde_json::from_slice::<TrashMeta>(&bytes) {
        Ok(meta) => Ok(Some(meta)),
        Err(_) => Ok(None),
    }
}

/// 打开根的回收目录（不存在返回 `Ok(None)`）。
fn open_trash_dir(root_dir: &Dir, root: ShareRootId) -> Result<Option<Dir>, ConfineError> {
    match root_dir.open_dir_nofollow(trash_dir_name(root)) {
        Ok(dir) => Ok(Some(dir)),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(confine_walk_error(source)),
    }
}

/// 打开根的暂存目录（不存在返回 `Ok(None)`；调用方决定 `NotFound` 与否）。
fn open_staging_dir(root_dir: &Dir, staging_id: &str) -> Result<Option<Dir>, ConfineError> {
    match root_dir.open_dir_nofollow(staging_dir_name(staging_id)) {
        Ok(dir) => Ok(Some(dir)),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(confine_walk_error(source)),
    }
}

/// 丢弃一个暂存目录；不存在视为已丢弃（幂等）。
fn remove_staging_tree(root_dir: &Dir, staging_id: &str) -> Result<(), ConfineError> {
    match root_dir.remove_dir_all(staging_dir_name(staging_id)) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(confine_io_error(source)),
    }
}

/// 惰性过期清扫：回收子目录里 `meta.deleted_at_ms` 超过保留期的整棵移除。
fn sweep_expired_trash(trash_dir: &Dir, cutoff_ms: i64) {
    let Ok(entries) = trash_dir.entries() else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Ok(entry_dir) = trash_dir.open_dir_nofollow(entry.file_name()) else {
            continue;
        };
        let Ok(Some(meta)) = read_trash_meta(&entry_dir) else {
            continue;
        };
        if meta.deleted_at_ms < cutoff_ms {
            // 清扫失败不升级：条目留在原地，下一次惰性清扫再试。
            // discarded-source[best-effort-cleanup]: `std::io::Error`: a failed
            // sweep leaves the expired entry in place; the next lazy sweep retries.
            let _ = trash_dir.remove_dir_all(entry.file_name());
        }
    }
}

/// 从已打开的目录句柄取文件系统身份（`dir` → `File` → `metadata`）。
fn identity_of_dir(dir: &Dir) -> Result<RootIdentity, ConfineError> {
    let file = dir.try_clone().map_err(confine_io_error)?.into_std_file();
    let meta = file.metadata().map_err(confine_io_error)?;
    Ok(identity_of(&meta))
}

#[async_trait]
impl ShareConfinementPort for CapStdConfinement {
    /// 登记一棵共享根：定稿路径 → 打开句柄 → 句柄身份与路径统计互证 →
    /// 扫描根内保留命名空间占用。任一失败即拒绝且不留下注册痕迹。
    async fn register_root(&self, root: ShareRootId, path: &Path) -> Result<(), ConfineError> {
        // canonicalize 跟随一次符号链接（用户登记一个"链接到的目录"是合法意图）；
        // 之后身份互证用的是"句柄 stat"与"定稿路径 stat"两侧，二者失配即拒绝。
        let canonical = std::fs::canonicalize(path).map_err(root_io_error)?;
        let dir = Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(root_io_error)?;

        let handle_identity = identity_of_dir(&dir)?;
        let path_identity = std::fs::metadata(&canonical)
            .map(|meta| identity_of(&meta))
            .map_err(root_io_error)?;
        if handle_identity != path_identity {
            // 句柄与路径指向不同的树：登记即失败（不猜哪一边对）。
            return Err(ConfineError::Denied);
        }

        // 规格 §6.1 的启用扫描：根内已占用保留命名空间的条目使该根不可启用；
        // 本根自己的回收目录保留（含历史条目），`.uniclipboard-staging-*` 一律
        // 视为崩溃残留清掉（该前缀只有内核会写）。
        let own_trash = trash_dir_name(root);
        for entry in dir.entries().map_err(confine_io_error)? {
            let entry = entry.map_err(confine_io_error)?;
            let name = name_str(&entry.file_name());
            if name.eq_ignore_ascii_case(&own_trash) {
                continue;
            }
            if is_reserved_trash_component(&name) {
                return Err(ConfineError::ReservedName);
            }
            if is_reserved_staging_component(&name) {
                let file_type = entry.file_type().map_err(confine_io_error)?;
                let result = if file_type.is_dir() {
                    dir.remove_dir_all(&name)
                } else {
                    dir.remove_file_or_symlink(&name)
                };
                result.map_err(confine_io_error)?;
            }
        }

        // 惰性过期清扫：本根回收目录里超过保留期的条目顺手清掉。
        if let Some(trash_dir) = open_trash_dir(&dir, root)? {
            sweep_expired_trash(&trash_dir, now_ms() - TRASH_RETENTION_MS);
        }

        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        // 丢弃来源是 error-handling.md 列出的允许例外：锁中毒的 `PoisonError`
        // 持有 guard、不能跨线程保存，也不含可用诊断信息。此处按 fail-closed
        // 归为不透明拒绝。
        // discarded-source[lock-poisoned]: `std::sync::PoisonError<Guard>`: the poison error holds the guard and cannot be stored across threads
        let mut guard = self.roots.write().map_err(|_| ConfineError::Denied)?;
        guard.insert(
            root,
            RootHandle {
                dir,
                path: canonical,
                identity: handle_identity,
                generation,
            },
        );
        Ok(())
    }

    /// 撤销注册并释放表里的句柄。撤销后新解析与旧代次 token 上的动词一律
    /// `RootGone`——句柄化之后这条保证由代次复核落实（`live_token`）。
    async fn unregister_root(&self, root: ShareRootId) {
        if let Ok(mut guard) = self.roots.write() {
            guard.remove(&root);
        }
    }

    /// 登记表成员 + 根仍然活着且身份未变，才算"登记中"。根在磁盘上被挪走/
    /// 替换后这里如实返回 `false`，驱动清单侧的 `unavailable` 呈现。
    async fn is_registered(&self, root: ShareRootId) -> bool {
        let Ok(guard) = self.roots.read() else {
            return false;
        };
        let Some(handle) = guard.get(&root) else {
            return false;
        };
        root_live(&handle.path, handle.identity)
    }

    /// 第一道：宿主无关的线文法筛查 + 层数/字节上限（在触达文件系统之前）。
    /// 之后取登记根（身份复核含在内），最后逐段下行并捕获末段父 fd。
    async fn resolve(
        &self,
        root: ShareRootId,
        client_rel: &str,
    ) -> Result<ConfinedTarget, ConfineError> {
        if !is_well_formed_relative(client_rel) || client_rel.len() > MAX_RELATIVE_BYTES {
            return Err(ConfineError::Denied);
        }
        if client_rel.split('/').count() > MAX_COMPONENTS {
            return Err(ConfineError::Denied);
        }

        let (root_dir, _root_path, _identity, generation) = self.opened_root(root)?;
        let (parent, leaf) = confine_and_capture(&root_dir, client_rel)?;

        let token = CapTargetToken {
            parent,
            leaf: Some(leaf),
            root,
            generation,
        };
        let relative: PathBuf = client_rel.split('/').collect();
        Ok(ConfinedTarget::new(root, relative, Arc::new(token)))
    }

    /// 共享根**自身**：与 `resolve` 共用同一个 `opened_root`（同一套登记查找、
    /// 身份复核与失败分类），token 的 `leaf` 为空表示"目标即根"。
    async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
        let (root_dir, _root_path, _identity, generation) = self.opened_root(root)?;
        let token = CapTargetToken {
            parent: root_dir,
            leaf: None,
            root,
            generation,
        };
        Ok(ConfinedTarget::new(root, PathBuf::new(), Arc::new(token)))
    }

    async fn target_metadata(
        &self,
        target: &ConfinedTarget,
    ) -> Result<ConfinedMetadata, ConfineError> {
        let (token, root_path) = self.live_token(target)?;
        let name = match &token.leaf {
            Some(leaf) => name_str(leaf),
            None => root_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        let (is_dir, is_file, size_bytes, modified_at_ms) =
            metadata_of(&token.parent, token.leaf.as_deref())?;
        Ok(ConfinedMetadata {
            name,
            is_dir,
            is_file,
            size_bytes,
            modified_at_ms,
        })
    }

    async fn target_child_metadata(
        &self,
        target: &ConfinedTarget,
        name: &str,
    ) -> Result<ConfinedMetadata, ConfineError> {
        check_name(name)?;
        let (token, _root_path) = self.live_token(target)?;
        let dir = open_target_dir(&token)?;
        let leaf = OsStr::new(name);
        let (is_dir, is_file, size_bytes, modified_at_ms) = metadata_of(&dir, Some(leaf))?;
        Ok(ConfinedMetadata {
            name: name.to_owned(),
            is_dir,
            is_file,
            size_bytes,
            modified_at_ms,
        })
    }

    async fn target_read_dir(
        &self,
        target: &ConfinedTarget,
    ) -> Result<Vec<ConfinedDirEntry>, ConfineError> {
        let (token, _root_path) = self.live_token(target)?;
        let dir = open_target_dir(&token)?;
        let mut entries = Vec::new();
        for entry in dir.entries().map_err(confine_io_error)? {
            let entry = entry.map_err(confine_io_error)?;
            let name = name_str(&entry.file_name());
            // 保留命名空间在序列化边界就过滤掉（规格 §6.1）：本根自己的回收目录
            // 与残留暂存目录都不出现在对端视野里。
            if is_reserved_share_component(&name) {
                continue;
            }
            let file_type = entry.file_type().map_err(confine_io_error)?;
            entries.push(ConfinedDirEntry {
                name,
                is_dir: file_type.is_dir(),
                is_file: file_type.is_file(),
                is_symlink: file_type.is_symlink(),
            });
        }
        Ok(entries)
    }

    async fn target_open_read(
        &self,
        target: &ConfinedTarget,
    ) -> Result<std::fs::File, ConfineError> {
        let (token, _root_path) = self.live_token(target)?;
        let Some(leaf) = &token.leaf else {
            return Err(ConfineError::IsADirectory);
        };
        match token.parent.symlink_metadata(leaf) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ConfineError::Denied);
            }
            Ok(metadata) if metadata.is_dir() => return Err(ConfineError::IsADirectory),
            Ok(_) => {}
            Err(source) if source.kind() == ErrorKind::NotFound => {
                return Err(ConfineError::NotFound);
            }
            Err(source) => return Err(confine_io_error(source)),
        }
        Ok(token
            .parent
            .open_with(
                leaf,
                OpenOptions::new().read(true).follow(FollowSymlinks::No),
            )
            .map_err(confine_io_error)?
            .into_std())
    }

    async fn target_create_dir(&self, target: &ConfinedTarget) -> Result<(), ConfineError> {
        let (token, _root_path) = self.live_token(target)?;
        let Some(leaf) = &token.leaf else {
            return Err(ConfineError::Denied);
        };
        token.parent.create_dir(leaf).map_err(confine_io_error)
    }

    async fn target_rename(
        &self,
        from: &ConfinedTarget,
        to: &ConfinedTarget,
    ) -> Result<(), ConfineError> {
        let (from_token, _) = self.live_token(from)?;
        let (to_token, _) = self.live_token(to)?;
        if from_token.root != to_token.root {
            return Err(ConfineError::Denied);
        }
        let (Some(from_leaf), Some(to_leaf)) = (&from_token.leaf, &to_token.leaf) else {
            // 根自身不可被移动；目标末段缺失即拒绝。
            return Err(ConfineError::Denied);
        };
        // 目标名冲突在两端 fd 上做判定；rename 语义本身是 `renameat(oldfd, leaf,
        // newfd, leaf)`，末段名不重新走中间解析，因此没有段级竞态。
        match to_token.parent.symlink_metadata(to_leaf) {
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Ok(_) => return Err(ConfineError::Conflict),
            Err(source) => return Err(confine_io_error(source)),
        }
        from_token
            .parent
            .rename(from_leaf, &to_token.parent, to_leaf)
            .map_err(confine_io_error)
    }

    async fn target_copy_into(
        &self,
        from: &ConfinedTarget,
        to: &ConfinedTarget,
    ) -> Result<(), ConfineError> {
        let (from_token, _) = self.live_token(from)?;
        let (to_token, _) = self.live_token(to)?;
        if from_token.root != to_token.root {
            return Err(ConfineError::Denied);
        }
        let Some(to_leaf) = &to_token.leaf else {
            return Err(ConfineError::Denied);
        };
        let Some(from_leaf) = &from_token.leaf else {
            // 根自身不可作为拷贝源（整树拷贝会把回收目录一并克隆）。
            return Err(ConfineError::Denied);
        };
        match to_token.parent.symlink_metadata(to_leaf) {
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Ok(_) => return Err(ConfineError::Conflict),
            Err(source) => return Err(confine_io_error(source)),
        }

        let metadata = from_token
            .parent
            .symlink_metadata(from_leaf)
            .map_err(leaf_walk_error)?;
        if metadata.file_type().is_symlink() {
            return Err(ConfineError::Denied);
        }
        if metadata.is_dir() {
            let from_dir = from_token
                .parent
                .open_dir_nofollow(from_leaf)
                .map_err(confine_walk_error)?;
            to_token
                .parent
                .create_dir(to_leaf)
                .map_err(confine_io_error)?;
            let to_dir = to_token
                .parent
                .open_dir_nofollow(to_leaf)
                .map_err(confine_walk_error)?;
            copy_tree_within(&from_dir, &to_dir, 0)
        } else {
            copy_file_within(&from_token.parent, from_leaf, &to_token.parent, to_leaf)
        }
    }

    async fn target_move_to_trash(&self, target: &ConfinedTarget) -> Result<String, ConfineError> {
        let (token, _root_path) = self.live_token(target)?;
        let Some(leaf) = &token.leaf else {
            // 根自身不可被删除。
            return Err(ConfineError::Denied);
        };
        let (root_dir, _path, _identity, _generation) = self.opened_root(target.root)?;

        // 回收目录惰性创建（登记时保持根干净，首次删除才出现）。
        match root_dir.create_dir(trash_dir_name(target.root)) {
            Ok(()) => {}
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
            Err(source) => return Err(confine_io_error(source)),
        }
        let trash_dir = root_dir
            .open_dir_nofollow(trash_dir_name(target.root))
            .map_err(confine_walk_error)?;

        let trash_id = Uuid::new_v4().to_string();
        trash_dir.create_dir(&trash_id).map_err(confine_io_error)?;
        let entry_dir = trash_dir
            .open_dir_nofollow(&trash_id)
            .map_err(confine_walk_error)?;

        token
            .parent
            .rename(leaf, &entry_dir, TRASH_PAYLOAD_NAME)
            .map_err(confine_io_error)?;

        // 移动完成后从 payload 自身取形状摘要，保证元数据与实际落位一致。
        let (is_dir, _is_file, size_bytes, _) =
            metadata_of(&entry_dir, Some(OsStr::new(TRASH_PAYLOAD_NAME)))?;
        write_trash_meta(
            &entry_dir,
            &TrashMeta {
                original_rel: target.relative.to_string_lossy().into_owned(),
                deleted_at_ms: now_ms(),
                is_dir,
                size_bytes,
            },
        )?;
        Ok(trash_id)
    }

    async fn list_trash(
        &self,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ConfinedTrashPage, ConfineError> {
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        let Some(trash_dir) = open_trash_dir(&root_dir, root)? else {
            return Ok(ConfinedTrashPage {
                entries: Vec::new(),
                next_after: None,
            });
        };
        sweep_expired_trash(&trash_dir, now_ms() - TRASH_RETENTION_MS);

        let mut named: Vec<(String, Dir)> = Vec::new();
        for entry in trash_dir.entries().map_err(confine_io_error)? {
            let entry = entry.map_err(confine_io_error)?;
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Ok(entry_dir) = trash_dir.open_dir_nofollow(entry.file_name()) else {
                continue;
            };
            named.push((name_str(&entry.file_name()), entry_dir));
        }
        named.sort_by(|a, b| a.0.cmp(&b.0));

        let start = match after {
            Some(cursor) => named
                .iter()
                .position(|(id, _)| id.as_str() > cursor)
                .unwrap_or(named.len()),
            None => 0,
        };
        let mut entries = Vec::new();
        let mut consumed = start;
        for (trash_id, entry_dir) in named.iter().skip(start) {
            if entries.len() >= limit as usize {
                break;
            }
            consumed += 1;
            let Ok(Some(meta)) = read_trash_meta(entry_dir) else {
                continue;
            };
            entries.push(ConfinedTrashEntry {
                trash_id: trash_id.clone(),
                original_rel: meta.original_rel,
                deleted_at_ms: meta.deleted_at_ms,
                is_dir: meta.is_dir,
                size_bytes: meta.size_bytes,
            });
        }
        let next_after = if consumed < named.len() {
            entries.last().map(|entry| entry.trash_id.clone())
        } else {
            None
        };
        Ok(ConfinedTrashPage {
            entries,
            next_after,
        })
    }

    async fn restore_from_trash(
        &self,
        root: ShareRootId,
        trash_id: &str,
        to: &ConfinedTarget,
    ) -> Result<String, ConfineError> {
        check_opaque_id(trash_id)?;
        if to.root != root {
            return Err(ConfineError::Denied);
        }
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        let (to_token, _to_path) = self.live_token(to)?;
        let Some(to_leaf) = &to_token.leaf else {
            return Err(ConfineError::Denied);
        };
        let Some(trash_dir) = open_trash_dir(&root_dir, root)? else {
            return Err(ConfineError::NotFound);
        };
        let entry_dir = trash_dir
            .open_dir_nofollow(trash_id)
            .map_err(leaf_walk_error)?;

        // 还原冲突按规格的自动改名策略处理（§11.7 → §8.1）。
        let final_leaf = unique_leaf(&to_token.parent, to_leaf)?;
        entry_dir
            .rename(
                OsStr::new(TRASH_PAYLOAD_NAME),
                &to_token.parent,
                &final_leaf,
            )
            .map_err(confine_io_error)?;

        // 元数据与子目录一并清掉；清理失败不翻转已完成的还原。
        // discarded-source[best-effort-cleanup]: `std::io::Error` (×2): leftover
        // meta/empty dir inside the reserved trash namespace is inert and swept later.
        let _ = entry_dir.remove_file(TRASH_META_NAME);
        let _ = trash_dir.remove_dir(trash_id);
        Ok(name_str(&final_leaf))
    }

    async fn empty_trash(&self, root: ShareRootId) -> Result<(), ConfineError> {
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        let Some(trash_dir) = open_trash_dir(&root_dir, root)? else {
            return Ok(());
        };
        for entry in trash_dir.entries().map_err(confine_io_error)? {
            let entry = entry.map_err(confine_io_error)?;
            let file_type = entry.file_type().map_err(confine_io_error)?;
            let result = if file_type.is_dir() {
                trash_dir.remove_dir_all(entry.file_name())
            } else {
                trash_dir.remove_file_or_symlink(entry.file_name())
            };
            result.map_err(confine_io_error)?;
        }
        Ok(())
    }

    async fn create_staging(&self, root: ShareRootId) -> Result<String, ConfineError> {
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        let staging_id = Uuid::new_v4().to_string();
        root_dir
            .create_dir(staging_dir_name(&staging_id))
            .map_err(confine_io_error)?;
        Ok(staging_id)
    }

    async fn staging_entry_path(
        &self,
        root: ShareRootId,
        staging_id: &str,
        rel: &str,
        is_dir: bool,
    ) -> Result<PathBuf, ConfineError> {
        check_opaque_id(staging_id)?;
        if !is_well_formed_relative(rel) || rel.len() > MAX_RELATIVE_BYTES {
            return Err(ConfineError::Denied);
        }
        if rel.split('/').count() > MAX_COMPONENTS {
            return Err(ConfineError::Denied);
        }
        let (root_dir, root_path, _identity, _generation) = self.opened_root(root)?;
        let Some(staging_dir) = open_staging_dir(&root_dir, staging_id)? else {
            return Err(ConfineError::NotFound);
        };

        let (parents, leaf) = split_rel(rel);
        let parent_dir = ensure_dir_within(&staging_dir, &parents)?;
        check_name(leaf)?;
        check_not_symlink(&parent_dir, OsStr::new(leaf))?;
        if is_dir {
            match parent_dir.create_dir(leaf) {
                Ok(()) => {}
                Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
                Err(source) => return Err(confine_io_error(source)),
            }
        }

        // 暂存路径是内核自有命名空间内的宿主路径，只给持有方的写入端用，
        // 永不上线（规格 §13 I2 覆盖线上，不禁止内核内部的能力传递）。
        Ok(root_path
            .join(staging_dir_name(staging_id))
            .join(PathBuf::from(rel)))
    }

    async fn commit_staging(
        &self,
        root: ShareRootId,
        staging_id: &str,
        dir: &ConfinedTarget,
        entries: &[ShareStagedEntry],
        policy: ConflictPolicy,
    ) -> Result<(), ConfineError> {
        check_opaque_id(staging_id)?;
        if dir.root != root {
            return Err(ConfineError::Denied);
        }
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        let (dir_token, _dir_path) = self.live_token(dir)?;
        let dest_dir = open_target_dir(&dir_token)?;
        let Some(staging_dir) = open_staging_dir(&root_dir, staging_id)? else {
            return Err(ConfineError::NotFound);
        };

        let result = self.commit_entries(&staging_dir, &dest_dir, entries, policy);
        // 规格 §8.1：落位成功或失败都丢弃暂存目录（失败不留半成品）。清理失败
        // 不翻转已完成的结果：残留只剩空目录，登记扫描的惰性清扫会收走它。
        // discarded-source[best-effort-cleanup]: `ConfineError`: a leftover staging
        // dir after a finished commit/abort contains only empty dirs and is swept
        // on the next registration scan.
        let _ = remove_staging_tree(&root_dir, staging_id);
        result
    }

    async fn abort_staging(&self, root: ShareRootId, staging_id: &str) -> Result<(), ConfineError> {
        check_opaque_id(staging_id)?;
        let (root_dir, _path, _identity, _generation) = self.opened_root(root)?;
        remove_staging_tree(&root_dir, staging_id)
    }
}

impl CapStdConfinement {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 取出登记的那一棵根：句柄的独立副本 + 定稿路径 + 身份 + 代次。
    ///
    /// 读锁内只做 `try_clone` 与字段克隆，随即释放守卫；随后的存活检查
    /// （一次 `std::fs::metadata`）在锁外执行，避免对端触发的慢盘 I/O 占住读锁
    /// （Ruling 22 的同一族考虑）。
    fn opened_root(
        &self,
        root: ShareRootId,
    ) -> Result<(Dir, PathBuf, RootIdentity, u64), ConfineError> {
        // discarded-source[lock-poisoned]: `std::sync::PoisonError<Guard>`: the poison error holds the guard and cannot be stored across threads
        let guard = self.roots.read().map_err(|_| ConfineError::Denied)?;
        let handle = guard.get(&root).ok_or(ConfineError::RootGone)?;
        let dir = handle.dir.try_clone().map_err(confine_io_error)?;
        let path = handle.path.clone();
        let identity = handle.identity;
        let generation = handle.generation;
        drop(guard);
        if !root_live(&path, identity) {
            return Err(ConfineError::RootGone);
        }
        Ok((dir, path, identity, generation))
    }

    /// 复核一个 `ConfinedTarget` 的 token：向下转型、登记代次匹配、根仍活着。
    /// 返回 token 的 fd 副本与根的定稿路径（后者只用于根自身条目的名字）。
    fn live_token(
        &self,
        target: &ConfinedTarget,
    ) -> Result<(CapTargetToken, PathBuf), ConfineError> {
        let token = target
            .token()
            .as_any()
            .downcast_ref::<CapTargetToken>()
            .ok_or(ConfineError::Denied)?;
        if token.root != target.root {
            return Err(ConfineError::Denied);
        }
        let (_dir, path, _identity, generation) = self.opened_root(token.root)?;
        if generation != token.generation {
            // 撤销或重登记之后旧 token 即作废。
            return Err(ConfineError::RootGone);
        }
        Ok((token.try_clone()?, path))
    }

    /// `commit_staging` 的核心：逐项校验并落位。目录项先建链，文件项核对
    /// 存在与声明大小后 `rename` 进目标目录；`dir` 项只做 `mkdir -p` 语义。
    fn commit_entries(
        &self,
        staging_dir: &Dir,
        dest_dir: &Dir,
        entries: &[ShareStagedEntry],
        policy: ConflictPolicy,
    ) -> Result<(), ConfineError> {
        for entry in entries {
            if !is_well_formed_relative(&entry.rel) || entry.rel.len() > MAX_RELATIVE_BYTES {
                return Err(ConfineError::Denied);
            }
            let (parents, leaf) = split_rel(&entry.rel);
            check_name(leaf)?;
            let src_parent = descend_within(staging_dir, &parents)?;
            let dst_parent = ensure_dir_within(dest_dir, &parents)?;

            if entry.is_dir {
                match dst_parent.create_dir(leaf) {
                    Ok(()) => {}
                    Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
                    Err(source) => return Err(confine_io_error(source)),
                }
                continue;
            }

            // 文件项：存在性与声明大小核对（fetch 未完成/被截断都在此显形）。
            let staged_meta = src_parent.symlink_metadata(leaf).map_err(leaf_walk_error)?;
            if !staged_meta.is_file() || staged_meta.len() != entry.size_bytes {
                return Err(ConfineError::Io {
                    source: std::io::Error::other("staged entry missing or size mismatch"),
                });
            }

            let final_leaf = match dst_parent.symlink_metadata(leaf) {
                Err(source) if source.kind() == ErrorKind::NotFound => OsString::from(leaf),
                Ok(existing) => {
                    match policy {
                        ConflictPolicy::AutoRename => unique_leaf(&dst_parent, OsStr::new(leaf))?,
                        ConflictPolicy::Overwrite => {
                            if existing.is_dir() {
                                return Err(ConfineError::IsADirectory);
                            }
                            // 覆盖语义：先移除既有普通文件/符号链接再落位。
                            // 目录撞目录在 `is_dir` 分支合并；文件撞目录拒绝。
                            dst_parent
                                .remove_file_or_symlink(leaf)
                                .map_err(confine_io_error)?;
                            OsString::from(leaf)
                        }
                    }
                }
                Err(source) => return Err(confine_io_error(source)),
            };
            src_parent
                .rename(leaf, &dst_parent, &final_leaf)
                .map_err(confine_io_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // 行为级探针在 `tests/share_confinement_escape_probe.rs`；
    // 这里只留纯函数的最小断言。
    use super::*;

    #[test]
    fn split_rel_splits_last_component() {
        assert_eq!(split_rel("a/b/c.txt"), (vec!["a", "b"], "c.txt"));
        assert_eq!(split_rel("c.txt"), (Vec::<&str>::new(), "c.txt"));
        assert_eq!(split_rel("a/c.txt"), (vec!["a"], "c.txt"));
    }

    #[test]
    fn opaque_id_rejects_path_and_reserved_names() {
        assert!(check_opaque_id("00000000-0000-0000-0000-000000000000").is_ok());
        for bad in [
            "",
            "a/b",
            ".uniclipboard-trash-x",
            ".uniclipboard-staging-x",
            "..",
        ] {
            assert!(check_opaque_id(bad).is_err(), "应拒绝：{bad:?}");
        }
    }
}
