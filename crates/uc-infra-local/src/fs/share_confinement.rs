//! 共享根的路径约束内核——设备文件共享唯一的信任边界。
//!
//! 保证强度取自任务 1 的实测（`tests/share_confinement_escape_probe.rs`、ADR-034）：
//! `cap-std` 4.0.3 在 Linux 上经 openat2 的 `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
//! 提供**目录树包含**，指向根外的符号链接被拒为 `PermissionDenied`。但同一次实测也证明
//! **库会跟随根内的符号链接**（`inside -> public` 解析成功）。共享授权是按 `root_id` +
//! 相对路径给出的，跟随一根链接等于把"对 `public/` 的授权"外扩成"对链接所指子树的授权"，
//! 读、改名、删除都会落到用户没有预期的位置。因此本层在库之上逐段拒绝**任何**符号链接：
//! 这是策略，不是重复劳动，**不得以"库已经挡住了"为理由删掉这段检查**（ADR-034「决定」
//! 第 2 条要求在此与 ADR 同时留痕）。
//!
//! Windows 与 macOS 未实测（ADR-034 结论表记「跳过」），所以本层不得把安全性寄托在库的
//! 实现行为上：宿主无关的字面筛查、逐段名字检查与逐段符号链接拒绝都是独立于库的第二道边界。
//! Windows 保留设备名（`CON`/`NUL`/`COMn`/`LPTn`/`PRN`/`AUX`/`CLOCK$`）也在这道名字边界里
//! 挡下：库自己的设备名过滤只作用于**库的 open**，而本层从不打开末段，那条过滤在这条路径上
//! 一次都不会执行——`<root>\CON` 在 Win32 里根本不在共享树上（危险的是命名空间切换，不是上跳）。
//!
//! 另两条实测出的 API 形状决定了本文件的写法：`cap_std::fs::Dir` 不实现 `Clone`
//! （只有 `try_clone()`），也没有 `path_for`。故句柄与其绝对路径成对保存在 `RootHandle`
//! 里，中间段用 `open_dir` 逐段下行（每步得到一个新的 owned `Dir`，不需要 `Clone`），
//! `ConfinedTarget::real_path` 由登记时定稿的根路径拼接而来。
//!
//! 本层约束的是**解析**，不是调用方随后那次环境权限打开，且它把 TOCTOU 窗口收窄而未闭合：
//! 中间段是"先 `symlink_metadata` 名字判定、再 `open_dir` 下行"两步，二者之间该段仍可被换成
//! 一根指向根内的符号链接——库会跟随它，于是下行落到用户没预期的子树。末段更不必说：本层
//! 从不打开末段，只把它名字与符号链接查过就交回绝对路径 `real_path`（`ConfinedTarget` 的文档
//! 记着这条义务与限制）。做到"检查过的对象与使用的对象是同一个 fd"要交出对外不透明的句柄并
//! 提供相对句柄的操作，已由控制方定为 P2 前置项，不在本轮。诚实的结论是：**窗口变窄，不是关闭。**
//!
//! 错误的不透明性：`Denied` / `ReservedName` / `RootGone` 都是无载荷变体，不可能回显路径
//! 片段（规格 §6）。`Io { source }` 的文本由下层决定，所以本层只把 `cap-std`/OS 自己产生的
//! `io::Error` 原样带上（其显示文本不含路径），**绝不**自己构造含路径的错误消息。

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use cap_std::ambient_authority;
use cap_std::fs::Dir;

use uc_core::ports::remote_share::{
    is_reserved_trash_component, is_well_formed_relative, is_windows_reserved_device_name,
    ConfineError, ConfinedTarget, ShareConfinementPort, ShareRootId,
};

/// 单次解析允许的最大层数，比客户端树深度上限（8）留足余量。
const MAX_COMPONENTS: usize = 32;

/// 相对路径原文的字节上限。ADR-034 把"超长"列为库不提供、本层必须自己定的规则之一；
/// 这里先把病态长的输入挡在系统调用之前。4 KiB 已贴着 POSIX `PATH_MAX`，
/// 比这更长的相对路径在三个目标平台上都落不了盘。
const MAX_RELATIVE_BYTES: usize = 4096;

/// 已登记的根：能力句柄 + 该句柄所指目录的绝对路径。
///
/// `Dir` 不可 `Clone` 也没有 `path_for`，故两者成对保存。`path` 在登记时经 `canonicalize`
/// 定稿，堵掉"调用方当初传入的那个路径后来被换成符号链接"这一条通道：拼出来的 `real_path`
/// 用的是定稿后的绝对路径，不再回看那个可能被改动过的原始输入。
///
/// 但它**不**保证 `path` 与 `dir` 指向同一棵树：`std::fs::canonicalize(path)` 与紧随其后的
/// `Dir::open_ambient_dir(&canonical)` 是两次独立的环境权限解析，若登记过程中 `canonical`
/// 被换成符号链接，`dir` 约束的是一棵树而 `path`（进而每个 `real_path`）说的是另一棵。
/// ADR-034 把"字符串定稿再另开一次"列为纯字符串方案（选项 C）的失格理由，本层没有更强。
/// 彻底的修法是在登记时从已打开的句柄取 `dev`/`ino`、并在 `root_is_live` 复核，不匹配即
/// fail-closed 成 `RootGone`；本轮按控制方裁定只留作后续项，未实现。登记路径的父目录由用户
/// 拥有、在威胁模型之外，是一条可辩护的范围决定，但不得据此声称通道已完全关闭。
struct RootHandle {
    dir: Dir,
    path: PathBuf,
}

/// [`ShareConfinementPort`] 的 cap-std 实现。
///
/// 内部只有一张 `root_id -> RootHandle` 表，无别的状态；克隆出来的实例共享同一张表，
/// 因此可以在装配层按 `Arc` 传递。
///
/// 五个方法走的都是同步 cap-std/`std::fs` 系统调用（Ruling 15）：调用方不得假设它们已被
/// 卸载到阻塞线程池，必要时自行 `spawn_blocking`。
#[derive(Clone, Default)]
pub struct CapStdConfinement {
    roots: Arc<RwLock<HashMap<ShareRootId, RootHandle>>>,
}

impl CapStdConfinement {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 段名字的本层规则。刻意不依赖"调用方已经筛查过整条路径"，也不依赖库在三个平台上
    /// 各自的路径解析行为：`is_well_formed_relative`、`is_windows_reserved_device_name` 与
    /// `is_reserved_trash_component` 都是宿主无关的纯字符串判定（前者经
    /// `normalize_share_component` 折叠大小写与结尾点/空格，因此禁的正是空段、上跳及其
    /// `.. `/`...` 别名写法、`/`、`\`、`:`、控制字符与 Windows 保留设备名；后两者对保留前缀
    /// 与设备名同样先归一化）。三个谓词只有 core 一个来源，本层不再各自裁剪；
    /// 归一化覆盖不到的等价类（NTFS 8.3 短名、locale 大小写折叠、`~` 变体）作为未关闭的
    /// 残留记在 core `is_reserved_trash_component` 的文档里，本层既不重复也不声称已解决。
    ///
    /// 设备名在这里**再判一次**不是冗余：本函数的立场一直是"不信任上游已筛查"（终评
    /// Important 3）。它危险的不是上跳而是命名空间切换——`<root>\CON` 在 Win32 里根本
    /// 不在共享树上。库自己的设备名过滤只作用于库的 open，而本层从不打开末段（见
    /// `check_not_symlink` 的说明），那条过滤在这条路径上一次都不执行，所以 Windows 上
    /// 这道名字检查是唯一的保证。判定与 `is_well_formed_relative` 同源，两处不会给出不同答案。
    fn check_name(name: &str) -> Result<(), ConfineError> {
        if !is_well_formed_relative(name) || is_windows_reserved_device_name(name) {
            return Err(ConfineError::Denied);
        }
        if is_reserved_trash_component(name) {
            return Err(ConfineError::ReservedName);
        }
        Ok(())
    }

    /// 段的符号链接检查。`symlink_metadata` 不跟随链接，因此链接本身会以
    /// `file_type().is_symlink()` 暴露出来（任务 1 实测）。
    ///
    /// 段**不存在**在这里不算失败：末段允许尚未创建（规格 §7 的 `Mkdir`/`StageUpload`
    /// 必须在落位前拿到目标路径），而中间段随后必然在 `open_dir` 上失败并被归类为拒绝。
    /// 这一条对末段尤其关键——本层不打开末段，末段的符号链接检查是本层内"解析结果被送到
    /// 根外"的唯一入口；但它只是解析期的名字判定，管不到调用方随后按 `real_path` 的那次
    /// 环境权限打开（见 `confine` 与本文件顶部的说明：窗口收窄而非闭合）。
    fn check_not_symlink(dir: &Dir, name: &str) -> Result<(), ConfineError> {
        match dir.symlink_metadata(name) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfineError::Denied),
            Ok(_) => Ok(()),
            Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => Err(confine_io_error(source)),
        }
    }

    /// 逐段下行，中间段与末段的名字都从已打开的父目录句柄出发判定，绝不"先校验字符串、
    /// 再按绝对路径重新打开"。这把 TOCTOU 窗口收窄（判定与下行都相对同一个父 `Dir`，
    /// 不给绝对路径留重解析的通道），但**没有闭合**：中间段的 `symlink_metadata` 判定与
    /// 紧随的 `open_dir` 是两次操作，二者之间该段仍可被换成一根指向根内的符号链接，而库
    /// 会跟随它，于是下行落到用户未预期的子树。要真正做到"检查过的对象与使用的对象是同一个
    /// fd"，需要交出对外不透明的句柄并相对它操作——那是 P2 前置项，不在本层。
    ///
    /// 返回 `Ok(())` 即证明：解析这一刻每个中间段都在根内、都不是符号链接且都是可下行的
    /// 目录，末段的名字合法且（若存在）不是符号链接。这足以让本层拼出的 `real_path` 在解析
    /// 时落在根内；随后的使用见本文件顶部与 `ConfinedTarget` 文档的窗口说明。
    fn confine(root: &Dir, client_rel: &str) -> Result<(), ConfineError> {
        let mut names = client_rel.split('/').peekable();
        let mut opened: Option<Dir> = None;

        while let Some(name) = names.next() {
            let parent = match &opened {
                Some(dir) => dir,
                None => root,
            };
            Self::check_name(name)?;
            Self::check_not_symlink(parent, name)?;
            // 还有后续段才需要把它当目录打开；末段只约束到此为止。
            if names.peek().is_some() {
                let descended = parent.open_dir(name).map_err(confine_io_error)?;
                opened = Some(descended);
            }
        }

        Ok(())
    }

    /// 根当前还在不在。句柄化下行在 Linux 上读不到"根已被删除"（老 inode 仍然可达），
    /// 而规格 §6 的 `root_gone` 状态迁移只有这个信号可以驱动，故对登记时定稿的根路径
    /// 做一次存在性检查。它只影响错误分类，不参与包含性判定——包含性由 `confine` 负责。
    ///
    /// 入参是登记时定稿的根路径的**副本**（见 `opened_root`：读锁内只 `try_clone` + clone 路径，
    /// 这次 `is_dir` 及后续所有系统调用都在锁外执行，避免对端触发的慢盘 I/O 占住读锁）。
    fn root_is_live(path: &Path) -> bool {
        path.is_dir()
    }

    /// 取出登记的那一棵根：句柄的独立副本 + 登记时定稿的绝对路径。
    ///
    /// 读锁内只做两件不涉及文件系统的事：`try_clone`（复制的是同一个底层 fd）与 `PathBuf`
    /// 克隆；随即释放守卫。所有同步系统调用（`is_dir`、`symlink_metadata`、`open_dir`）都在
    /// 锁外执行，避免对端触发的慢盘/网络挂载 I/O 占住读锁、把 `unregister_root` 的写锁排在
    /// 后面（Ruling 22）。
    ///
    /// 代价是并发顺序变了：守卫不再贯穿整个行走，于是已经完成这次克隆的解析可能在一个
    /// `unregister_root` 落地之后仍返回 `Ok`——撤销与行走之间不再是串行的。包含性不受影响：
    /// `dir` 与 `path` 都来自同一个受守卫保护的 `RootHandle`，是同一次登记的那一代，交回的
    /// 目标不可能把新登记的路径拼到旧的 fd 上（`dir` 与 `path` 是否指向同一棵树仍受
    /// `RootHandle` 文档记着的那条未闭合项约束，本层不声称这里更强）。
    ///
    /// `resolve` 与 `resolve_root` 共用这一条，于是"根是否登记过"与"`RootGone` 怎么分类"
    /// 在两条入口上不可能漂移。
    fn opened_root(&self, root: ShareRootId) -> Result<(Dir, PathBuf), ConfineError> {
        // 锁中毒的 `PoisonError` 属于 error-handling.md 允许丢弃来源的情形，
        // 拿不到表就一律不解析，绝不降级为全盘可见。
        // discarded-source[lock-poisoned]: `std::sync::PoisonError<Guard>`: the poison error holds the guard and cannot be stored across threads
        let guard = self.roots.read().map_err(|_| ConfineError::Denied)?;
        let handle = guard.get(&root).ok_or(ConfineError::RootGone)?;
        let dir = handle.dir.try_clone().map_err(confine_io_error)?;
        Ok((dir, handle.path.clone()))
    }
}

/// `register_root` 一路（环境权限打开根）上的 errno 归类。
///
/// 根不存在即 `RootGone`（§6：绝不降级为全盘可见）；其余 errno 带来源上抛、同样不注册，
/// 但不谎报成"根被删除"——瞬态失败被标成永久状态是 Ruling 18 刚处理过的同一族错误。
fn root_io_error(source: std::io::Error) -> ConfineError {
    if source.kind() == ErrorKind::NotFound {
        return ConfineError::RootGone;
    }
    ConfineError::Io { source }
}

/// 逐段行走一路的 errno 归类。
///
/// 此处的 `NotFound` 含义是"某个段不存在"，必须与"根不存在"分开：把两者都记成
/// `RootGone` 会让每一条未命中的路径都谎报根被删除，§6 的 `root_gone` 迁移会被误触发。
/// 段缺失、权限被改走、段名与目录形状不符（穿过普通文件、名字超过文件系统上限）
/// 一律归为不透明拒绝；其余 errno 保留来源。
fn confine_io_error(source: std::io::Error) -> ConfineError {
    match source.kind() {
        // `cap-std` 的逃逸拒绝形态（任务 1 实测）。
        ErrorKind::PermissionDenied
        // 段不存在 / 是普通文件 / 名字非法或过长：都不是本层该放行的路径形状。
        | ErrorKind::NotFound
        | ErrorKind::NotADirectory
        | ErrorKind::InvalidFilename => ConfineError::Denied,
        _ => ConfineError::Io { source },
    }
}

#[async_trait]
impl ShareConfinementPort for CapStdConfinement {
    /// 根必须能被成功打开并定稿为绝对路径；打不开即失败且不留下任何注册痕迹，
    /// 绝不降级为全盘可见。
    async fn register_root(&self, root: ShareRootId, path: &Path) -> Result<(), ConfineError> {
        // 先把根路径定稿（这里跟随一次符号链接），再打开句柄。定稿让拼出的 `real_path` 不再
        // 回看原始输入，堵掉"调用方当初传入的路径后来被换成符号链接"这一条通道。
        // 但 `canonicalize` 与紧随的 `open_ambient_dir` 是两次独立的环境权限解析，若这中间
        // `canonical` 被换成符号链接，`path` 与 `dir` 就会指向不同的树——本层不声称这条也堵了
        // （见 `RootHandle` 文档）。彻底的修法是登记时从已打开句柄取 dev/ino 并在 root_is_live
        // 复核、不匹配即 fail-closed，控制方裁定为后续项，本轮未实现。
        let canonical = std::fs::canonicalize(path).map_err(root_io_error)?;
        let dir = Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(root_io_error)?;

        // 丢弃来源是 error-handling.md 列出的允许例外：锁中毒的 `PoisonError` 持有 guard、
        // 不能跨线程保存，也不含可用诊断信息。此处按 fail-closed 归为不透明拒绝。
        // discarded-source[lock-poisoned]: `std::sync::PoisonError<Guard>`: the poison error holds the guard and cannot be stored across threads
        let mut guard = self.roots.write().map_err(|_| ConfineError::Denied)?;
        guard.insert(
            root,
            RootHandle {
                dir,
                path: canonical,
            },
        );
        Ok(())
    }

    /// 撤销注册并释放表里的句柄（`Dir` 被 drop 即 close fd）。此后**在这次写锁之后才开始
    /// 取表**的解析一律 `RootGone`；在那之前已经从守卫里克隆过句柄的那次 `resolve` 仍可能
    /// 返回 `Ok`（`try_clone` 交出的是独立的 fd，不受这里 close 影响；见 `resolve` 的说明——
    /// 它交回的 `dir`/`path` 始终属于同一次登记的那一代，包含性不因这条竞态而受影响）。
    /// 本层的临界区里没有可 panic 的路径，锁中毒实际不可达；万一发生，
    /// 保持原状（继续约束这个根）比"假装已撤销但句柄仍在表里"更安全。
    async fn unregister_root(&self, root: ShareRootId) {
        if let Ok(mut guard) = self.roots.write() {
            guard.remove(&root);
        }
    }

    async fn is_registered(&self, root: ShareRootId) -> bool {
        self.roots
            .read()
            .is_ok_and(|guard| guard.contains_key(&root))
    }

    async fn resolve(
        &self,
        root: ShareRootId,
        client_rel: &str,
    ) -> Result<ConfinedTarget, ConfineError> {
        // 第一道：宿主无关的线文法筛查（Ruling 12）。它挡的是依赖平台路径解析器的写法
        // （`C:foo`、UNC、`\\?\`、ADS、`\` 分隔、上跳及其 `.. `/`...` 别名、绝对路径、
        // 控制字符、Windows 保留设备名），也挡掉空串与纯点段——因此共享根自身
        // **不能**由本方法寻址，它走 `resolve_root`（终评 Important 4）。
        // 三个平台上这里给出同一个答案。
        if !is_well_formed_relative(client_rel) || client_rel.len() > MAX_RELATIVE_BYTES {
            return Err(ConfineError::Denied);
        }
        // 层数上限在触达文件系统之前判定（ADR-034 把"层数上限"列为本层规则）。
        if client_rel.split('/').count() > MAX_COMPONENTS {
            return Err(ConfineError::Denied);
        }

        // 取登记的根：锁内只克隆句柄与路径，之后全部系统调用都在锁外（见 `opened_root`）。
        let (dir, root_path) = self.opened_root(root)?;

        if !Self::root_is_live(&root_path) {
            return Err(ConfineError::RootGone);
        }
        Self::confine(&dir, client_rel)?;

        // confine 已证明解析这一刻每一段都在根内且都不是符号链接，此时拼接才安全。
        // `relative` 用**与 confine 同一份分段**重建，而不是 `Path::new(client_rel)`：
        // 这样它结构上就不可能是绝对路径，也就不存在 `join` 把根整段替换掉的通道
        // （线文法里 `/` 是唯一的分隔符，平台分隔符已在筛查里禁掉）。
        // real_path 只是解析期的快照，不携带句柄，其后的使用见 `ConfinedTarget` 文档。
        let relative: PathBuf = client_rel.split('/').collect();
        Ok(ConfinedTarget {
            root,
            real_path: root_path.join(&relative),
            relative,
        })
    }

    /// 共享根**自身**的解析（终评 Important 4：规格 §7 的 `List { root, rel }` 要列举根的顶层，
    /// 而线文法禁掉了 `""`/`"."` 两种哨兵写法）。
    ///
    /// 这里没有段可走，因此既不需要字面筛查也不需要逐段 `open_dir`；但**根是否登记过**与
    /// **根还在不在**这两条判定与 `resolve` 用的是同一个 `opened_root` + `root_is_live`，
    /// 失败分类（未登记/已撤销 ⇒ `RootGone`，锁不可用 ⇒ `Denied`）因此在两条入口上完全一致。
    /// 刻意不给"把空串当根来传给 `resolve`"留旁路：那要求调用方在内核之前特判空串，
    /// 忘记特判的那一路就把整道筛查绕过去了。
    ///
    /// 交回的 `relative` 为空、`real_path` 就是登记时定稿（`canonicalize`）的根路径本身，
    /// 因此它必然落在登记的树里——这不是新得到的保证，它正是 `register_root` 定稿的那个路径；
    /// `dir` 与 `path` 是否指向同一棵树仍受 `RootHandle` 文档记着的那条未闭合项约束
    /// （`dev`/`ino` 身份复核是 P2 项，本轮未实现）。
    async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
        let (_dir, root_path) = self.opened_root(root)?;
        if !Self::root_is_live(&root_path) {
            return Err(ConfineError::RootGone);
        }
        Ok(ConfinedTarget {
            root,
            real_path: root_path,
            relative: PathBuf::new(),
        })
    }
}
