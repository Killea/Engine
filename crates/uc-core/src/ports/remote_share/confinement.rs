//! 路径约束端口：把对端给出的相对路径关进已授权的共享根。
//!
//! 判定失败一律不透明（规格 §6）：三个纯判定变体（`Denied` / `ReservedName` /
//! `RootGone`）不带任何载荷，`#[error(...)]` 也是无占位符的静态串，因此不可能
//! 回显路径片段。`Io { source }` 是唯一例外——它的显示文本由 `std::io::Error`
//! 自己决定，端口层管不住，所以适配器**不得**构造消息里含路径的 `io::Error`
//! （固定动作文本，或只带 `raw_os_error()` 分类）。同理，`ConfinedTarget` 手写
//! `Debug` 把两条路径都 `[REDACTED]` 掉，防止派生实现把它们打进日志。

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use super::{is_windows_reserved_device_name, normalize_share_component, ShareRootId};

#[derive(Debug, thiserror::Error)]
pub enum ConfineError {
    /// 不透明拒绝：不回显任何路径片段（规格 §6）。
    #[error("path rejected by share confinement")]
    Denied,
    #[error("path resolves to the reserved trash prefix")]
    ReservedName,
    #[error("shared root directory is gone")]
    RootGone,
    #[error("confinement io failure")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

/// 约束成功后的真实目标。
///
/// **它是解析结果的一个快照，不是能力句柄。** `real_path` 是本层按登记时定稿的根路径
/// 拼出的绝对路径：本层把每一段做过名字与符号链接检查，但**从不打开末段**，也不持有它。
/// 随后对它的一切操作都走调用方的环境权限（P2 的 serve 适配器与 P3 的
/// `open`/`read`/`rename`/`delete`；P1 内没有任何调用方），
/// 那是 ADR-034「决定」第 2 条要收敛的两步式，本层把窗口收窄但未闭合。
///
/// 因此：
/// - 一切破坏性或环境权限操作（`Rename`/`Delete`/覆盖写/读写）都**不得**信任一个可能已经
///   过期的 `real_path`；动作前应经端口重新解析（重解析后仍是一次新的环境权限打开，竞态
///   依旧存在，只是窗口更短）。
/// - 撤销根（`unregister_root`）只让**新的解析**失败，不会、也无法让一个已经交出的
///   `ConfinedTarget` 作废——它就是一段字符串，本层无权回收调用方随后的打开。
///
/// 要做到"检查过的对象与使用的对象是同一个 fd"，端口需要交出对外不透明的句柄并提供
/// 相对该句柄的操作；那会重画端口并波及 P2/P3/P4，已由控制方定为 P2 前置项，非本轮范围。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfinedTarget {
    pub root: ShareRootId,
    /// 本机绝对路径。**严禁**进入日志、错误消息或崩溃报告（规格 §13 I4）。
    /// 见类型文档：它不是一把授权句柄，撤销后仍可被环境权限使用。
    pub real_path: PathBuf,
    /// 对端 supplied 的相对路径原文。
    ///
    /// 共享根**自身**（经 [`ShareConfinementPort::resolve_root`] 得到）此处为空，
    /// `real_path` 即登记时定稿的根路径——这是"根目标"的唯一表示方式，
    /// `""`/`"."` 两种写法在 [`is_well_formed_relative`] 里始终是被拒绝的。
    pub relative: PathBuf,
}

/// 手写 `Debug`：派生会把 `real_path` 原样打出，正是 `8ada11ca` 为 `ShareRoot`
/// 堵掉的那类泄漏。`root` 是不透明 UUID，可保留以便关联。
impl core::fmt::Debug for ConfinedTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfinedTarget")
            .field("root", &self.root)
            .field("real_path", &"[REDACTED]")
            .field("relative", &"[REDACTED]")
            .finish()
    }
}

/// 共享根的路径约束，并同时拥有根的生命周期。
///
/// 生命周期方法必须留在端口上：任务 7 注入的是 `Arc<dyn ShareConfinementPort>`，
/// 若 `register_root` 只存在于 infra 的具体类型，装配后就没有授权与撤销的入口，
/// 规格 §6 的 `unavailable` / `root_gone` 迁移也无从驱动。
///
/// 注意本 trait 的方法是 `async`，而预期实现走的是同步 cap-std 系统调用；
/// 调用方不得假设已被卸载到阻塞线程池，必要时自行 `spawn_blocking`。
///
/// 本 trait 所有方法一律**按值**收 `ShareRootId`（它是 `Copy`）：形状保持一致，调用方不必在
/// 借用与复制之间按方法区分。这条统一在端口成型时只改了 `resolve` 一侧，
/// 现由终评收尾补齐（原计划在任务 5 完成，任务 5 按当时已提交的签名实现了）。
#[async_trait]
pub trait ShareConfinementPort: Send + Sync {
    /// 注册一个共享根。打开失败即 `RootGone`，绝不降级为全盘可见。
    async fn register_root(&self, root: ShareRootId, path: &Path) -> Result<(), ConfineError>;
    /// 撤销注册并释放根句柄。此后对同一 `root_id` 的**新解析**一律 `RootGone`。
    ///
    /// 本层能声称的就是这一条：撤销让"再拿一个新的 `ConfinedTarget`"失败。它**不**能
    /// 让此前已经交出的 `ConfinedTarget::real_path` 作废——那只是一个路径字符串，调用方
    /// 随后按环境权限的打开不受本层约束（见 [`ConfinedTarget`] 的文档）。
    async fn unregister_root(&self, root: ShareRootId);
    #[must_use]
    async fn is_registered(&self, root: ShareRootId) -> bool;
    /// 把对端 supplied 的相对路径关进已授权的共享根，返回一个 [`ConfinedTarget`] 快照。
    ///
    /// 约束的是**解析**，不是调用方随后那次环境权限打开：返回的 `real_path` 不携带句柄，
    /// 撤销根也不会让它失效。破坏性/读写操作不得信任一个可能已过期的 `real_path`，
    /// 动作前应重新解析；"检查与使用同一个对象"所需的对外不透明句柄是 P2 前置项。
    ///
    /// `client_rel` 必须是符合线文法（见 [`is_well_formed_relative`]）的**非空**相对路径：
    /// `""` 与 `"."` 一律 `Denied`，共享根**自身**经 [`Self::resolve_root`] 寻址。
    /// 这条不是风格问题——在适配器里特判 `rel == ""` 再调用本方法，等于把整道筛查绕过去。
    ///
    /// **本方法不构成授权（终评 Important 2 登记的义务）。** 它只看登记表：一个在清单里被
    /// 禁用、被删除、或整机暂停（`suspended`）的根，只要还留在登记表里，`resolve` 一律返回
    /// `Ok`。于是"放行一次操作"必须是**两个**事实的合取——`SharedRootStorePort` 侧的授权判定
    /// 与这里的路径约束，缺任何一个都不构成许可。判定的那一半（`ShareAuthorizer::authorize`，
    /// `uc-application/src/remote_share/authorizer.rs`）从不碰文件系统，本方法也从不读清单，
    /// 所以这条合取**没有任何一层能自己保证**：它由 P2 的 serve 适配器负责，顺序必须是先
    /// `authorize` 再 `resolve`，且两者都成功才动手（规格 §5.2 的第 1–6 步本就是这条合取的顺序
    /// 陈述，本端口只覆盖它的第 6 步"路径经 §6 约束成功"）。把 `Ok(resolve)` 当成许可的适配器
    /// 等于把隐私边界换成"这个根有没有被 `register_root` 过"。
    ///
    /// **登记表与清单的一致性不由本端口负责，也不由任何读侧兜住。** 本端口只维护
    /// `root_id -> 句柄`，它无从知道清单里那个根是否已被禁用或删除；反过来，
    /// `SharedRootStorePort::save` 也不会来动这张表。因此**改写清单的那个人**必须在**同一个
    /// 事务**里配套调用 `register_root` / `unregister_root`：新增并启用一个根⇒登记，禁用、
    /// 删除或整体覆盖清单⇒撤销不再受支持的根。任何一侧漏掉都留下一个"清单说不共享、登记表
    /// 说可以解析"的根——上面那条合取正是这种情况唯一还站得住的防线，所以写清单的那条路径
    /// （P5 的 `PUT /remote-share/roots`）必须把撤销做成同事务的收尾，而不是稍后的清理。
    async fn resolve(
        &self,
        root: ShareRootId,
        client_rel: &str,
    ) -> Result<ConfinedTarget, ConfineError>;
    /// 解析共享根**自身**，返回一个 `relative` 为空、`real_path` 即登记时定稿的根路径的
    /// [`ConfinedTarget`]。
    ///
    /// 为什么是端口上的一个显式方法，而不是"`rel` 传空串/`.`"这类哨兵写法（终评 Important 4）：
    /// 规格 §7 的线文法同时禁掉了这两种写法（空串被 `is_well_formed_relative` 拒绝，`.` 折叠后
    /// 为空），于是 `List { root, rel }` 列举根的顶层在哨兵方案下**表达不出来**；而要让空串走通，
    /// 只能在适配器里于调用内核**之前**特判，或往内核里塞一条不经筛查与行走的旁路——两者都是
    /// P2 最可能在工期压力下写出 bypass 的那一处。显式方法在类型上没有"忘记特判"这条通道，
    /// 根自身因此始终与其余路径走同一套登记查找、同一个 `RootGone` 分类。
    ///
    /// 保证强度与 [`Self::resolve`] 完全一致，不多也不少：它同样交回一个解析期快照，
    /// 末段（这里就是根本身）的后续使用仍走调用方的环境权限，同样不在本层保证之内。
    /// [`Self::resolve`] 上那两条义务（**不构成授权**、登记表与清单的一致性由写清单的一方负责）
    /// 对本方法同样成立，不得因为它只交出根目录就当成"已经许可了一次 `List`"。
    async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError>;
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
/// 设备名过滤只作用于库的 open，而内核从不打开末段，那条过滤在本路径上一次都不会执行；
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

    /// 派生 Debug 会把本机绝对路径打出来，必须被手写实现替掉。
    #[test]
    fn confined_target_debug_never_prints_paths() {
        let target = ConfinedTarget {
            root: ShareRootId(uuid::Uuid::new_v4()),
            real_path: PathBuf::from("/home/hank/Must-Never-Leak"),
            relative: PathBuf::from("Must-Never-Leak-Relative"),
        };
        let text = format!("{target:?}");
        assert!(!text.contains("Must-Never-Leak"), "Debug 泄漏了路径");
        assert!(text.contains("[REDACTED]"));
    }
}
