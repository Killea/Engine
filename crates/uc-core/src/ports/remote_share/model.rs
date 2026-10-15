//! 设备文件共享的领域类型。绝对路径永不出现在协议里（规格 §13 I2）。

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 共享根对外暴露的唯一不透明标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareRootId(pub Uuid);

impl ShareRootId {
    /// The 16 raw bytes for the wire form. Opaque to the peer: it is the holder's
    /// share-root id, not a UUID-shaped value the client is expected to interpret.
    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.0.into_bytes()
    }

    /// Construct from the 16 raw wire bytes.
    #[must_use]
    pub fn from_wire_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

/// 逐根权限（规格 §5.1）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareGrants {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

/// 一次操作所需的权限意图。
///
/// `Write` 与 `Overwrite` 必须分开：规格 §7 里 `Mkdir`/`StageUpload`/`CommitUpload`/
/// `AbortUpload`/`CopyWithin` 只需 `write`，而覆盖已有内容按 §5.2 还需 `delete`。
/// 合并成一个变体会让"可写但未开放删除"的共享根直接无法上传。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareOperation {
    List,
    Read,
    /// 创建新内容（新建目录、上传暂存与落位、设备内拷贝）。
    Write,
    /// 覆盖或移走已存在的内容，按规格 §5.2 需要 write 与 delete 两者。
    Overwrite,
    Rename,
    Delete,
}

/// 单个共享根。`path` 与 `label` 是业务负载，只存在于密文文档内。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRoot {
    pub id: ShareRootId,
    pub path: String,
    pub label: String,
    pub grants: ShareGrants,
    pub enabled: bool,
    pub added_at_ms: i64,
}

/// 手写 `Debug`：规格 §13 I4 与 `AGENTS.md:24` 禁止路径与文件名进入日志，
/// 派生 `Debug` 会把它们原样打出来。与仓库既有的敏感类型脱敏做法一致。
impl fmt::Debug for ShareRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareRoot")
            .field("id", &self.id)
            .field("path", &"[REDACTED]")
            .field("label", &"[REDACTED]")
            .field("grants", &self.grants)
            .field("enabled", &self.enabled)
            .field("added_at_ms", &self.added_at_ms)
            .finish()
    }
}

impl ShareRoot {
    #[must_use]
    pub fn grants_allow(&self, op: ShareOperation) -> bool {
        match op {
            ShareOperation::List | ShareOperation::Read => self.grants.read,
            // 规格 §7：只创建新内容不触碰既有内容，单个 write 授权即足够。
            ShareOperation::Write => self.grants.write,
            // 规格 §5.2：覆盖与重命名同时需要 write 与 delete。
            ShareOperation::Overwrite | ShareOperation::Rename => {
                self.grants.write && self.grants.delete
            }
            ShareOperation::Delete => self.grants.delete,
        }
    }
}

/// 落盘的整份加密文档。只有一个最终 `schema_version`，不留中间布局。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareStoreDoc {
    pub schema_version: u32,
    pub suspended: bool,
    pub roots: Vec<ShareRoot>,
}

/// 手写 `Default`：派生会把 `schema_version` 置 0，而 `new()` 置 1。
/// 两者不一致会让"先 `default()` 再序列化"写出一条版本为 0 的文档。
impl Default for ShareStoreDoc {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareStoreDoc {
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;

    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: Self::CURRENT_SCHEMA_VERSION,
            suspended: false,
            roots: Vec::new(),
        }
    }

    #[must_use]
    pub fn shares_anything(&self) -> bool {
        !self.suspended && self.roots.iter().any(|root| root.enabled)
    }

    #[must_use]
    pub fn find(&self, id: ShareRootId) -> Option<&ShareRoot> {
        self.roots.iter().find(|root| root.id == id)
    }
}

/// 单个路径组件的宿主无关归一化：ASCII 小写 + 去掉组件结尾的 `.` 与空格。
///
/// 这是"这一段究竟指向哪个名字"的唯一来源。Windows 与 macOS 的文件系统大小写不敏感，
/// Windows 还会吃掉段结尾的点与空格，于是 `.Uniclipboard-Trash-<id>.` 与 `.. ` 在别的宿主上
/// 真正指向的分别是小写去点后的回收目录与父目录。保留名判定与上跳筛查都走这一个函数，
/// 本机侧与对端侧不可能各算各的（Ruling 19/20）。
///
/// 折叠的覆盖面就是这两件事，仅此：ASCII 大小写与结尾的 `.`/空格。它**不**覆盖
/// NTFS 的 8.3 短名（`UNICLI~1` 之类——短名既不以 `.` 或空格结尾，也折不出保留前缀，
/// 因此这条归一化在结构上不可能命中那一类）、依赖 locale 的大小写折叠（土耳其语
/// `İ`/`I` 不是 ASCII 折叠能覆盖的），也不处理 `~` 写法本身。也就是说：经它判定为等价的
/// 写法确实等价，但被它放过的写法并不因此就等价。残留的处置见
/// [`is_reserved_trash_component`] 的文档。
///
/// 本函数只回答"它真正叫什么"，是否放行/占用仍由各自的谓词判定。
#[must_use]
pub fn normalize_share_component(name: &str) -> String {
    name.to_ascii_lowercase()
        .trim_end_matches(['.', ' '])
        .to_owned()
}

/// Windows 保留设备名（win32 命名空间，与所在目录无关）。
///
/// 这里只取规范里那份确定的清单：`CON`、`PRN`、`AUX`、`NUL`、`CLOCK$`、
/// `COM1`–`COM9`、`LPT1`–`LPT9`。未纳入的写法（`COM0`/`LPT0`、`CONIN$`/`CONOUT$`/`CONSOLE`
/// 一类未见于规范清单的扩展）本谓词**不**拒绝——不得把它当作 Windows 保留名的完整集合。
const WINDOWS_RESERVED_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "clock$", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// 这一段在 Windows 上是否指向一个**保留设备名**而不是共享树里的文件。
///
/// 判定是宿主无关的纯字符串比较，与 [`normalize_share_component`] 同处 core，因此
/// 筛查层与内核的逐段行走只有这一个答案（ADR-034「决定」第 3、4 条：第二道边界
/// 不得跟着宿主变）。
///
/// 为什么必须在协议层挡下，而不能指望 `cap-std`：库确实在 Windows 上过滤设备名
/// （`cap-primitives` 的 `src/windows/fs/open_impl.rs`，见 ADR-034 机制表），但那道过滤
/// 作用于**库自己的 open**。约束内核把末段当"可能尚未创建的目标"来处理、从不打开它
/// （规格 §7 的 `Mkdir`/`StageUpload` 要求如此），于是 `resolve(root, "CON")` 只返回一个
/// 拼出来的 `real_path = <root>\CON`，库层过滤一次都没执行；调用方随后按环境权限打开这个
/// 字符串时，Win32 的名称解析把 `<root>\CON` 归到**设备命名空间**，读写根本不落进共享树。
/// Windows 上本层又是唯一边界（两平台未实测），所以这一步不能留给库。
///
/// 折叠规则与保留前缀判定共用同一条"这个段究竟指向哪个名字"的定义：先经
/// [`normalize_share_component`]（ASCII 小写 + 去段尾 `.`/空格），再取**第一个 `.` 之前**的部分，
/// 并去掉该部分结尾的空格——Windows 按第一个点切分基础名，`nul.log` 与 `NUL` 撞的是同一个设备。
/// 判定只覆盖这一种切分：它**不**处理前导空格、也不处理点分段的其它平台语义。
///
/// 刻意接受的代价（与线文法禁 `:`/`\` 同一族，已写进规格 §7）：`CON`、`nul` 这类名字在
/// Linux/macOS 上是合法文件，但经本协议**不可访问**；UI 应给出"不可经共享访问"的提示，
/// 而不是静默隐藏。判定只看基础名，因此 `cone.txt`、`nulled`、`com1x`、`lpt10` 照常放行。
#[must_use]
pub fn is_windows_reserved_device_name(name: &str) -> bool {
    let folded = normalize_share_component(name);
    // 第一个 `.` 之前即 Windows 眼里的基础名；`split` 的迭代器至少给出一段。
    let stem = folded
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    WINDOWS_RESERVED_DEVICE_NAMES.contains(&stem)
}

/// 规格 §6.1：`.uniclipboard-staging-<staging_id>` 为上传暂存目录的保留前缀。
///
/// 归一化、等价类残留与"谓词即唯一权威记录"的约定与 [`is_reserved_trash_component`]
/// 完全相同，见该函数文档。
#[must_use]
pub fn is_reserved_staging_component(name: &str) -> bool {
    normalize_share_component(name)
        .strip_prefix(".uniclipboard-staging-")
        .is_some_and(|suffix| !suffix.is_empty())
}

/// 规格 §6.1 的合并谓词：段名是否落入任一内核保留命名空间
/// （回收目录 `.uniclipboard-trash-*` 或上传暂存 `.uniclipboard-staging-*`）。
///
/// 逐段行走、登记扫描与列举过滤都只问这一个问题，保证三条路径给出同一答案。
#[must_use]
pub fn is_reserved_share_component(name: &str) -> bool {
    is_reserved_trash_component(name) || is_reserved_staging_component(name)
}

/// 规格 §6.1：`.uniclipboard-trash-<root_id>` 为保留前缀，用户内容不得占用。
///
/// 判定先经 [`normalize_share_component`] 折叠大小写与结尾点/空格，再比对前缀，
/// 因此"折叠后确实指向同一个回收目录"的那批写法在三个宿主上得到同一个答案
/// （该函数是纯字符串判定，与宿主无关是**按构造**成立的，不是实测出来的）。
///
/// **任务 2 的递延项并没有在此关闭**：递延原文点名大小写、结尾 `.` 与 `~` 变体三类，
/// 本轮只覆盖了前两类。仍未处理的等价类（本段是该残留在代码里的唯一记录，
/// 规格 §6.1 的接受决定与后续改动都以此为据）：
/// - **NTFS 8.3 短名**：`UNICLI~1` 之类短名指向同一个目录，但它既不以 `.`/空格结尾，
///   也折不出 `.uniclipboard-trash-` 前缀，本谓词在结构上不可能命中这一类；
/// - **带 locale 的大小写折叠**：土耳其语 `İ`/`I` 之类的折叠不是 ASCII 折叠；
/// - **`~` 变体**：仍按字面处理，未做拒绝。
///
/// 并且 **Windows 与 macOS 至今一次都没有执行过**，现有语料结论只有 Linux 实测加源码核对。
/// 要彻底封死需要"拒绝任何可能折叠/缩短到该前缀的名字"（偏严，可能挡掉合法用户名）
/// 或由文件系统侧保证不生成 8.3 名。
///
/// 本谓词同时就是 **P5** 启用共享根时那次保留名扫描（规格 §6.1，报 `reserved_name`）所用的
/// 那一个：接这条扫描的人必须知道上面三类残留仍在谓词之外，不得把它当作该风险的完整防线。
/// P1 内没有任何任务做这条扫描（任务 6 是授权判定器、任务 7 是装配接线），本段一度被误写成
/// "任务 6/7"，已按 ADR-034 对齐到 P5；两处不得再各自漂移，以本段为唯一权威记录。
#[must_use]
pub fn is_reserved_trash_component(name: &str) -> bool {
    normalize_share_component(name)
        .strip_prefix(".uniclipboard-trash-")
        .is_some_and(|suffix| !suffix.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(read: bool, write: bool, delete: bool) -> ShareGrants {
        ShareGrants {
            read,
            write,
            delete,
        }
    }

    fn root_with(g: ShareGrants) -> ShareRoot {
        ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: "/tmp/whatever".to_owned(),
            label: "whatever".to_owned(),
            grants: g,
            enabled: true,
            added_at_ms: 0,
        }
    }

    /// 规格 §5.2：重命名同时要求 write 与 delete。穷举 2^3 组合。
    #[test]
    fn rename_requires_write_and_delete() {
        let cases = [
            (false, false, false, false),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (true, true, false, false),
            (true, false, true, false),
            (false, true, true, true),
            (true, true, true, true),
        ];
        for (read, write, delete, expected) in cases {
            let root = root_with(grants(read, write, delete));
            assert_eq!(
                root.grants_allow(ShareOperation::Rename),
                expected,
                "read={read} write={write} delete={delete}"
            );
        }
    }

    /// 规格 §7：`Write` 只需 write，让"可写但未开放删除"的根能正常上传。
    #[test]
    fn write_needs_only_the_write_grant() {
        assert!(root_with(grants(false, true, false)).grants_allow(ShareOperation::Write));
        assert!(root_with(grants(true, true, true)).grants_allow(ShareOperation::Write));
        assert!(!root_with(grants(true, false, true)).grants_allow(ShareOperation::Write));
    }

    /// 规格 §5.2、§8.1：覆盖已有内容额外要求 delete。
    #[test]
    fn overwrite_requires_write_and_delete() {
        assert!(!root_with(grants(true, true, false)).grants_allow(ShareOperation::Overwrite));
        assert!(root_with(grants(true, true, true)).grants_allow(ShareOperation::Overwrite));
    }

    /// 规格 §13 I4 / AGENTS.md:24：派生 Debug 会把绝对路径与 label 打进日志。
    #[test]
    fn debug_redacts_path_and_label() {
        let root = root_with(grants(true, false, false));
        let text = format!("{root:?}");
        assert!(
            !text.contains("/tmp/whatever"),
            "Debug 泄漏了共享根绝对路径"
        );
        assert!(!text.contains("whatever\""), "Debug 泄漏了 label");
        assert!(text.contains("[REDACTED]"));
        // 判定所需的信息仍然可见，脱敏不能把类型变成黑盒。
        assert!(text.contains("id"));
    }

    /// Default 与 new() 必须给出同一个 schema_version，否则会写出版本 0 的文档。
    #[test]
    fn default_and_new_agree_on_schema_version() {
        assert_eq!(
            ShareStoreDoc::default().schema_version,
            ShareStoreDoc::CURRENT_SCHEMA_VERSION
        );
        assert_eq!(ShareStoreDoc::default(), ShareStoreDoc::new());
    }

    #[test]
    fn list_and_read_require_only_read() {
        let root = root_with(grants(true, false, false));
        assert!(root.grants_allow(ShareOperation::List));
        assert!(root.grants_allow(ShareOperation::Read));
        assert!(!root.grants_allow(ShareOperation::Write));
        assert!(!root.grants_allow(ShareOperation::Delete));
    }

    /// 规格 §5.1：总开关语义即"清单为空"。
    #[test]
    fn empty_doc_is_by_definition_disabled() {
        let doc = ShareStoreDoc::default();
        assert!(doc.roots.is_empty());
        assert!(!doc.suspended);
        assert!(!doc.shares_anything());
    }

    #[test]
    fn suspended_or_disabled_shares_nothing() {
        let mut doc = ShareStoreDoc::default();
        doc.roots.push(root_with(grants(true, true, true)));
        assert!(doc.shares_anything());

        doc.suspended = true;
        assert!(!doc.shares_anything());

        doc.suspended = false;
        doc.roots[0].enabled = false;
        assert!(!doc.shares_anything());
    }

    #[test]
    fn find_returns_only_the_requested_root() {
        let mut doc = ShareStoreDoc::default();
        let kept = root_with(grants(true, false, false));
        let other = root_with(grants(true, true, true));
        doc.roots.push(kept.clone());
        doc.roots.push(other.clone());

        assert_eq!(doc.find(other.id), Some(&other));
    }

    /// 规格 §6.1：`.uniclipboard-trash-<id>` 是保留名，裸名不是。
    /// Ruling 19/20：判定经归一化，大小写与结尾点/空格的写法同样命中，
    /// 而"裸前缀不算占用"这条边界不因归一化而漂移。
    #[test]
    fn reserved_trash_prefix_is_detected() {
        assert!(is_reserved_trash_component(".uniclipboard-trash-00000000"));
        assert!(!is_reserved_trash_component(".uniclipboard-trash"));
        assert!(!is_reserved_trash_component(".uniclipboard-trash-"));
        assert!(!is_reserved_trash_component("notes"));
        // 大小写 / 结尾点 / 结尾空格：折叠后撞的是同一个回收目录，必须命中。
        assert!(is_reserved_trash_component(".Uniclipboard-Trash-abc"));
        assert!(is_reserved_trash_component(".UNICLIPBOARD-TRASH-abc"));
        assert!(is_reserved_trash_component(".uniclipboard-trash-abc."));
        assert!(is_reserved_trash_component(".uniclipboard-trash-abc. "));
    }

    /// 终评 Important 3：Windows 保留设备名判定必须是宿主无关的——在 Linux 上就把这批
    /// 写法挡下，这样三平台得到同一个答案，Windows 上无需依赖任何未实测的库行为。
    /// 判定只看第一个 `.` 之前的基础名（`nul.log` 与 `NUL` 撞同一个设备），
    /// 并且复用同一条归一化，因此大小写与结尾 `.`/空格 的写法一并命中。
    #[test]
    fn windows_reserved_device_names_are_detected_on_every_host() {
        for reserved in [
            "CON",
            "con",
            "PRN",
            "prn",
            "AUX",
            "NUL",
            "nul",
            "COM1",
            "com9",
            "LPT1",
            "lpt9",
            "CLOCK$",
            "clock$",
            // 带扩展名：Windows 按第一个点切分基础名，这些同样是设备。
            "nul.log",
            "CON.txt",
            "com1.dat",
            "LPT3.x",
            // 基础名结尾的空格同样被折掉（`COM1 .txt` 的设备部分是 `COM1`）。
            "COM1 .txt",
            // 结尾点/空格经归一化折叠后仍是设备名。
            "CON.",
            "NUL ",
            "PRN. ",
        ] {
            assert!(
                is_windows_reserved_device_name(reserved),
                "保留设备名未命中：{reserved:?}"
            );
        }

        // 本谓词只覆盖规范清单那 23 个名字：裸 `COM` 与 `COM0`/`LPT0` 不在清单里，
        // 因此放行。这条边界（以及它**没有**覆盖什么）记在谓词文档里，不得当成
        // Windows 保留名的完整集合。
        for permitted in [
            "cone.txt",
            "nulled",
            "com1x",
            "lpt10",
            "aux1",
            "a-com1",
            "helper-con",
            "con10",
            "COM",
            "COM0",
            "LPT0",
            "notes.txt",
            "备注 (1).txt",
            "",
            ".",
            "..",
            "CLOCK",
            "CLOCK$X",
        ] {
            assert!(
                !is_windows_reserved_device_name(permitted),
                "普通名字被误判成保留设备名：{permitted:?}"
            );
        }
    }

    /// Ruling 19/20：归一化只折叠大小写与结尾点/空格，不得改动段的其余内容，
    /// 也不得把普通名字的中间点吃掉。
    #[test]
    fn normalize_share_component_folds_case_and_trailing_dots_spaces() {
        assert_eq!(normalize_share_component("Foo.TXT"), "foo.txt");
        assert_eq!(normalize_share_component("a.  "), "a");
        // 纯点/点加空格的段折叠后为空——正是上跳写法被挡下的依据。
        assert_eq!(normalize_share_component(".. "), "");
        assert_eq!(normalize_share_component("."), "");
        assert_eq!(normalize_share_component("..."), "");
        // 中间的点不受影响，只有结尾的点/空格被吃掉。
        assert_eq!(normalize_share_component("a.b.c"), "a.b.c");
    }
}
