//! 用测试固定 `cap-std` 实际提供哪一种包含保证。
//!
//! 规格 §6 要的是 openat2 `RESOLVE_BENEATH` / `O_NOFOLLOW` 那种"绝不离开目录树"，
//! 而不是"路径字符串不逃出"。任何一条逃逸成功都意味着 ADR-034 的选型必须重估，
//! 不得改用更弱的保证来让测试变绿。

use std::fs;
use std::path::Path;
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use tempfile::TempDir;

use uc_core::ports::remote_share::{
    is_well_formed_relative, ConfineError, ShareConfinementPort, ShareRootId,
};
use uc_infra_local::fs::CapStdConfinement;

/// 构造 `<tmp>/root/{public,escape}` 与 `<tmp>/outside/secret.txt`，
/// 其中 `root/escape` 是指向 `../outside` 的符号链接。
///
/// 末尾的对照断言是本 fixture 的关键：它证明这条链接**确实能解析到真实内容**。
/// 没有它，`open("escape/secret.txt")` 返回任何错误（包括链接根本没建成的 ENOENT）
/// 都会被误读成"cap-std 挡住了逃逸"。
fn fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    fs::create_dir_all(dir.path().join("root/public")).expect("root");
    fs::create_dir_all(dir.path().join("outside")).expect("outside");
    fs::write(dir.path().join("outside/secret.txt"), b"top-secret").expect("secret");

    #[cfg(unix)]
    std::os::unix::fs::symlink("../outside", dir.path().join("root/escape")).expect("symlink");
    // 链接目标相对于链接所在目录（root/），故必须是 ..\outside；
    // 链接路径直接 join("root/escape")，不做 ../ 规范化。
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir("..\\outside", dir.path().join("root/escape"))
        .expect("symlink (Windows 需开发者模式或管理员权限)");

    // 正向对照：绕过 cap-std，用环境权限经同一条链接读到内容。
    // 若这一行失败，说明 fixture 自己坏了，后面的"被拒绝"结论全部无效。
    assert_eq!(
        fs::read(dir.path().join("root/escape/secret.txt")).expect("control read"),
        b"top-secret",
        "对照失败：符号链接未解析到真实内容，逃逸探针的结论不可信"
    );

    dir
}

fn open_root(dir: &Path) -> Dir {
    Dir::open_ambient_dir(dir.join("root"), ambient_authority()).expect("open root")
}

#[test]
fn literal_parent_traversal_is_rejected() {
    let tmp = fixture();
    let root = open_root(tmp.path());

    assert!(
        root.open("../outside/secret.txt").is_err(),
        "cap-std 连字面 ../ 都挡不住，选型必须改自研 openat2"
    );
}

#[test]
fn absolute_path_is_rejected() {
    let tmp = fixture();
    let root = open_root(tmp.path());

    assert!(root.open("/etc/passwd").is_err(), "绝对路径必须被拒绝");
}

/// 关键探针。断言必须区分"被 cap-std 主动拒绝"与"链接根本不存在"：
/// 只写 `is_err()` 的话，ENOENT 会以完全相同的方式通过，整条 gate 就是假的。
#[test]
fn symlink_pointing_outside_the_root_is_denied_not_missing() {
    let tmp = fixture();
    let root = open_root(tmp.path());

    let error = root
        .open("escape/secret.txt")
        .expect_err("逃出共享根的符号链接必须被拒绝");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "期望 cap-std 主动拒绝（PermissionDenied），实际是 {error:?}；\
         若为 NotFound 则说明链接没建成或 fixture 坏了，而不是逃逸被挡住"
    );
}

#[test]
fn symlink_itself_is_still_visible_as_a_link() {
    let tmp = fixture();
    let root = open_root(tmp.path());

    let meta = root.symlink_metadata("escape").expect("symlink_metadata");
    assert!(meta.file_type().is_symlink(), "escape 必须被识别为符号链接");
}

// ============================ 任务 5：路径约束内核 ============================
//
// 上面四条是任务 1 的库层闸门；以下各条面向 `CapStdConfinement`，即本功能唯一的
// 信任边界。规格 §6 的逃逸语料必须逐条被拒，且每条都要证明"为正确的理由被拒"。

/// 在任务 1 `fixture()` 的布局之上，补本任务需要的三样东西：一根**根内**目录链接
/// （`link_to_public -> public`）、一根**末段**指向根外的文件链接（`link_secret`）、
/// 以及两个真实目标文件（`public/n.md`、`public/notes.md`）。
/// 任务 1 的四条既有测试只依赖 `fixture()`，故这里新增函数而不是改它。
///
/// 每个新增形状都带正向对照：目标不存在时，"被拒"与"可解析"两种结论都不可信。
fn extended_fixture() -> TempDir {
    let dir = fixture();
    fs::write(dir.path().join("root/public/n.md"), b"note").expect("target file");
    // `legitimate_relative_paths_resolve` 的正向对照：这是一个真实存在的文件，
    // 不是"因为不存在才碰巧解析失败"的反面证据。
    fs::write(dir.path().join("root/public/notes.md"), b"notes").expect("target file");
    #[cfg(unix)]
    std::os::unix::fs::symlink("public", dir.path().join("root/link_to_public")).expect("link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir("public", dir.path().join("root/link_to_public"))
        .expect("link (Windows 需开发者模式或管理员权限)");
    // 正向对照：链接确实可达，否则"被拒"结论同样不可信。
    assert_eq!(
        fs::read(dir.path().join("root/link_to_public/n.md")).expect("control read"),
        b"note",
        "对照失败：根内符号链接未解析到真实内容"
    );

    // 末段是**指向根外**的文件符号链接。内核不把末段当目录打开（规格 §7 的
    // `Mkdir`/`StageUpload` 要求在目标尚不存在时也能解析），所以末段的符号链接检查
    // 是"解析结果被送到根外"的唯一入口，必须挡得住。
    #[cfg(unix)]
    std::os::unix::fs::symlink("../outside/secret.txt", dir.path().join("root/link_secret"))
        .expect("leaf link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(
        "..\\outside\\secret.txt",
        dir.path().join("root/link_secret"),
    )
    .expect("leaf link (Windows 需开发者模式或管理员权限)");
    assert_eq!(
        fs::read(dir.path().join("root/link_secret")).expect("leaf control read"),
        b"top-secret",
        "对照失败：末段符号链接未解析到真实内容"
    );
    dir
}

/// 复用 `extended_fixture()` 的目录布局，并把 `<tmp>/root` 注册为一个共享根。
/// `TempDir` 必须随结构体一起持有，否则目录先被删。
struct Harness {
    _tmp: TempDir,
    confinement: Arc<CapStdConfinement>,
    root_id: ShareRootId,
}

impl Harness {
    async fn new() -> Self {
        let tmp = extended_fixture();
        let confinement = Arc::new(CapStdConfinement::new());
        let root_id = ShareRootId(uuid::Uuid::new_v4());
        confinement
            .register_root(root_id, &tmp.path().join("root"))
            .await
            .expect("register root");
        Self {
            _tmp: tmp,
            confinement,
            root_id,
        }
    }

    /// 临时目录根，供需要移走/删除 `root/` 的用例使用。
    fn tmp(&self) -> &Path {
        self._tmp.path()
    }
}

/// 规格 §6 的逃逸清单，逐条固定。
///
/// 前三条追加项（`link_secret`、`link_to_public/n.md`、`.Uniclipboard-Trash-*`）是任务 5
/// 在 §6 清单之外补的：§6 的清单没有覆盖"末段符号链接"、"根内符号链接"与
/// "保留前缀的大小写/结尾点变体"，而这三条正是本层相对库额外提供的东西。
const ESCAPE_CORPUS: &[&str] = &[
    "../outside/secret.txt",
    "..",
    "./../../outside/secret.txt",
    "public/../../outside/secret.txt",
    "/etc/passwd",
    "escape/secret.txt",                     // 符号链接逃出根
    "escape/../escape/secret.txt",           // 链接链
    "C:foo",                                 // Windows 盘相对
    "\\\\server\\share\\file",               // UNC
    "file:stream",                           // ADS
    "\\\\?\\C:\\Windows",                    // 长路径前缀
    "PUBLIC/../outside/secret.txt",          // 大小写不敏感前缀绕过
    ".uniclipboard-trash-00000000/anything", // 保留前缀
    "",
    "\0",
    "link_secret",                      // 末段是逃出根的符号链接
    "link_to_public/n.md",              // 中间段是根内符号链接
    ".Uniclipboard-Trash-abc/notes.md", // 保留前缀的大小写变体
    // Ruling 19/20：Windows 会吃掉段结尾的点与空格，于是下列写法在 Windows 上是父目录上跳，
    // 而 ADR-034 指定本层是那条平台上唯一的保证。字面筛查此前只比对 `.`/`..`，放行了它们。
    ".. ",   // 结尾空格：Linux 上是字面名，Windows 上是 `..`
    ".../x", // 纯点段：Windows 折叠后为空/非法，不得下行
    ". /x",  // 点+空格段：同上
    // 终评 Important 3：Windows 保留设备名。本层从不打开末段，库层的设备名过滤因此不生效，
    // `resolve(root, "CON")` 会返回 `Ok` 且 `real_path = <root>\CON`——调用方随后的环境权限
    // 打开落到 Win32 命名空间的设备而非共享树。三条断言在**每个宿主**上都把它挡下。
    "CON",
    "nul.log",
    "a/CON/b",
];

/// 语料中**通过**宿主无关字面筛查、必须由逐段行走挡下的条目。
/// 其余条目都由 `is_well_formed_relative` 在第一道就拒绝，到不了内核的行走。
///
/// Ruling 19/20 追加的 `".. "`、`".../x"`、`". /x"` 不在这里：筛查经 `normalize_share_component`
/// 折叠后就把这些上跳段挡在第一道（`is_well_formed_relative` 返回 `false`），因此它们属于
/// 筛查层拒绝，与 `WALK_STAGE_DENIALS` 的归属定义（"通过了筛查、由行走挡下"）相斥。
const WALK_STAGE_DENIALS: &[&str] = &[
    "escape/secret.txt",
    ".uniclipboard-trash-00000000/anything",
    "link_secret",
    "link_to_public/n.md",
    ".Uniclipboard-Trash-abc/notes.md",
];

#[tokio::test]
async fn every_corpus_entry_is_denied() {
    let harness = Harness::new().await;

    for (index, client_rel) in ESCAPE_CORPUS.iter().enumerate() {
        assert!(
            harness
                .confinement
                .resolve(harness.root_id, client_rel)
                .await
                .is_err(),
            "语料条目 #{index} 被放行，约束内核可绕过"
        );
    }
}

/// headline 断言 `is_err()` 单独是不够的：`RootGone`（根句柄没了）与 `Io`（底层 errno）
/// 同样让 `is_err()` 通过，却与本层的判定无关——那样这条语料就是假绿。
/// 于是逐条固定两件事：它由**哪一道**边界挡下，以及错误变体只能是 `Denied`/`ReservedName`。
#[tokio::test]
async fn every_corpus_entry_is_denied_for_the_right_reason() {
    let harness = Harness::new().await;

    for (index, client_rel) in ESCAPE_CORPUS.iter().enumerate() {
        // 分层归属必须可判定：走逐段行走的条目确实通过了字面筛查，其余确实没过。
        // 否则"行走挡下了它"这一结论没有任何证据支撑。
        let screened = is_well_formed_relative(client_rel);
        assert_eq!(
            screened,
            WALK_STAGE_DENIALS.contains(client_rel),
            "语料条目 #{index} 的拒绝层级归属与筛查结果不一致"
        );

        let error = harness
            .confinement
            .resolve(harness.root_id, client_rel)
            .await
            .expect_err("语料条目必须被拒绝");
        // 只取分类名，不打错误本体：`Io` 的来源文本不在本层掌控内。
        let kind: &'static str = match error {
            ConfineError::Denied => "denied",
            ConfineError::ReservedName => "reserved",
            ConfineError::RootGone => "root_gone",
            ConfineError::Io { .. } => "io",
        };
        let expected = if *client_rel == ".uniclipboard-trash-00000000/anything"
            || *client_rel == ".Uniclipboard-Trash-abc/notes.md"
        {
            "reserved"
        } else {
            "denied"
        };
        assert_eq!(kind, expected, "语料条目 #{index} 的拒绝理由不对");
    }
}

/// 规格 §6：拒绝必须不透明，不回显任何路径片段。
#[tokio::test]
async fn denial_messages_never_echo_paths() {
    let harness = Harness::new().await;

    for client_rel in ESCAPE_CORPUS {
        let error = harness
            .confinement
            .resolve(harness.root_id, client_rel)
            .await
            .expect_err("corpus entries must all be denied");
        let text = error.to_string();
        assert!(!text.contains("secret.txt"), "错误回显了文件名");
        assert!(!text.contains("outside"), "错误回显了目录名");
        assert!(!text.contains("Windows"), "错误回显了路径");
    }
}

/// 反向保障：没把合法路径一起锁死。
#[tokio::test]
async fn legitimate_relative_paths_resolve() {
    let harness = Harness::new().await;

    let target = harness
        .confinement
        .resolve(harness.root_id, "public/notes.md")
        .await
        .expect("legitimate path must resolve");
    assert!(target
        .real_path
        .ends_with(std::path::Path::new("public/notes.md")));
    assert_eq!(target.relative, std::path::Path::new("public/notes.md"));
}

/// 末段允许尚不存在（规格 §7 的 `Mkdir`/`StageUpload` 要在落位前拿到目标路径），
/// 但中间段必须真实存在且是一个可下行的目录。
#[tokio::test]
async fn absent_leaf_is_allowed_but_absent_or_non_directory_middle_is_not() {
    let harness = Harness::new().await;

    let target = harness
        .confinement
        .resolve(harness.root_id, "public/new-upload.part")
        .await
        .expect("尚未创建的末段必须可以解析，否则上传无法落位");
    assert!(target
        .real_path
        .ends_with(std::path::Path::new("public/new-upload.part")));

    // 中间段不存在：不得凭空造出一条可写的绝对路径来。
    assert!(matches!(
        harness
            .confinement
            .resolve(harness.root_id, "no-such-dir/x.md")
            .await,
        Err(ConfineError::Denied)
    ));
    // 中间段是普通文件：不得穿过它继续下行。
    assert!(matches!(
        harness
            .confinement
            .resolve(harness.root_id, "public/n.md/x")
            .await,
        Err(ConfineError::Denied)
    ));
    // 一级目录 `public` 本身可解析（它是 `check_not_symlink` 只查名字、不打开末段的正例）。
    // 注意这**不是**共享根自身：`resolve(root, "")` 与 `resolve(root, ".")` 都被字面筛查拒绝
    // （`""` 就在 `ESCAPE_CORPUS` 里），根自身经 `resolve_root` 寻址，见
    // `the_root_itself_is_addressable_and_stays_inside_the_registered_tree`（终评 Important 4）。
    assert!(harness
        .confinement
        .resolve(harness.root_id, "public")
        .await
        .is_ok());
}

/// 终评 Important 4：共享根**自身**必须可寻址。规格 §7 的 `List { root, rel }` 要列举一个根的
/// 顶层，而 §7 的线文法同时禁掉了 `""` 与 `"."` 两种写法——没有入口就表达不出来。
///
/// 选定的形态是端口上的显式 `resolve_root(root)`，**不是**"`rel` 传空串"这类哨兵写法：
/// 哨兵要么要求在调用内核**之前**特判 `rel == ""`（适配器一旦忘了特判就绕过整道筛查），
/// 要么往内核里再塞一条不走筛查与行走的旁路。显式方法在类型上就没有"忘记特判"这一条通道。
#[tokio::test]
async fn the_root_itself_is_addressable_and_stays_inside_the_registered_tree() {
    let harness = Harness::new().await;

    let target = harness
        .confinement
        .resolve_root(harness.root_id)
        .await
        .expect("共享根自身必须可寻址，否则列举顶层无从表达");
    assert_eq!(target.root, harness.root_id);
    // 根没有相对部分：`relative` 必须是空，交回的目标才是登记的那棵树本身。
    assert!(
        target.relative.as_os_str().is_empty(),
        "根目标的 relative 必须为空，实际 {target:?}",
    );

    // 落在**登记的那棵树**里：等于登记时定稿（`canonicalize`）后的 `<tmp>/root`。
    let registered = std::fs::canonicalize(harness.tmp().join("root")).expect("canonical root");
    assert_eq!(
        target.real_path, registered,
        "根目标必须就是登记时定稿的那棵树"
    );
    // 反向对照：这个目录里确实有 `public`，即它就是 `List` 要列举的那一层。
    assert!(std::fs::read_dir(&target.real_path)
        .expect("read root")
        .filter_map(std::result::Result::ok)
        .any(|entry| entry.file_name() == "public"));

    // 与 `resolve` 同一套失败分类：未注册 ⇒ `RootGone`，绝不降级为全盘可见。
    let unregistered = ShareRootId(uuid::Uuid::new_v4());
    assert!(matches!(
        harness.confinement.resolve_root(unregistered).await,
        Err(ConfineError::RootGone)
    ));
    harness.confinement.unregister_root(harness.root_id).await;
    assert!(matches!(
        harness.confinement.resolve_root(harness.root_id).await,
        Err(ConfineError::RootGone)
    ));

    // 根被**显式哨兵写法**寻址仍然是被拒绝的：两条拼不出来的写法不得因为
    // `resolve_root` 的存在而被放开（否则 §7 的文法就出现第二套答案）。
    for sentinel in ["", "."] {
        assert!(
            harness
                .confinement
                .resolve(harness.root_id, sentinel)
                .await
                .is_err(),
            "哨兵写法 {sentinel:?} 必须仍被拒绝"
        );
    }
}

/// 根目录在磁盘上被删除后，`resolve_root` 与 `resolve` 给出同一个 `RootGone`：
/// 状态迁移（规格 §6 的 `root_gone`）只能靠这一条信号驱动，两条入口不得漂移。
#[tokio::test]
async fn deleted_root_is_root_gone_for_root_resolution_too() {
    let harness = Harness::new().await;
    assert!(harness
        .confinement
        .resolve_root(harness.root_id)
        .await
        .is_ok());

    fs::remove_dir_all(harness.tmp().join("root")).expect("remove root dir");

    assert!(matches!(
        harness.confinement.resolve_root(harness.root_id).await,
        Err(ConfineError::RootGone)
    ));
}

/// 规格 §6.1：保留前缀给出可区分的错误，便于本机 UI 提示。
#[tokio::test]
async fn reserved_prefix_is_reported_distinctly() {
    let harness = Harness::new().await;

    let error = harness
        .confinement
        .resolve(harness.root_id, ".uniclipboard-trash-abc/notes.md")
        .await
        .expect_err("reserved prefix must be denied");
    assert!(matches!(error, ConfineError::ReservedName));
}

/// 任务 2 递延项中"大小写 + 结尾 `.`/空格"这两类在 core 收口：保留名谓词经
/// `normalize_share_component` 折叠 ASCII 大小写与结尾的 `.`/空格后再比对前缀，
/// Windows/macOS 的文件系统大小写不敏感、Windows 会吃掉结尾点与空格，于是下列写法撞的都是
/// 同一个回收目录（与 Ruling 12 同一理由：第二道边界不得跟着宿主变）。约束内核直接复用该
/// 谓词，不再在本地另做裁剪。递延项剩下的两类（NTFS 8.3 短名与 `~` 变体）**仍未处理**，
/// 且 Windows/macOS 从未实测，详见 `is_reserved_trash_component` 的文档。
#[tokio::test]
async fn reserved_prefix_variants_are_reported_distinctly() {
    let harness = Harness::new().await;

    for (index, client_rel) in [
        ".Uniclipboard-Trash-abc/notes.md",
        ".UNICLIPBOARD-TRASH-abc/notes.md",
        ".uniclipboard-trash-abc./notes.md",
        ".uniclipboard-trash-abc. /notes.md",
    ]
    .iter()
    .enumerate()
    {
        let error = harness
            .confinement
            .resolve(harness.root_id, client_rel)
            .await
            .expect_err("保留前缀的变体写法同样必须被拒");
        assert!(
            matches!(error, ConfineError::ReservedName),
            "保留前缀变体 #{index} 的拒绝理由不是保留名"
        );
    }

    // 反向保障：裸前缀不是保留名（规格 §6.1 只保留 `.uniclipboard-trash-<id>`），
    // 不得把它连同用户数据一起误挡。这里它因不存在而被拒，但理由必须是 Denied。
    let error = harness
        .confinement
        .resolve(harness.root_id, ".uniclipboard-trash/notes.md")
        .await
        .expect_err("不存在的目录仍须被拒");
    assert!(
        matches!(error, ConfineError::Denied),
        "裸前缀被误判成保留名"
    );
}

/// 任务 1 实测：`cap-std` 会跟随**根内**符号链接（`inside -> public` 成功）。
/// 本层逐段拒绝的全部理由就在这条——一根链接不得把已授权子树外扩。
/// 若删掉 `confinement.rs` 里 `check_not_symlink` 的符号链接分支，这条必须变红。
#[tokio::test]
async fn root_internal_symlink_is_rejected_even_though_the_library_would_follow_it() {
    let harness = Harness::new().await;
    // fixture 里 root/link_to_public -> public，两端都在根内。
    let through = harness
        .confinement
        .resolve(harness.root_id, "link_to_public/n.md")
        .await;
    assert!(
        matches!(through, Err(ConfineError::Denied)),
        "根内符号链接被放行：授权子树可被一根链接外扩，实际结果 {through:?}"
    );
    // 对照：同一目标经真实路径可达，证明被拒的原因是"它是符号链接"。
    assert!(harness
        .confinement
        .resolve(harness.root_id, "public/n.md")
        .await
        .is_ok());
}

/// 本层存在理由的另一半，用可执行的形式钉住：同一条根内链接，裸 `cap-std` 句柄
/// 自己就能跟随并读到内容。若哪天有人以"库已经挡住了"为理由删掉逐段符号链接检查，
/// 这条与上一条一起变红，说明库挡的是"逃出根"，不是"外扩授权子树"。
///
/// 只在 Linux 上断言：这是任务 1 的实测范围，Windows/macOS 未执行（ADR-034 结论表记
/// "跳过"），首跑后据实登记，不得在这里替它们编结论。
#[cfg(target_os = "linux")]
#[test]
fn cap_std_alone_follows_a_root_internal_symlink() {
    let tmp = extended_fixture();
    let root = Dir::open_ambient_dir(tmp.path().join("root"), ambient_authority())
        .expect("open ambient root");

    let through = root.read_to_string("link_to_public/n.md").expect(
        "cap-std 应当跟随根内符号链接（任务 1 实测）；若此处已失败，库行为变了，\
                 必须重跑闸门并更新 ADR-034 的结论表",
    );
    assert_eq!(through, "note");
}

/// 撤销注册之后的**新解析**即 `RootGone`，绝不降级为全盘可见（规格 §6）。
/// 注意本用例撤销的是登记表里的这一项，不是磁盘上的目录；磁盘侧的三种形态只有"删除且不重建"
/// 会报 `RootGone`，见下一条与 ADR-034 的"根生命周期"条目。
#[tokio::test]
async fn unregistered_root_is_root_gone() {
    let harness = Harness::new().await;
    harness.confinement.unregister_root(harness.root_id).await;

    assert!(matches!(
        harness.confinement.resolve(harness.root_id, "public").await,
        Err(ConfineError::RootGone)
    ));
    assert!(!harness.confinement.is_registered(harness.root_id).await);
}

/// 已登记的根目录在磁盘上被**删除**（`remove_dir_all`，且不重建）：解析必须报 `RootGone`，
/// 不得退化成"全都拒绝"以外的形态，更不得降级为全盘可见。§6 的 `root_gone` 状态迁移只能靠
/// 这个信号驱动。**这条断言的范围就到删除为止**：把根改名挪走后在同路径重建、或删除后重建，
/// `is_dir()` 都为真，本层检测不到（ADR-034"根生命周期"条目，修法与 `dev`/`ino` 身份复核同一条）。
#[tokio::test]
async fn root_directory_deleted_while_registered_reports_root_gone() {
    let harness = Harness::new().await;
    // 先证明它是好的，避免"因为一开始就没建起来"而假绿。
    assert!(harness
        .confinement
        .resolve(harness.root_id, "public/n.md")
        .await
        .is_ok());

    fs::remove_dir_all(harness.tmp().join("root")).expect("remove root dir");

    assert!(matches!(
        harness
            .confinement
            .resolve(harness.root_id, "public/n.md")
            .await,
        Err(ConfineError::RootGone)
    ));
    // 根外的内容不受本用例的删除影响，也正因如此它必须仍然进不来。
    assert_eq!(
        fs::read(harness.tmp().join("outside/secret.txt")).expect("outside intact"),
        b"top-secret"
    );
}

/// `register_root` 打不开根即失败，并且**不留半注册状态**：
/// 失败后 `is_registered` 为假、`resolve` 报 `RootGone`（绝不降级为全盘可见）。
#[tokio::test]
async fn register_failure_leaves_no_half_registered_root() {
    let tmp = extended_fixture();
    let confinement = CapStdConfinement::new();
    let missing = ShareRootId(uuid::Uuid::new_v4());

    let error = confinement
        .register_root(missing, &tmp.path().join("does-not-exist"))
        .await
        .expect_err("打不开的根必须注册失败");
    assert!(
        matches!(error, ConfineError::RootGone),
        "根不存在应是 RootGone，实际 {error:?}"
    );
    assert!(!confinement.is_registered(missing).await);
    assert!(matches!(
        confinement.resolve(missing, "public/n.md").await,
        Err(ConfineError::RootGone)
    ));

    // 登记一个真实存在的文件（不是目录）同样不得成功，且不得因此看得见全盘。
    let as_file = ShareRootId(uuid::Uuid::new_v4());
    let file_error = confinement
        .register_root(as_file, &tmp.path().join("root/public/n.md"))
        .await
        .expect_err("普通文件不能当共享根");
    assert!(
        matches!(file_error, ConfineError::Io { .. }),
        "非目录的登记失败要保留底层来源，不得谎报成根被删除，实际 {file_error:?}"
    );
    assert!(!confinement.is_registered(as_file).await);

    // 撤销一个不存在的根不得 panic，也不得影响别的根。
    confinement.unregister_root(as_file).await;
    confinement.unregister_root(missing).await;
}

/// 端口形状本身的可观察行为：登记/撤销与 `is_registered` 一致；同 id 重注册以最后一次为准，
/// 旧路径不再可见；撤销后 `is_registered` 转假，且对同一 `root_id` 的**新解析**不再成功。
///
/// 注意本用例只覆盖"新解析"这一侧——它并不声称、也无法声称"已返回的 `ConfinedTarget` 在
/// 撤销后失效"：`real_path` 只是路径字符串，本层不持有句柄，撤销管不到调用方随后那次环境
/// 权限打开（见 `ConfinedTarget` 文档；对既有目标真正失效需要 P2 的不透明句柄端口）。
#[tokio::test]
async fn registration_lifecycle_is_observable() {
    let tmp = extended_fixture();
    let confinement = CapStdConfinement::new();
    let root_id = ShareRootId(uuid::Uuid::new_v4());

    assert!(!confinement.is_registered(root_id).await);
    confinement
        .register_root(root_id, &tmp.path().join("root"))
        .await
        .expect("register root");
    assert!(confinement.is_registered(root_id).await);
    assert!(confinement.resolve(root_id, "public/n.md").await.is_ok());

    // 同一个 id 换路径重注册：以最后一次登记为准，旧路径不残留。
    let other = extended_fixture();
    confinement
        .register_root(root_id, &other.path().join("outside"))
        .await
        .expect("re-register root");
    let target = confinement
        .resolve(root_id, "secret.txt")
        .await
        .expect("re-registered root");
    assert!(target
        .real_path
        .ends_with(std::path::Path::new("secret.txt")));
    assert!(matches!(
        confinement.resolve(root_id, "public/n.md").await,
        Err(ConfineError::Denied)
    ));

    confinement.unregister_root(root_id).await;
    assert!(!confinement.is_registered(root_id).await);
}
