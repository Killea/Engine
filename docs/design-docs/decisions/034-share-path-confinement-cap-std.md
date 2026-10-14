# ADR-034：共享根路径约束以 cap-std 为原语

- **状态**：已采纳（Linux 实测已完成；**Windows 与 macOS 从未在任何真机上执行过**，见“未验证项”，
  两列一律记“跳过”。本文件一切跨平台结论都是 **Linux 实测 + 源码核对**的外推，不是三平台证据）
- **日期**：2026-10-12（任务 8 最终校对：内核已落地，原“决定”第 2 条的 TOCTOU 表述**据代码推翻**，
  并补记线文法、归一化残留类与 P2 前置条件；fix round 1 又据代码推翻选项 A 的“句柄即权限 ⇒
  根被移走/替换直接失败”，补记根生命周期的三种形态与保留名扫描的相位归属。
  **P1 终评收尾再改五处**：线文法补入 Windows 保留设备名（`is_windows_reserved_device_name`，
  与“库自己过滤设备名”不是一回事，因为本层不打开末段）；共享根自身改由端口上的显式 `resolve_root`
  寻址；撤回两处“`RootGone` 只有一个否定来源”的说法（实际三条，且不区分“目录消失”与“从未登记”）；
  把“根被挪走本层检测不到”收窄为“同路径重建的两种形态检测不到，单纯改名挪走**会**被 `is_dir()` 检出”；
  「后果」补记本层**不构成授权**这条义务（`authorize` 与 `resolve` 的合取、清单与登记表的同事务
  一致性都归 P2 的 serve 适配器与写清单的一方））
- **范围**：设备文件共享的路径约束内核（任务 5 的 `crates/uc-infra-local/src/fs/share_confinement.rs`）
  所依赖的包含原语选型；只回答“对端可控的相对路径如何被限制在用户授权的目录树内”，
  不涉及授权矩阵（任务 6）、持久化格式（任务 4，其密钥来源见
  [ADR-035](035-share-store-space-subkey.md)）与任何传输协议
- **相关文件**：[`share_confinement_escape_probe.rs`](../../../crates/uc-infra-local/tests/share_confinement_escape_probe.rs)（本决定的实测闸门与逃逸语料）、
  [`crates/uc-infra-local/Cargo.toml`](../../../crates/uc-infra-local/Cargo.toml)（`cap-std = "4.0.3"`）、
  [`uc-infra-local/src/fs/share_confinement.rs`](../../../crates/uc-infra-local/src/fs/share_confinement.rs)（约束内核实现）、
  [`uc-core/src/ports/remote_share/confinement.rs`](../../../crates/uc-core/src/ports/remote_share/confinement.rs)（端口与线文法筛查）、
  产品仓规格 `docs/specs/2026-10-12-device-file-share-spec.md` §6 与 §18（该条在产品仓编号 ADR-013，
  在本仓按顺序落为 034）

## 背景

设备文件共享允许对端以 `root_id` + 相对路径寻址本机某个被授权的目录。协议上不存在绝对路径字段，
因此唯一的信任边界是服务端把相对路径解析为本机路径的那一步：解析必须**无法逃出被授权的目录树**。

规格 §6 要求的是 `openat2(RESOLVE_BENEATH)` / `O_NOFOLLOW` 那一档强度（“绝不离开目录树”），
而不是“路径字符串不逃出”（挡住字面 `../` 与绝对路径，但跟随指向根外的符号链接）。两者的差别
正是符号链接：逃逸清单里的 `escape/secret.txt`（`root/escape -> ../outside`）在第一档下会被放行。

计划选择了 `cap-std`，但选型依据只来自文档与规格 §6 的书面核对（“`Dir` 拒绝字面逃逸、`read_link`
拒绝绝对链接目标”），**符号链接能否被跟随到根外从未实测**。在这个事实确定之前写约束内核，
等于把安全边界建在假设上：若库只给路径字符串包含，内核必须自己逐段加严；若库已给目录树包含，
内核的加严就只是纵深。因此本任务先做测量闸门，再据此定任务 5 的实现幅度。

## 实测结论

### 结论表（Linux 为实测；Windows/macOS 未执行，一律记“跳过”）

- 实测环境：Linux（内核 `7.0.0-38-generic`，支持 `openat2`）、rustc 1.95.0、`cap-std`/`cap-primitives` 4.0.3
- 复现命令：`cargo test -p uc-infra --test share_confinement_escape_probe`
- 拒绝的统一形态：`io::ErrorKind::PermissionDenied`，消息 `a path led outside of the filesystem`
  （`cap-primitives` 的 `errors::escape_attempt()`，非 `ENOENT`）

| 场景（相对 `Dir::open_ambient_dir(root)`） | Linux（实测 2026-10-12） | Windows | macOS |
| --- | --- | --- | --- |
| 前置校验：ambient `fs::read("root/escape/secret.txt")`（正向对照） | 读到 `top-secret`（链接是活的，拒绝不是假阳性） | 跳过（未执行） | 跳过（未执行） |
| `open("../outside/secret.txt")` 字面 `..` | 拒绝 | 跳过 | 跳过 |
| `open("/etc/passwd")` 绝对路径 | 拒绝 | 跳过 | 跳过 |
| `open("escape/secret.txt")`（`escape -> ../outside`，**关键一条**） | **拒绝**（`PermissionDenied`） | 跳过 | 跳过 |
| `open("escape/../escape/secret.txt")` 链接链 | 拒绝 | 跳过 | 跳过 |
| `open("link_secret")`（尾段是逃出根的**文件**软链） | 拒绝 | 跳过 | 跳过 |
| `open("abs/secret.txt")`（软链目标为**绝对路径**） | 拒绝 | 跳过 | 跳过 |
| `open_dir("escape")` | 拒绝 | 跳过 | 跳过 |
| `metadata("escape")`（跟随式 stat） | 拒绝 | 跳过 | 跳过 |
| `symlink_metadata("escape")`（不跟随） | `Ok`，`file_type().is_symlink() == true` | 跳过 | 跳过 |
| `read_link("escape")`（相对目标） | `Ok("../outside")`，只返回目标字符串、不解析到根外 | 跳过 | 跳过 |
| `read_link("abs")`（绝对目标） | 拒绝 | 跳过 | 跳过 |
| `entries()` 目录枚举 | 软链以自身名字出现，不被展开 | 跳过 | 跳过 |
| `open("inside/notes.md")`（`inside -> public`，**根内**软链） | **跟随成功** | 跳过 | 跳过 |
| `open("public/notes.md")`（无软链的正常路径，反向对照） | 放行 | 跳过 | 跳过 |

表中 `open("escape/secret.txt")`、字面 `../`、绝对路径、`symlink_metadata("escape")` 四条已固化为
仓库测试。关键探针 `symlink_pointing_outside_the_root_is_denied_not_missing` 断言的是
`io::ErrorKind::PermissionDenied`，不是笼统的 `is_err()`——这样悬空链接的 `ENOENT` 无法让闸门假通过。
第一行的正向对照也已固化进 `fixture()`：每次建链后用 ambient `std::fs::read` 经同一条链接读回
`top-secret`，断言失败即 panic，因此**只要四条测试能跑到断言，就已证明链接是活的、拒绝是主动的**。
这条对照写在没有 `cfg` 门控的公共代码里，在本文件编译到的每个平台（Linux、macOS、Windows）上都会执行；
Windows/macOS 列仍记“跳过”，是指尚未在真机上**运行过**这四条测试，而不是指对照缺失。
表中其余行当初由一次性诊断程序采集（`cargo test ... -- --nocapture` 打印错误形态）。任务 5 已把**面向本层**
的结论固化为 committed 断言，但证据强度是分级的，不得笼统自称“全部已固定”：

- **面向本层（`CapStdConfinement`）**：`ESCAPE_CORPUS` 的 24 条逐条被拒
  （`every_corpus_entry_is_denied`），且每条还固定“由哪一道边界挡下”与“错误变体只能是
  `Denied`/`ReservedName`”（`every_corpus_entry_is_denied_for_the_right_reason` 配合
  `WALK_STAGE_DENIALS` 的分层归属断言）。`RootGone` 或 `Io` 冒充“被挡住”这类假绿由这条排除。
- **本层相对库多出来的那一条前提**（“库会跟随**根内**软链”）现在有两条 committed 断言：
  `root_internal_symlink_is_rejected_even_though_the_library_would_follow_it`（本层拒绝）与
  `cap_std_alone_follows_a_root_internal_symlink`（裸库确实跟随；`#[cfg(target_os = "linux")]` 门控，
  因为它断言的是任务 1 的 Linux 实测范围）。这条是“逐段拒绝不得被删掉”的可执行证据；
  任务 1 阶段它只有一次性测量与散文记录。
- **仍是单次测量、树内无可复现断言的**：`read_link("abs")` 的拒绝、`entries()` 不展开软链、
  `metadata("escape")` 的跟随式 stat 拒绝、`open("escape/../escape/secret.txt")` 链接链，
  以及本文件顶部那句**关于整张表**的“拒绝形态统一为 `PermissionDenied` +
  `a path led outside of the filesystem`”——committed 测试只断言了关键一条的 `kind()`，
  消息文本无人断言。升级 `cap-std` 时这些是最先需要重跑的部分。

### 结论

1. **Linux 上 `cap-std` 给的是目录树包含，不只是路径字符串包含。** 指向根外的符号链接一律被拒绝，
   与 `openat2(RESOLVE_BENEATH)` 的语义一致。规格 §6 里“库会解析并跟随指向根外的符号链接”的书面
   假设**不成立**，以本表为准。
2. **库层不拒绝根内的合法软链**（`inside -> public` 被跟随）。这是能力模型下的正常语义，
   对本功能却是一条真实的策略差：见“决定”第 2 条。
3. 该结论只对 Linux、且只在支持 `openat2` 的内核上取得。Windows 与 macOS 的行为**未实测**，
   不得当作已保证。

## 决定

1. **选型采用 `cap-std`（能力式目录句柄），不改自研，也不退回纯字符串校验。** 共享根在启用时
   `Dir::open_ambient_dir` 一次并持有 fd，此后所有对端可控路径只从该 `Dir` 出发解析；`uc-infra`
   为约束内核新增 `cap-std = "4.0.3"`。
2. **内核层仍在库之上逐段加严，且这不是重复劳动。** 任务 5 的 `CapStdConfinement` 保留以下库层
   不提供或提供得不完整的行为：
   - **拒绝任何软链中间段**（含根内软链）。库层跟随根内软链，而共享授权是按 `root_id` + 相对路径
     给出的；跟随软链会把“对 `public/` 的授权”实际扩大成“对软链所指子树的授权”，读、改名、删除
     都会落到用户未预期的位置。本功能的策略是**软链一律不可穿越**，比库更严。
     该差异必须在内核注释与本 ADR 中同时留痕，防止后来者以“库已经挡了”为理由把逐段检查删掉。
   - **Windows/macOS 的纵深**：两平台未实测，逐段 `symlink_metadata` 拒绝与 `is_well_formed_relative`
     字符串预检构成独立于库实现行为的第二道边界；首次真机跑通语料前，不得据 Linux 结论放松。
   - **库自身语义之外的规则**：保留前缀 `.uniclipboard-trash-*`（规格 §6.1）、NUL/控制字符/超长、
     层数上限、根缺失时的 `RootGone`（绝不降级为全盘可见——它的信号来源与检测不到的那两种形态
     见“`real_path` 是快照，不是能力”一节的根生命周期条目）、不透明错误（不回显任何路径片段）。
   - **TOCTOU：窗口变窄，不是关闭。**（任务 8 校正：本节原先写“检查的对象”和“使用的对象”始终是
     同一个，**该说法已被落地代码正面推翻**，以代码与 `ConfinedTarget` 文档为准。）实现的实际形态是：
     中间段先由父 `Dir` 做一次 `symlink_metadata` **名字判定**，紧接着再对同一个名字调 `open_dir`
     **重开一次**——这是两次操作，二者之间该段仍可被换成一根指向根内的符号链接，而库会跟随它，
     于是下行落到用户没预期的子树。末段更根本不打开：本层查过它的名字与符号链接就交回绝对路径
     `real_path`，随后的 `open`/`read`/`rename`/`delete` 走调用方的环境权限，正是本节要收敛的两步式。
     因此本层诚实可声称的只有：相比“先校验字符串、再按绝对路径重新打开”，判定与下行都相对同一个
     父句柄出发，不给绝对路径重解析的通道，**窗口更短且包含性在解析那一刻成立**；随后的使用不在
     保证之内。要做到“检查过的对象与使用的对象是同一个 fd”，需要端口交出不透明句柄并提供相对该
     句柄的操作——那是 P2 的前置决定，见“`real_path` 是快照，不是能力”。
3. **协议相对路径的字面线文法（本层的第一道边界，宿主无关）。** 相对路径定义为 `/` 分隔的一段段名字，
   任何一段在经 `normalize_share_component` 折叠 ASCII 大小写与结尾 `.`/空格 后**为空**即拒绝，并且禁止
   空段、`.`、`..`、前导 `/`、反斜杠 `\`、冒号 `:`、Windows 保留设备名（`CON`/`PRN`/`AUX`/`NUL`/
   `CLOCK$`/`COM1`–`COM9`/`LPT1`–`LPT9`，由 `is_windows_reserved_device_name` 判定：先走同一条归一化，
   再取**第一个 `.` 之前的基础名**比对，故 `nul.log`、`COM1 .txt` 一并禁止）与任何控制字符（含 NUL）——由
   `is_well_formed_relative` 单独判定，实现是纯字符串比较。之所以定死成 POSIX 风格而不是跟着宿主的
   `Path` 解析器走，正是上面那条纵深决定的必然结果：Windows/macOS 未实测，本层作为这些平台上的
   第二道边界时必须给出三平台同一个答案。
   - 这条筛查在评审前只比对字面 `.`/`..`，于是 `".. "`、`".../x"`、`". /x"` 同时穿过筛查与段名检查：
     Linux 上 `resolve(root, ".. ")` 返回 `Ok`，Windows 上它却是父目录上跳，而 Windows 恰是本层兜底的
     平台。**RED 证据**：修复前 `resolve(".. ")` 得到 `Ok(ConfinedTarget)`。现由
     `host_independent_screen_rejects_windows_spellings` 与语料里的这三条共同固定。
   - 设备名这一条是终评收尾补的（同一族缺陷、不同的失效机制）：筛查与内核的段名检查都不看设备名，
     于是 `resolve(root, "CON")` 返回 `Ok` 且 `real_path = <root>\CON`。本 ADR 的机制表写着
     `cap-primitives` 在 Windows 上“先屏蔽 `CON`/`PRN`/`AUX`/`NUL`/`COMn`/`LPTn` 等设备名，再
     `manually::open`”（见下面机制表那一行），**那道过滤只作用于库自己的 open**，
     而本层从不打开末段（规格 §7 的 `Mkdir`/`StageUpload` 要求目标尚不存在时也能解析），所以那条过滤
     在这条路径上一次都不执行；调用方随后按环境权限打开那个字符串时，Win32 名称解析把它归到**设备
     命名空间**，共享树整个被绕过——危险的不是上跳而是命名空间切换。**RED 证据**：修复前
     `resolve(root, "CON")` 得到 `Ok`（新增三条语料里的第一条，即现语料第 22 条；修复前语料只有
     21 条，其中不含设备名）。现由
     `windows_reserved_device_names_are_detected_on_every_host`、`host_independent_screen_rejects_windows_spellings`
     与语料里的 `"CON"`、`"nul.log"`、`"a/CON/b"` 共同固定，判定本身在 core 只有一个来源。
     谓词只覆盖规范清单那 23 个名字：`COM0`/`LPT0`、`CONIN$` 一类未见于规范清单的写法**未**拒绝。
   - 刻意接受的代价：Linux/macOS 上合法的含冒号文件名（`notes:backup.txt`）、纯点/纯空格段名，
     以及 `CON`/`nul`/`COM1` 这类只在 Windows 上保留的名字，**不可经协议访问**；产品仓规格 §7 已把
     这条文法与其代价写入（任务 8 同步补入“纯点/纯空格段亦禁止”，终评收尾补入保留设备名，
     使规格不弱于实现）。UI 侧应给出“不可经共享访问”的提示，而不是静默隐藏。
   - 筛查**不是**包含性边界本身，它只保证一批依赖平台解析器的写法在任何平台都进不去；真正的逃出由
     逐段行走与库层拒绝负责。
4. **保留名判定共用一条归一化，但归一化堵不完。** `is_reserved_trash_component` 与上跳判定共用
   `normalize_share_component`（ASCII 小写 + 去段尾 `.`/空格），于是本机侧与对端侧不可能各算各的答案。
   它**结构上覆盖不到**的等价类见“归一化覆盖不到的残留类”一节，那些仍是开放项。
5. **本 ADR 的结论表是后续平台验证的登记处。** Windows/macOS 首次真机执行 `share_confinement_escape_probe`
   后，把“跳过”替换为实测结果；若与 Linux 不一致（尤其“关键一条”在某一平台被跟随），内核的逐段加严
   从纵深升格为唯一保证，需在本文补记并考虑把语料固化为跨平台 CI 作业。

## `real_path` 是快照，不是能力（P2 前置条件）

任务 5 的评审裁定把这条定为 **P2 开工前必须解决的设计决定**，理由是它是端口形状的，
不是某行代码的：

- `ConfinedTarget.real_path` 是一个 `PathBuf`。它是本层在**解析那一刻**用登记时定稿的根路径拼出来的
  字符串快照；本层从不打开末段，也不持有它。调用方（P2 的 serve 适配器、P3 的破坏性操作）随后是
  拿着这个字符串按**环境权限**重新打开——本 ADR“决定”第 2 条要收敛、并在选项 C 里被判为失格形态的
  正是这个两步式。
- 直接后果是一条**无法满足的契约**：端口原先声称“撤销根之后，对既有 `ConfinedTarget` 的使用必须失败”。
  拿着一个字符串，本层无权回收调用方随后的打开，这条声称兑现不了。当前文本已改成可兑现的措辞：
  撤销只让**新的解析**失败（`unregister_root` 与 `resolve` 的文档、
  `registration_lifecycle_is_observable` 的注释都按此写，不再声称覆盖既有目标）。
- 因此：**在 `real_path` 上直接建任何破坏性操作（`Rename`/`Delete`/覆盖写）之前，必须先定稿不透明句柄
  重画**——端口交出一个对外不透明的目标句柄，并提供相对该句柄（相对已保留的 `Dir`）操作的方法，
  使“检查过的对象”与“被改的对象”在类型上就是同一个 fd。这条决定会重画 `ShareConfinementPort`，
  并波及 P2/P3/P4 的全部设计，所以它必须是 P2 的第一个决定，不能边写边补。
- 同一条重画也顺带解决末段：末段目前只有解析期的名字判定这一处入口。
- **共享根自身经端口上的显式 `resolve_root(root)` 寻址**（终评 Important 4 收尾定稿）。
  它不是“能力”，只是把这条快照语义往前挪了一格，因此没有新的保证需要软化：
  `resolve_root` 交回的 `real_path` 就是登记时定稿的根路径、`relative` 为空，
  与 `resolve` 共用 `opened_root`（同一套登记查找与 `RootGone` 分类）和 `root_is_live`，
  随后的列举/打开仍走调用方的环境权限。为什么不做成“`rel` 传空串”的哨兵：那要求适配层在
  进入内核**之前**特判，而特判一旦漏掉，整道筛查与逐段行走就被一起绕过——这是一条比
  “窗口收窄未闭合”更危险的形状。P2 的重画必须让 `resolve_root` 与 `resolve` 一起换成
  不透明句柄（`List` 的根层列举是它第一个真实消费者），并同样补上“根自身可解析且落在登记的树里”
  这条 committed 断言（现为 `the_root_itself_is_addressable_and_stays_inside_the_registered_tree`
  与 `deleted_root_is_root_gone_for_root_resolution_too`）。

登记与根生命周期另有四条已软化、已订正而尚未闭合的保证，P2 前不得重新升格为“已保证”：

- `std::fs::canonicalize(path)` 与紧随其后的 `Dir::open_ambient_dir(&canonical)` 是**两次独立的环境权限
  解析**：若这中间 `canonical` 被换成符号链接，`RootHandle.path`（进而每个 `real_path`）与 `dir`
  约束的树就不是同一棵。彻底修法是从已打开的句柄取 `dev`/`ino`（Windows 取 file index）并在
  `root_is_live` 复核，不匹配即 fail-closed 成 `RootGone`；本轮按裁定只留后续项，**未实现**。
  当前论证是“登记路径的父目录由用户拥有、在威胁模型之外”，这是一条范围决定，不是通道已关闭。
- 读锁内只 `try_clone()` + 克隆 `PathBuf` 后即释放守卫（避免对端触发的慢盘/网络挂载 I/O 占住读锁、
  把撤销的写锁排在后面；任务 5 的同一轮评审裁定）。代价是并发顺序变了：已经克隆过句柄的那次
  `resolve` 可能在 `unregister_root` 落地之后仍返回 `Ok`。包含性不受影响
  （`dir` 与 `path` 来自同一次登记的那一代），但“撤销与行走串行”这句不能讲。
- **根生命周期（fix round 1 新增；终评收尾订正了两处过泛的说法）**：根在登记之后**被改名挪走或在同一路径重建**——只要那个路径上仍然有一个目录——本层**检测不到**。
  原先这里写作“被挪走或在同一路径重建，本层检测不到”，**那是过泛的**：单纯 `rename` 把根挪走、
  不在原路径重建时，定稿路径上的 `is_dir()` 变假，这一条**是**会被检测到的（报 `RootGone`），
  与“删除且不重建”同一条通道。真正检测不到的是“同路径上又有一个目录”那两种形态。
  同时原先“`RootGone` **只有一个**否定来源”也是错的，见下一条。三种形态按本轮复核分别是：
  - 根被删除且不重建 → `is_dir()` 为假 → `RootGone`。这是**唯一**有 committed 断言的形态
    （`root_directory_deleted_while_registered_reports_root_gone`）。
  - 根被改名挪走、同路径重建（replant）→ `is_dir()` 为真，逐段行走跑在旧 fd 那棵**仍然完整**的树
    上并通过，`real_path` 却拼在那个路径上，于是交回一棵从未被本层验证过的树里的对象。
    本轮一次性探针（Linux，树内无 committed 断言）：新树里把末段名写成指向根外的符号链接，
    `resolve` 仍返回 `Ok`，调用方随后的环境权限读取直接拿到根外内容。
  - 删除后在同路径重建 → 多段路径得到 `Denied`，但那是递归删除把已脱离的根 inode 清空、
    旧树里查不到这个名字的直接后果，**不是**检测；单段末段走“末段允许尚未存在”那条规则，
    同样返回 `Ok` 并交出新树里的对象。
  后面两条的差异只是“旧树还在不在”，本层都不作为信号使用。这与上面 `dev`/`ino` 那条属**同一个
  未闭合家族**、修法相同（从已打开句柄取身份并在 `root_is_live` 复核，不匹配即 fail-closed），
  本轮同样**未实现**。可达前提是能对根路径的父目录写入（本机用户或同机进程）：对端经协议
  删不掉也改不了共享根本身（`..`、绝对路径一律被拒），所以它是 Ruling 23 那条范围决定的同一族，
  不是新出现的对端可达通道。
- **`RootGone` 不是一个“根被删除”的信号，它有三个否定来源**（终评收尾订正：本文件此前在两处
  写作“只有一个来源”，那会误导读者以为 `RootGone` 能区分“目录消失”与“根从未登记”，而它不能）：
  1. `opened_root` 里登记表未命中——包括**从未 `register_root` 过**的 id，以及已被
     `unregister_root` 撤销的 id（`crates/uc-infra-local/src/fs/share_confinement.rs:193`）；
     `resolve` 与 `resolve_root` 两条入口共用这条，因此分类不会漂移。
  2. `root_is_live` 对定稿路径的 `is_dir()` 为假（`:170`，调用点 `:294` 与 `:327`）——根被删除
     或被改名挪走且未在原路径重建。
  3. `register_root` 一路的 `NotFound` 经 `root_io_error` 归类成 `RootGone`（`:205`）——登记失败。
  四条 `RootGone` 构造点（`:193`、`:205`、`:295`、`:328`）归结为这三条原因：后两条是同一个
  存活检查在两条解析入口上的调用点，不是第四种原因。三者都只回答“这条路走不通”，**不**回答
  “为什么”。要区分“根从未登记/已撤销”与“目录不见了”，
  调用方必须另经 `is_registered`（它只查登记表，不碰文件系统），不能靠 `RootGone` 本身。
  规格 §6 的 `unavailable`/`root_gone` 状态迁移因此需要 `is_registered` 与 `RootGone` 两个信号一起用。

## 归一化覆盖不到的残留类

`normalize_share_component` 折叠的只有两件事：ASCII 大小写、段尾的 `.` 与空格。因此它挡得住
`.Uniclipboard-Trash-x`、`.uniclipboard-trash-x.`、`.. `、`...` 这一批（语料与
`reserved_prefix_variants_are_reported_distinctly` 已固定），但下面三类**结构上命中不了，仍是开放项**：

- **NTFS 8.3 短名**：`UNICLI~1` 之类的短名可以指向同一个保留目录，但它既不以 `.`/空格结尾，
  也折不出 `.uniclipboard-trash-` 前缀，本归一化不可能命中。
- **依赖 locale 的大小写折叠**：土耳其语 `İ`/`I` 这类折叠不是 ASCII 折叠能覆盖的。
- **`~` 写法本身**：仍按字面处理，未做拒绝。

并且**Windows 与 macOS 至今一次都没有执行过**，这三类残留的实际可达性只有源码推断。
要彻底封死需要“拒绝任何可能折叠/缩短到该前缀的名字”（偏严，可能挡掉合法用户名），或由文件系统侧
保证不生成 8.3 名（NTFS 的 8.3 名生成可关，但不是本功能能假设的环境条件）。

这条残留的关键在于**复用**：同一个 `is_reserved_trash_component` 就是 P5 启用共享根时那次
“根内是否已存在匹配保留模式的条目”扫描（规格 §6.1，报 `reserved_name`）所使用的谓词。
接那条扫描的人必须知道上面三类在谓词之外，**不得把它当作该风险的完整防线**。
归属相位本轮定稿为 **P5**：P1 的任务 6 是授权判定器、任务 7 是装配接线，两者都不做这条扫描，
而代码文档一度把它写成“任务 6/7”（评审发现），已连同本节一并对齐——只有启用共享根的那条路由
（P5）会跑这条扫描。
这条警告与这条归属的唯一权威记录在 `uc-core/src/ports/remote_share/model.rs` 的
`is_reserved_trash_component` 文档里（该处曾两度漂移：先被误写成“任务 2 的递延项已在此关闭”，
后被误写成“任务 6/7”，均由评审发现后校正）。本节与它不得再各自漂移：以代码文档为准，
本节是决策层面的登记处。

## 库层机制（源码核对，非实测）

`cap-primitives` 4.0.3 的 `open` 分平台实现：

| 平台 | 机制 | 源码位置 |
| --- | --- | --- |
| Linux | 优先 `openat2`，resolve flags 为 `BENEATH \| NO_MAGICLINKS`；`ENOSYS`（永久不可用）或 `EPERM`（seccomp 拦截）时回退 `manually::open`；`EXDEV` 转成 `escape_attempt()` | `src/rustix/linux/fs/open_impl.rs` |
| Android | **不尝试 `openat2`**：`open_impl` 里那段调用整体是 `#[cfg(target_os = "linux")]`，源码注释写明 Android 的 seccomp 策略连“探测 `openat2` 是否可用”都挡不住，因此 Android 恒走 `manually::open` | `src/rustix/linux/fs/open_impl.rs` 的 cfg 门控 |
| FreeBSD | `openat` 带 `O_RESOLVE_BENEATH` | `src/rustix/freebsd/fs/open_impl.rs` |
| macOS 等其他 unix | `manually::open`（无内核侧 beneath 解析可用） | `src/rustix/fs/mod.rs` 的 cfg 选择 |
| Windows | 先屏蔽 `CON`/`PRN`/`AUX`/`NUL`/`COMn`/`LPTn` 等设备名，再 `manually::open` | `src/windows/fs/open_impl.rs` |

本表原先把 Android 与 Linux 并列为“优先 `openat2`”，**那是错的**（评审记为任务 1 的递延 Minor，
本轮修正）。对本项目的含义：移动端若将来承载共享根，其库层保证只有 `manually::open` 的句柄栈，
没有内核侧 beneath 解析——本层的逐段加严在那条路径上更不是“纵深”而是分担。

`manually::open` 的包含性是构造性的：逐段解析时把已下降的目录句柄压栈，遇到 `..` 只从栈里取父句柄，
栈空即 `escape_attempt()`（`src/fs/manually/open.rs` 的 `parent_dir()`），因此**任何情况下都无法上升到
起点目录之上**；软链目标里的 `..` 走同一条栈。符号链接由库自己按段读取并展开，展开后的目标同样受
该栈约束——这解释了本次实测的拒绝形态。

需要如实标注的一点：`escape_attempt()` 在两条路径（`openat2` 的 `EXDEV` 转换、`manually` 的栈空弹父）
下都会产生，本次实测**无法只凭错误形态区分实际走了哪一条**。本机内核支持 `openat2`，按源码优先走前者；
回退的 `manually` 只有源码核对，未在本机强制触发（见“未验证项”）。因此本表记录的结论是
**“`cap-std` 在本机这一条实现路径上拒绝了全部探测的逃逸”**，而不是“两条路径都实测过”。

两条对任务 5 有直接影响的 API 事实（4.0.3，源码核对）：

- `cap_std::fs::Dir` **没有 `Clone`**，只有 `try_clone() -> io::Result<Self>`；计划的 `HashMap<ShareRootId, Dir>`
  加 `.cloned()` 写法需要改为显式 `try_clone()` 并处理失败。任务 5 已按此实现：中间段每步 `open_dir`
  得到一个新的 owned `Dir`（不需要 `Clone`），`resolve` 在锁内 `try_clone()` 后立即释放守卫。
- `Dir` **没有 `path_for`**；`canonicalize` 返回的是**相对**路径（能力模型下绝对路径无意义）。
  `ConfinedTarget.real_path` 所需的绝对路径只能由本层在 `register_root` 时保存 `PathBuf` 后拼接
  （实现即 `RootHandle { dir, path }` 成对保存），拼接前该相对路径已通过逐段校验。
  代价是本层交回的是一个**字符串快照而非句柄**，其后果与必须的前置决定见
  “`real_path` 是快照，不是能力（P2 前置条件）”一节；`path` 与 `dir` 是否在同一个根上，
  还受“两次独立环境权限解析”那条残留约束。

## 选项与取舍

### 选项 A：`cap-std`（选定）

优点：

- 实测（Linux）直接给到目录树包含，包含性由内核 `openat2` 或库的句柄化下行保证，不依赖调用方
  把路径写对；`..` 与绝对路径在类型层面就无法表达（`Dir` 只接受相对路径）。
- 跨平台一套 API，覆盖本项目的三个目标 OS，无需各自维护 `libc`/`windows-sys` 绑定与降级矩阵。
- 句柄即权限的**真实含义**（fix round 1 校正：本条原先写作“根被移走/替换时后续解析直接失败，
  天然满足 `RootGone` 不降级为全盘可见”，那高于代码提供的保证，也与本 ADR“决定”第 2 条自相
  矛盾——`RootGone` 恰恰被列在那里，属于库不提供、必须由本层补的规则）。落地代码给到的是：
  **行走本身**始终从登记时那个 `Dir` 出发，`..`、绝对路径与平台专有写法在类型层面进不来，
  所以逐段下行不会越出当时那棵树；它**不**保证“根被移走后后续解析直接失败”，而交回的
  `real_path` 走的是字符串快照那条通道（同名重建时说的已经是另一棵树）。`RootGone`
  **不是**单一来源的信号（本条原先写作“只有一个来源”，那是错的）：`root_is_live` 的
  `path.is_dir()` 存活检查、`opened_root` 的登记表未命中、`register_root` 打不开根这三条
  都会给出同一个变体，逐条的源码行号与含义以“`real_path` 是快照，不是能力”一节里
  “`RootGone` 不是一个‘根被删除’的信号，它有三个否定来源”那条为唯一权威记录，本条不重复
  行号以免漂移。其中进入**解析**路径的只有前两条（登记表未命中与存活检查），而 `root_is_live`
  自己的文档写明，句柄化下行在 Linux 上“读不到根已被删除”（老 inode 仍然可达），
  所以存在性检查只能靠定稿路径那一次 `is_dir()`。
  删除 / 改名挪走 / 同路径重建这几种形态各自走到哪一步，见同一节的根生命周期条目；
  简言之**只要原路径上不再是一个目录就会被检测到（删除或改名挪走且不重建），
  一旦同路径上重建了目录，本层分辨不出它是不是原来那棵**。
- 社区长期维护的能力模型实现，逃逸语义由其测试与文档正面覆盖。

代价：

- 新依赖，见“依赖影响”。
- 平台内部机制不一致（Linux 走 `openat2`，Windows/macOS 走手动下行），强度需按平台分别验证；
  本项目当前只有 Linux 证据。
- 能力模型与“绝对路径”世界不互通：本层要自己维护 `root_id -> 绝对路径` 的映射用于本机文件操作。
- 库不提供本功能需要的策略层（软链一律不可穿越、保留前缀、不透明错误、层数/长度上限），
  内核仍要写。

### 选项 B：自研三平台 `openat2` + `O_RESOLVE_BENEATH` + `NtCreateFile`

优点：

- 完全可控，可把“拒绝一切软链穿越”直接写进解析路径（`RESOLVE_NO_SYMLINKS`）。
- 无第三方依赖，行为与平台文档一一对应。

缺点：

- 三套 syscall 绑定与三套回退（老内核 `ENOSYS`、seccomp `EPERM`、Windows 命名空间前缀 `\\?\`、
  ADS `file:stream`、盘相对 `C:foo`）全部自己实现并自己测；本项目 `crates/uc-infra/src/fs/` 目前
  只做“无覆盖写发布”这一件小事，没有承载这类底层能力的模块。
- 安全语义自证成本高：这正是 `cap-std` 已经解决的问题，重新实现等于把逃逸风险从库转给自己。
- 与选项 A 相比不增加任何可验证的强度（Linux 上两者都是 `RESOLVE_BENEATH`）。

### 选项 C：纯字符串校验（normalize + `starts_with(root)`）

优点：零依赖、最易写、易读。

缺点：

- 只有路径字符串包含。符号链接、挂载点、大小写不敏感、`\\?\`、ADS、盘相对路径都能绕过；
  `canonicalize` 本身就是一次跟随软链的解析，校验与使用之间还有 TOCTOU 窗口。
- 校验的是“我以为的路径”，打开的是“内核解析出的路径”，两者可以不同——这正是规格 §6 明令禁止的形态。
- 结论不满足需求，仅作为对照列出。

## 依赖影响

- 引入前本工作区对 `cap-std`/`cap-primitives` 是**零命中**，属全新依赖；OS 侧**直接**依赖只有
  `libc`（unix）与 `windows-sys`（windows），无 `nix`、无 `windows` crate。
- `rustix 1.1.4` 在引入前已存在于 `Cargo.lock`，来源是 `tempfile`、`xattr`（经 `tar`）、`reflink-copy`
  （经 `iroh-blobs`）的传递依赖；`cap-std` 让 `rustix` 进入约束内核的实际执行路径，此前它只服务于
  测试与第三方库的内部实现。
- 本次 `cargo test` 解析新增 10 个包：`cap-std 4.0.3`、`cap-primitives 4.0.3`、`ambient-authority 0.0.2`、
  `fs-set-times 0.20.3`、`io-extras 0.19.0`、`io-lifetimes 2.0.4` 与 `3.0.1`、`maybe-owned 0.3.4`、
  `rustix-linux-procfs 0.1.1`、`winx 0.36.4`（`winx` 只在 Windows 构建中参与编译）。
- 同一次 `Cargo.lock` 更新里另有两行**不是新增包**的变化：`anstyle-query` 与 `anstyle-wincon` 的
  `windows-sys` 依赖由 `0.60.2` 刷到 `0.61.2`。这是加 `cap-std` 触发整张图重解析时的版本刷新，
  评审核实为 no-op（没有引入新 crate，也不改变本仓任何依赖边）。登记在此，是为了让下一次读锁文件
  的人不必再猜这两行的来处——它们看起来像 `cap-std` 的连带影响，实际只是同一次解析的副产品。
- `cap-std` 是 `uc-infra` 的普通 `[dependencies]`（不是 dev-dependency）：约束内核是生产代码，
  上层 crate 不直接依赖它，具体库类型不外泄到 `uc-core` 端口之外。任务 1 提交时它曾短暂处于
  “已进生产依赖、`src/` 下尚无使用者”的窗口，任务 5 落地内核后该窗口已闭合。

## 后果

- 任务 5 的内核按“库已提供目录树包含（仅 Linux 证据）+ 本层逐段加严为策略与纵深”的形态实现，
  注释需引用本 ADR，避免后来者误删逐段检查。该留痕已落在
  `crates/uc-infra-local/src/fs/share_confinement.rs` 的模块文档与 `check_not_symlink` 上，
  并由 `root_internal_symlink_is_rejected_even_though_the_library_would_follow_it` 与
  `cap_std_alone_follows_a_root_internal_symlink` 两条测试共同守卫。
- **`real_path` 那条“快照不是能力”是 P2 的第一道门**（见同名小节）：在它解决之前，
  P2/P3 不得在 `real_path` 上直接建破坏性操作，端口文档也不得重新声称“撤销让既有目标失效”。
- **本 ADR 选定的这一层不构成授权**（终评 Important 2 登记的义务，权威记录在
  `uc-core/src/ports/remote_share/confinement.rs` 的 `resolve` 文档与执行计划「前置条件」第 9 条）：
  `CapStdConfinement` 只读 `root_id -> 句柄` 那张登记表，从不读清单；判定器 `ShareAuthorizer` 只读
  清单，从不碰文件系统。于是 `resolve` 返回 `Ok` 只说明“这个 id 登记过且路径仍在树内”，被禁用、
  被删除或整机 `suspended` 的根照样能通过。一次操作的许可必须是 `authorize` 与 `resolve` 两者都
  放行（规格 §5.2 的第 3–5 步与第 6 步正是这条合取的顺序陈述），且**改写清单的一方**要在同一事务里
  配套 `register_root` / `unregister_root`。选型把包含判定做成独立一层买到的正是可替换性，代价就是
  这条合取没有任何一层能自己保证，只能由调用方（P2 的 serve 适配器）承担。
- 线文法（“决定”第 3 条）是跨仓约束：产品仓规格 §7 定义了同一套禁止项，实现比规格更严的那一半
  （纯点/纯空格段）已在任务 8 回写进规格，两处必须同步演进，不得一边收紧一边不动。
- 归一化覆盖不到的三类残留（NTFS 8.3 短名、locale 大小写折叠、`~` 变体）是**开放项**，
  且同一个谓词会被 P5 的启用时保留名扫描复用；该风险的权威记录在
  `uc-core/src/ports/remote_share/model.rs` 的 `is_reserved_trash_component` 文档里。
- 逃逸语料（任务 5 的 `ESCAPE_CORPUS`）在三平台首跑前，Windows/macOS 的安全论证强度只能算
  “按 Linux 实测 + 源码核对的外推”，评审时按此判断。
- `cap-std` 版本升级需要重跑本闸门：结论表里的“拒绝/跟随”都是版本相关事实，升级 PR 应带上
  三平台的执行结果或明确标注未执行。
- 本 ADR 不引入新的持久化格式，也不改变日志/凭据边界；约束内核的错误必须保持不透明，
  不回显路径片段（`AGENTS.md` 日志脱敏硬约束）。唯一的例外形态是 `ConfineError::Io { source }`：
  它的显示文本由下层决定，因此本层只原样转带 `cap-std`/OS 自己产生的 `io::Error`，**绝不**构造含路径的消息；
  适配器侧同样受这条约束（`uc-core` 端口文档已写明）。

## 未验证项

- **Windows**：跳过（本任务未在 Windows 真机上执行）。`manually::open` 与设备名屏蔽仅源码核对；NTFS 软链/目录联接/junction
  的可跟随性、大小写不敏感前缀、`\\?\` 长路径、ADS 均未测。
  **本层新加的保留设备名筛查同样没有 Windows 实测**：谓词是纯字符串比较，因此“三平台同一个答案”
  是按构造成立、并在 Linux 语料上固定的（`windows_reserved_device_names_are_detected_on_every_host`
  与语料的 `"CON"`/`"nul.log"`/`"a/CON/b"`）；但“若不挡，`<root>\CON` 会被 Win32 归到设备命名空间”
  这条**动机**只有文档与源码依据，未在真机复现。真机首跑时应补一条“经环境权限打开
  `<root>\CON` 拿到的不是共享树里的文件”的对照。
  此前 Windows 分支的 fixture 缺陷（链接建在临时目录**同级**、目标写作 `outside` 而非 `..\outside`，
  会导致 `expect` 把“路径写错”误报成权限问题、或建成悬空链接让 `open` 因 `ENOENT` 假通过）**已修复并固化**：
  `#[cfg(windows)]` 分支现在把链接建在 `dir.path().join("root/escape")`、目标为 `..\outside`，且第一行的
  ambient 正向对照在无 `cfg` 门控的公共代码里，任何平台下悬空/错误的链接都会先让 fixture panic。
  剩下的只是**执行**缺口：需在真机跑一次这四条测试，把“跳过”替换为实测结果；若关键一条在 Windows 上被
  跟随（非 `PermissionDenied`），内核的逐段加严从纵深升格为唯一保证，需在本表补记。注意 `expect("symlink
  (Windows 需开发者模式或管理员权限)")` 在未开启开发者模式/无权限时仍会 panic——那是运行前提，不是探针结论。
- **macOS**：跳过（未执行）。APFS 软链行为与 `manually::open` 下行未测。
- **任务 5 的语料与线文法筛查**：`ESCAPE_CORPUS` 24 条、`WALK_STAGE_DENIALS` 的分层归属、
  `host_independent_screen_rejects_windows_spellings` 全部只在 Linux 上跑过（一条命令：
  `cargo test -p uc-infra --test share_confinement_escape_probe`）。Windows/macOS **跳过**：
  而这两平台上本层是唯一边界，所以语料里那些“依赖 Windows 语义才成立”的条目（`C:foo`、UNC、
  `\\?\`、`.. ` 结尾点空格、`CON`/`nul.log` 保留设备名）目前只有字符串层面的证据，没有平台层面的证据。
- **归一化覆盖不到的三类**（NTFS 8.3 短名、locale 大小写折叠、`~` 变体）：未测，且未拒绝，
  见“归一化覆盖不到的残留类”。
- **`register_root` 的句柄与路径身份一致性**：`dev`/`ino`（Windows file index）复核未实现也从未测；
  现有保证只到“定稿过的绝对路径不再回看原始输入”。登记后根被挪走/同路径重建的三种形态由本轮
  一次性探针在 Linux 上复核（结论见“根生命周期”条目），**探针未入库**：树内只有“删除且不重建”
  一条 committed 断言。P2 实现身份复核时应把另外两种形态一并固化为回归测试。
- **Linux 上 `openat2` 不可用时的回退路径**：跳过（本机内核支持 `openat2`，无法在不引入 seccomp/容器
  限制的前提下强制走 `manually`）。回退的包含性由 `parent_dir()` 的句柄栈构造性保证，属源码核对。
- **TOCTOU 竞态**：未做并发改名压力实测；`cap-primitives` 的 `racy_asserts` 配置未在本工作区启用。
  另外本层从未声称关闭该窗口（见“决定”第 2 条与“`real_path` 是快照，不是能力”），
  所以这一项即便测了也只是加深证据，不会改变结论的形状。
- **`ambient_authority()` 的可用性门禁**：本 ADR 假定进程持有环境权限（我们的部署形态成立）；若未来
  在 `Landlock`/沙箱下运行，`Dir::open_ambient_dir` 可能直接失败，需要在装配层给出可见错误。

## 参考

- 产品仓规格 `docs/specs/2026-10-12-device-file-share-spec.md` §6（逃逸清单与不透明错误）、
  §6.1（回收前缀）、§7（相对路径线文法及其代价，任务 8 已补入“纯点/纯空格段亦禁止”）、§18（要求新增本决定）
- 执行计划 `docs/exec-plans/active/2026-10-12-device-file-share-phase1.md` 任务 1（本闸门）与任务 5（内核）
- 闸门与语料测试 `crates/uc-infra-local/tests/share_confinement_escape_probe.rs`；
  内核实现 `crates/uc-infra-local/src/fs/share_confinement.rs`；端口与线文法
  `crates/uc-core/src/ports/remote_share/confinement.rs`；归一化与保留名谓词
  `crates/uc-core/src/ports/remote_share/model.rs`
- [`openat2(2)` 手册](https://man7.org/linux/man-pages/man2/openat2.2.html)（`RESOLVE_BENEATH`、
  `RESOLVE_NO_MAGICLINKS`、`RESOLVE_NO_SYMLINKS` 的差别）
- `cap-std` / `cap-primitives` 4.0.3 源码：`src/rustix/linux/fs/open_impl.rs`、
  `src/fs/manually/open.rs`、`src/windows/fs/open_impl.rs`、`src/fs/errors.rs`
- 相邻决定：[ADR-013 本地加密搜索索引](013-local-encrypted-search-index.md)（本仓编号 013，与产品仓规格里
  提到的“ADR-013 cap-std”无关；后者是产品仓自己的编号体系，对应本文）。
  同一功能的存储侧决定见 [ADR-035：共享根清单用 Space 派生子密钥密封](035-share-store-space-subkey.md)。
