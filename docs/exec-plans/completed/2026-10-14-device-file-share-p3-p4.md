# 设备文件共享 P3–P4（句柄化约束 / 变更 RPC / 传输编排）实施计划

- **日期**：2026-10-14。
- **状态**：已完成（2026-10-15；T9 门禁证据见文末「交付记录」）。
- **上游**：[设备文件共享规格](https://github.com/UniClipboard/UniClipboard)（产品仓 `docs/specs/2026-10-12-device-file-share-spec.md`，下文以「规格 §n」引用）与本仓 `feat/device-file-share-p1-port` 分支已合并的 Phase 0 + Phase 1（`ed3116be..33aa08b8`）。
- **本计划覆盖**：规格 §17 的 P3（变更 RPC）与 P4（传输编排），加上被两者共同列为开工前置的约束内核句柄化（交接文档 §4 三项未闭合保证）。

## 1. 前置裁定的现状

交接文档（产品仓 `.planning/2026-10-13-device-file-share-status.md`）§4 登记的三项，本次一并关闭：

1. **`real_path` 是快照不是能力**：`ShareConfinementPort` 改为交出不透明句柄（`ConfinedTarget` 内嵌 token），端口上提供相对已保留 `Dir` 的全部操作；撤销根后既有 target 的操作必须失败（登记表代次复核）。
2. **根生命周期检测不全**：登记时从**已打开的句柄**取 `dir_metadata()` 的 `dev`/`ino`（Windows：`volume_serial_number`/`file_index`）作为 `RootIdentity`；存活检查改为「登记路径 stat 的身份 == 登记身份」，不匹配 fail-closed 成 `RootGone`——同时覆盖「改名后同路径重植」与「删除后重建」两个原检测不到形态。
3. **`canonicalize` 与 `open_ambient_dir` 不互证**：同一次登记里比对 `std::fs::metadata(canonical)` 与 `dir.dir_metadata()` 的身份，不一致即拒绝登记（`Denied`）。

规格 §19 裁定：**接受残余风险并写入 ADR-036**（持 digest 者可拉取同一内容属既有属性；能算出 digest 者本就持有相同字节，残余仅为「经旁路得知 digest 而无内容」的存在性预言机与带宽占用）。不为导出加盐、不建 digest 白名单。

## 2. 设计决策摘要

### 2.1 句柄化端口形状（`uc-core` → `uc-infra-local`）

- `ConfinedTarget` 从「`real_path` 字符串快照」改为 `{ root, relative, token: Arc<dyn ConfinedTargetToken> }`；`ConfinedTargetToken` 是 core 定义的 marker trait（`Send + Sync`），只有内核能构造。
- token 承载：父目录 `Dir`（`try_clone` 的独立 fd）、末段名 `Option<OsString>`（`resolve_root` 的根自身为 `None`）、登记代次 `generation`。
- 所有动词留在 `ShareConfinementPort` 上，每个 op 先查登记表（未登记/代次不符 ⇒ `RootGone`），再对 token 内的 `Dir` 做 cap-std 相对操作——**检查过的对象与被操作的对象是同一个 fd**。
- 末段读取/下行用 `cap-fs-ext` 的 no-follow `open`/`open_dir` 把「resolve 期非符号链接、op 期被换成符号链接」的最后一条竞态缝上（Linux 上 openat2 `RESOLVE_BENEATH` 本就挡根外，no-follow 同时服务 Windows/macOS 未实测平台与本层"拒绝一切根内符号链接"的策略一致）。新增依赖 `cap-fs-ext`（与 `cap-std` 4.0.3 同族同版系）。
- `Dir::rename`/`remove_file`/`create_dir`/`create` 按名字作用、不跟随符号链接，本身无末段 TOCTOU；`Dir::copy` 的源跟随问题经先 `symlink_metadata` 收窄，残窗内最坏落入根内另一文件（不出授权边界），如实记录。
- 端口方法集（一个完整的安全边界，刻意不拆）：生命周期 `register_root`/`unregister_root`/`is_registered`；解析 `resolve`/`resolve_root`；目标动词 `target_metadata`/`target_read_dir`/`target_open_read`/`target_create_dir`/`target_rename`/`target_copy_into`/`target_move_to_trash`；根级动词 `list_trash`/`empty_trash`/`restore_from_trash`/`sweep_expired_trash`；暂存动词 `create_staging`/`staging_target_path`/`staging_entry_count`/`commit_staging`/`abort_staging`。
- `ConfineError` 扩 `NotFound`/`Conflict`/`NotADirectory`/`IsADirectory`，全部保持无载荷。

### 2.2 回收目录与暂存目录（规格 §6.1 修订）

- 根内保留命名空间扩为两段：`.uniclipboard-trash-<root_id>`（回收目录）与 `.uniclipboard-staging-<staging_id>`（上传暂存）。`is_reserved_trash_component` 泛化为 `is_reserved_share_component`，两个前缀都拒。
- 回收条目布局：`.uniclipboard-trash-<root_id>/<trash_id>/` 每条目一个子目录，内含 `payload`（原条目本体，同盘 `rename` 移入）与 `meta.json`（`original_rel`、`deleted_at_ms`、`is_dir`、`size_bytes`）。`trash_id` 是不透明名；`ListTrash` 只认能解析出 meta 的子目录。
- `Restore` 的默认目标即 `original_rel`；冲突按 §8.1 重名策略（自动改名；显式覆盖需 `Overwrite` 授权）。
- `TRASH_RETENTION_DAYS = 7`：惰性清理——`register_root` 与 `list_trash` 顺带 `sweep_expired_trash`，不另设后台定时器。
- 登记期扫描：`register_root` 时根内出现 `.uniclipboard-trash-*`（非本根 id）⇒ `ReservedName` 拒绝登记；`.uniclipboard-staging-*` 一律视为崩溃残留直接清掉（只有内核会写该前缀；peer 端协议上不可寻址）。本根自己的 `.uniclipboard-trash-<root_id>` 保留（含历史回收条目）。

### 2.3 线格式重构（`uc-sync-protocol`）

- 现状 postcard 裸枚举遇到未知变体直接解码失败掉连接，不满足规格 §15「未知操作码必须回 `unsupported_request`」。改为**显式 opcode**：body = `postcard(u32 opcode) ++ postcard(按 op 的 payload struct)`；未知 opcode 解码为 `ShareRequest::Unknown { opcode }`，serve 适配器回 `Denied{UnsupportedRequest}`。回复侧同法。版本仍为 `/1`（未发布，允许直接改帧体）。
- `DenyCode` 扩到规格 §12 全集：`locked/unsupported/unsupported_request/suspended/revoked/denied/reserved_name/not_found/conflict/root_gone/quota/too_large/too_many_entries/io/cancelled/too_late/interrupted`。既有 `NotUnlocked`→`locked`、`NotAuthorized`→`denied` 重命名对齐（未发布）。
- 新增请求：`Mkdir/Rename/Delete/ListTrash/Restore/EmptyTrash/CopyWithin`（P3）与 `StageUpload/CommitUpload/AbortUpload/Export`（P4）。回复新增 `Ack`/`Staged{staging_id}`/`Deleted{trash_id}`/`TrashEntries{…}`/`Exported{ticket,size}`。
- 字节寻址在 wire 上以 **BlobTicket 字节**（含对端 addr+hash）传递，不是裸 digest——这是既有 `BlobTransferPort` 的取件凭据，规格 §8 的「digest」措辞按实现订正为 ticket（spec 已同步）。
- `StageUpload` 带 `transfer_id: [u8;16]`：holder 的 blob 拉取进度经既有 `transfer-progress/1` 反向帧回推给上传方，`transfer_id` 即进度帧的关联键。
- golden 向量按 crate 规则新增（见 `tests/golden_vectors.rs` 既有形态）。

### 2.4 传输编排（Application，已实现为准）

- `remote_share/transfer.rs`：`ShareTransferCoordinator` 单锁持有 staging 会话、commit 墓碑与导出租约；fetch worker 以 `Semaphore::new(MAX_CONCURRENT_FETCHES=4)` 逐条 `staging_entry_path` + `fetch_to_path`；`EntryProgressSink` 逐条聚合后经 `OutboundProgressReporterPort` 以 `transfer_id`（16 字节 client 选定）上报。
- `CommitUpload` 先等 fetch 收敛（`wait_settled`），再复核授权并逐条落位（`ConflictPolicy` 自动改名）；成功后 staging_id 进墓碑集——重复 commit 或迟到 abort 一律 `TooLate`（对端应答丢失重试可区分「已落地」与「已丢弃」）。`AbortUpload` 置取消位、对在途 fetch 逐票 `shutdown_inflight_fetch`、收敛后 `abort_staging` 清目录；未知/外源 id → `StagingNotFound`，幂等。
- `Export`：`target_open_read`（no-follow fd）→ `tokio::fs::File` → `ReaderStream` → `add_stream` 流式发布；`BlobTransferPort` 新增 `publish_reader(std::fs::File)` 端口方法，不引入 `retain_temp`——导出内容以 `TagReason::RemoteShareExport(lease_id)` 命名标签代持，`EXPORT_LEASE_TTL=30min`，每次 `publish_export` 顺带清扫过期租约（对端可惰性开拉）。上传侧不写本地 tag（字节来自对端自己的 store），故无 `RemoteShareUpload` 变体。
- 审计（规格 §5.3）：变更/传输类操作在 serve 适配器发 `remote_share.serve.op` 封闭记录——`op`、`root_id`、`blake3(rel)` 截断 `u64`、结果码；对端身份经 `peer_context` 内存上下文挂入、由序列化层分配匿名 `peer_ref`（ADR-036）。`Hello`/`ListRoots`/`List`/`Stat`/`ListTrash` 高频只读记 `uc_debug!`，不进记录通道。

### 2.5 根注册责任人（`remote_share/registry.rs`，已实现为准）

- `ShareRootsRegistry`：清单写路径唯一责任人——`reconcile_startup`（load→收敛：登记 enabled 根、撤销自记 `registered` 集合中不再期望的根）、`replace_doc`（save 成功才收敛，save 失败登记表不动）、`revoke_all`（会话结束收口）。suspended 即期望集为空，全量撤销。
- 登记表无列举 API，责任人以 `registered: Mutex<HashSet<ShareRootId>>` 自记撤销依据；单根登记失败只让该根缺席（`RootGone` fail-closed），清单读不出来时全量撤销。
- 装配点 `prepare_sync_session`：`install_remote_share` 后、`builder.finish()` 前 `reconcile_startup().await`（登记表动词是同步 fs 工作穿 async 外衣，`register_root` 逐根经 `spawn_blocking` + `block_on` 卸载）；句柄挂在 `SyncSessionAssembly::remote_share_registry`，`shutdown` 首步 `revoke_all`。

## 3. 不变量（随本阶段新增）

- **I9'**：`.uniclipboard-trash-*` 与 `.uniclipboard-staging-*` 两个保留前缀首段一律拒绝，`List` 永不返回该前缀。
- **能力一致性**：撤销根（或重登记到另一路径）后，既有 `ConfinedTarget` 的一切 op 必须失败（`RootGone`）。
- **末段一致性**：`target_*` 动词操作的对象与 `resolve` 检查过的对象是同一个 fd；末段符号链接替换在 no-follow open 处被拒。
- **暂存不可寻址**：`staging_id` 只由 `StageUpload` 回复给出；任何以 `.uniclipboard-staging-` 为首段的客户端路径被拒。
- **事务性**：`CommitUpload` 逐文件原子 `rename`；中途失败已落位文件保持完整，未落位条目的暂存随后清除——目标目录不出现半个文件。
- **wire 脱敏**沿用：DTO 不带绝对路径，`original_rel`/`name`/`label` 类用户内容 `Debug` 脱敏。

## 4. 任务切分（每片可独立验收）

| # | 片 | 内容 | 验收 |
| --- | --- | --- | --- |
| T1 | 文档 ✅ | 本计划、spec 订正（暂存前缀/ticket/§19 裁定/句柄化描述）、ADR-036 | 文档落库 |
| T2 | 句柄化内核 ✅ | `confinement` 端口重画 + `CapStdConfinement` 重写（身份复核 + no-follow 末段 + 全动词）+ 逃逸探针/新用例 + `cap-fs-ext` 依赖 | 内核 + 探针 25 测全绿 |
| T3 | serve 迁移 ✅ | `RemoteShareServe` 的 `list`/`stat` 改走 `target_*` 动词 | 20 测语义保留 |
| T4 | 线格式 ✅ | opcode 重构 + `DenyCode` 全集 + P3/P4 全部 DTO + golden 向量 | 41 单测 + 10 golden 全绿 |
| T5 | 变更 RPC ✅ | `RemoteShareServePort` 增 `mkdir/rename/delete/copy_within` + serve 实现 + 适配器分发 + 判定矩阵 | 适配器 7 verdict 全绿 |
| T6 | 回收目录 ✅ | `list_trash/restore/empty_trash` + `move_to_trash` + 惰性清理 + I9' 过滤 | trash 生命周期用例全绿 |
| T7 | 传输编排 ✅ | `transfer.rs` + `StageUpload/Commit/Abort/Export` + `publish_reader` + 进度/取消 + §5.3 审计记录 | 应用 32 测 + 契约记录测全绿 |
| T8 | 注册责任人 ✅ | `ShareRootsRegistry`（reconcile_startup/replace_doc/revoke_all）+ 装配 reconcile + shutdown 撤销 | 5 测全绿 |
| T9 | 收尾 | 全量 gate（`cargo test --workspace --locked`、fmt、rust-style、repo-check、obs-privacy）+ 文档对齐 | 全部通过 |

## 5. 明确不做

- 出站 client（dial 对端 ALPN）：P5 daemon 阶段一起做（YAGNI，当前无消费者）。
- daemon 路由/OpenAPI/SDK、Go 宿主、前端：本仓阶段。
- 本地地址透出（P8）、三平台端到端（P9）。
- `revoked` 之外的会话代次吊销语义深化；`quota` 目前只定义 wire/错误分类占位，不实现配额核算。

## 6. 风险与已接受残余

- Windows/macOS 仍未实测（P9 才跑真机）；`cap-std` 手工逐段路径上的行为按文档记录为跳过而非通过。
- `Dir::copy` 源符号链接残窗：先 lstat 再 copy，残窗内最坏读到根内另一文件（不出授权边界）。
- 暂存目录内路径为内核构造的环境路径（blob 层 `export_with_opts` 需要真实 `PathBuf`）；peer 无法注入路径，本地同名进程换目录属既有威胁模型范围外（能写共享根即可改文件，见规格 §6 讨论）。
- 进度帧 transfer_id 关联：B 端按 `StageUpload.transfer_id` 回报，A 端聚合即得父任务进度。

## 7. 交付记录（T9 gate 证据，2026-10-15）

| Gate | 结果 |
| --- | --- |
| `cargo check --workspace --all-targets --locked` | 通过（仅 uc-ohos-napi 既有 unused-import 警告，非本改动） |
| `cargo test --workspace --locked` | 109 个测试目标全绿；**唯一失败组**为 `uc-upgrade-matrix` 的 66 个 `d*::*_to_head` cell——`anchor-host-missing` 环境缺口（需 CI `build-upgrade-anchors.sh` 预构建旧版 anchor，本地 worktree 不具备），交接文档 §6 已登记。`peer_address_read_diagnostics` 的栈符号断言在本环境以 `UC_EXPECT_DIAGNOSTIC_STACK=available` 运行（该测试自带此环境开关，注释允许"插桩或平台差异"下符号缺失）。`space_leave::repeated_leaves_do_not_accumulate_tasks_or_descriptors` 首轮报资源计数抖动（49→52 task），单独重跑通过，判定为并行采样时序问题而非本改动引入——本改动不新增常驻任务。 |
| `cargo fmt --all -- --check` | 通过 |
| `node scripts/architecture/check-rust-style.mjs` | 通过 |
| `node scripts/architecture/check-engine-repository.mjs` | 通过（含 observability privacy、collector 契约与全部负例夹具） |
| `git diff --check` | 通过 |

定向证据：约束探针 25 测、应用 remote_share 37 测（含编排 12 测）、sync-protocol 41+10、serve 适配器 7、registry 5 测、审计记录契约测 1。

**未执行（如实记为跳过）**：Windows/macOS 平台验证（P9 真机）、双 peer 端到端（需推送 fork + rev-pin 后在产品仓跑）。**推送 `UniClipboard/Engine`、发标签、产品仓 rev-pin 均未执行**——需用户明确授权。

### 实施后的稳定结论

- `ShareRootsRegistry` 是清单写路径的唯一责任人（`reconcile_startup`/`replace_doc`/`revoke_all`）；登记表无列举 API，责任人以自记 `registered` 集合驱动撤销——装配层不得绕过它直接 `register_root`。
- staging_id 生命周期三态：会话表 → 墓碑（commit 后）→ 清除；墓碑保证重复 commit/迟到 abort 得 `TooLate` 而非假 `NotFound`。
- 导出字节以 `RemoteShareExport(lease_id)` 命名标签短时持有（30 min TTL，`publish_export` 顺带清扫），不引入独立 guard 类型。
- §5.3 审计在 serve 适配器落成 `remote_share.serve.op` 封闭记录；`peer_ref` 匿名编号由记录层分配，peer 身份与明文 rel 均不出进程。
