# ADR-035：共享根清单用 Space 派生子密钥密封

- **状态**：已采纳（Linux 单元层证据齐备；真实 Space 会话下的“锁定即不可读”尚未端到端验证，见“未验证项”）
- **日期**：2026-10-12（P1 终评收尾补记一条：这份密文文档还会随整份 profile 进 profile-upgrade
  备份归档，见“后果”最后一条与“未验证项”最后一条；判定为可接受，附 P5 确认条件）
- **范围**：设备文件共享的共享根清单（`ShareStore`）的密钥来源、落盘形态、容量上限与版本策略。
  不决定路径约束原语（见 [ADR-034](034-share-path-confinement-cap-std.md)），不决定线协议、daemon 路由与 UI
- **相关文件**：[`remote_share/store.rs`](../../../crates/uc-infra-storage/src/remote_share/store.rs)（密封与读回的唯一实现）、
  [`ports/remote_share/store.rs`](../../../crates/uc-core/src/ports/remote_share/store.rs)（`SharedRootStorePort` 与其错误分类）、
  [`ports/remote_share/model.rs`](../../../crates/uc-core/src/ports/remote_share/model.rs)（`ShareStoreDoc` 与唯一版本号）、
  [`fs/vault_layout.rs`](../../../crates/uc-infra-local/src/fs/vault_layout.rs)（`share_store_path()` 是文件名的唯一来源）、
  [`assembly/wire/infra.rs`](../../../crates/uc-engine/src/assembly/wire/infra.rs)（子密钥端口的注入点）、
  产品仓规格 `docs/specs/2026-10-12-device-file-share-spec.md` §2.2、§5.1、§9、§13 I4（该条在产品仓编号 ADR-014，
  在本仓按顺序落为 035）

## 背景

设备文件共享的白名单是若干“共享根”：每个根带一个**本机绝对路径**与一个**用户可读 label**，外加逐根的
读/写/删除授权。按仓库底线（`AGENTS.md`「持久化默认密文」），这两项都是用户内容，**严禁明文落库或落盘**；
规格 §13 I4 进一步要求数据库列、缓存、搜索索引、日志与崩溃报告里都不得出现它们的明文。

落点有两个既存事实需要避开：

- `settings.json` 是**明文落盘**的（规格 §2 核对表的最后一行：`crates/uc-infra-local/src/settings/repository.rs`
  有读写、无 AEAD 调用点）。规格 §5.1 因此明确“不新增 settings 数据模型分区”，本功能对它零改动。
- 仓里有两处“小型加密文档落盘”的先例：`security/profile_storage_upgrade/persistence.rs`（经
  `AdmissionKeyManager::seal_profile_payload` + 64 KiB 上限 + 自有 `write_atomically`）与
  `security/profile_content_key_vault/persistence.rs`（形态相近，但整模块是 `pub(super)`，外部不可调用）。
  规格 §2 把前者记为**最贴近的模板**，同时写明“不可直接复用，需按同形态新写”。

“最贴近”这个词是真实的诱惑：照抄 `seal_profile_payload` 是最省事的路径。本 ADR 的主要价值就在于说明
**为什么恰好不能这么做**——它不是风格偏好，而是一条会静默作废安全语义的功能性错误。

## 先摆证据（源码核对）

| 事实 | 位置 | 结论 |
| --- | --- | --- |
| `AdmissionKeyManager::profile_key()` 从宿主 `SecureStoragePort` 读 `profile_admission_master_key:v1`；**读不到就现场生成 32 字节随机数、写入、再读回** | `admission_key_manager.rs:137-157`（生成并写入那段是 `:146-152`） | 这是一把 **profile 级**密钥，与 Space 会话、解锁状态毫无关系 |
| `seal_profile_payload()` 直接用 `self.profile_key()?` 做 AEAD | `admission_key_manager.rs:198-210` | 上面那条因此进入每一条加解密路径 |
| `DeriveSpaceSubkeyPort::derive_subkey(salt, info) -> [u8; 32]`，**会话未就绪时先返回类型化的 `SpaceAccessError::NotUnlocked`** | 端口声明 `uc-core/src/ports/space/access.rs:207-213`；实现 `uc-infra-security/src/access.rs:2125` → `session.rs:796-815` | HKDF-SHA256，IKM 是当前会话里 `ContentKeyId::legacy_v1` 对应的 Space 内容密钥（本机 Space 的主密钥材料；派生字节由 `store.rs` 的 `subkey()` 交给 `MasterKey::from_bytes` 消费）；密钥可得性等价于“会话已解锁且材料已就位” |
| `EncryptedBlob` 用 `serde_json` 落盘，`nonce`/`ciphertext` 都是 `Vec<u8>` | `uc-infra-crypto/src/crypto_model.rs:170-182` | `serde_json` 把字节数组渲染成**十进制数组**，尺寸放大见“决定”第 5 条 |

## 决定

1. **存储形态：单文件密文文档，密钥来自 Space 子密钥派生。**
   `ShareStoreDoc` 经 `postcard` 编码 → `v1_aead::encrypt_blob_xchacha`（XChaCha20-Poly1305，
   AAD 为 `SHARE_STORE_PURPOSE = b"uniclipboard/share-store/v1\0"`）→ `serde_json` framing →
   原子替换写入 `VaultLayout::share_store_path()`（即 `<vault>/share-store-v1.json`，文件名只有一个来源）。
   密封密钥由 `derive_subkey(SHARE_STORE_SALT, SHARE_STORE_INFO)` 产出，`salt`/`info` 是本域专用常量，
   与其它 Space 子密钥域（关系存储、搜索根密钥等）分隔。派生字节一律包在 `Zeroizing` 里，
   任何提前返回先清零。清单**不进 `settings`**，也不进 SQLite。

2. **“解锁前共享不可用”是被接受的约束，不是缺陷。** 密钥只在已解锁会话里可得，因此 Space 锁定时
   白名单既读不出也写不进（`load` 与 `save` 都在派生失败处直接返回 `NotUnlocked`，
   `save` 一个字节也不落）。后果必须在下游如实呈现，不得为消除这条约束而换密钥来源：

   - P5 的两条写路由 `PUT /remote-share/roots`、`POST /remote-share/suspend` 读写的正是这份文档，
     未解锁时必须返回 **`423 session_locked`**（规格 §9），与内容路由的既有行为一致；
     不得为了让设置页渲染而把该文档加进锁屏放行清单。
   - `GET /remote-share/state` 只读，锁屏下返回 `200 { locked: true, rootCount: null, suspended: null }`，
     不含任何路径。
   - UI 必须如实呈现“解锁后方可管理”，**不得**把 `423` 表现成“保存失败”或静默重试；
     也不能显示一份看起来可编辑、实则一提交就报错的空表单。

3. **不用 `AdmissionKeyManager::seal_profile_payload`，尽管它看起来是最贴近的模板。**
   它的密钥来自 `profile_key()`：profile 级、**缺失时自动生成并持久化**（见上表），整个过程不查问
   Space 解锁状态。用它写清单会得到两个各自都足以否证设计的后果：

   - **锁屏下白名单可读**。绝对路径与 label 是用户内容，其密文必须由 MasterKey 派生；profile 密钥不是
     MasterKey 的派生物，于是“持久化默认密文必须来自 MasterKey”这条底线直接被违反（`AGENTS.md`、规格 §13 I4）。
   - **“锁定 ⇒ 共享不可用”静默失效**。第 2 条约束的存在理由就是“密钥此刻不可得”。换成 profile 级密钥后，
     锁定状态下清单照样解得开：`derive_subkey` 那一处 `NotUnlocked` 再也不会触发，P5 的 `423` 变成死代码，
     UI 的“解锁后方可管理”变成一句谎话，而对端侧的共享能力会真的在锁屏下继续可用（第 4 步的授权判定
     读得出白名单）。**这三处都不会有任何测试变红**——现有断言全部以“构造 `EncryptedShareStore` 时必须传入
     `Arc<dyn DeriveSpaceSubkeyPort>`”这一形状为前提（`load_reports_not_unlocked_when_locked`、
     `existing_document_becomes_unreadable_when_space_locks`、`save_reports_not_unlocked_and_writes_nothing_when_locked`）。
     换密钥来源会直接编译不过，所以编译期确实挡住一次替换；但挡住的是“替换”，不是“忘记”：任何新增的
     第二份共享根持久物若顺手调用 `seal_profile_payload`，没有任何东西会提醒它违反了第 2 条。

   这条理由足以压倒“少写一份密钥派生”的省事动机。后来者若打算“简化”回 `seal_profile_payload`，
   请先重读本节并复核规格 §5.1 推论与 §9 的 `423` 语义是否还成立。

4. **不沿用产品仓 `file_sync.auto_save_dir` 的明文先例。** 规格 §2.2 的记录是：该设置项存的是用户绝对
   目录路径、明文落盘、**未检索到任何书面非敏感性论证**，并明确“本功能不沿用该先例”，其处置另立工作项。
   也就是说：这里存在一个既存偏差，但它不是许可。以“仓库里已经有人这么干了”为理由把共享根路径写进
   明文 `settings.json`，等于把一个未被论证的偏差扩散成第二个，并同时踩坏第 2 条与第 3 条。

5. **容量上限的唯一权威是 framing 之后的密文尺寸，不是明文尺寸。**
   `EncryptedBlob` 的 JSON 把 `ciphertext` 写成十进制数组：字节值 0–9 占 2 个字符、10–99 占 3 个、
   100–255 占 4 个，均匀分布下平均 **约 3.6 字符/字节**（`(10·2 + 90·3 + 156·4) / 256 ≈ 3.57`）。
   因此若只按明文尺寸设限，一份 ~2.3 MiB 的清单就能产出超过 8 MiB 的落盘文档，`save` 会接受它，
   而 `load` 的截断读取必然报 `CapacityExceeded` —— **白名单在下次重启把自己永久变砖**，且错误文案
   还在指责用户超出容量。这是计划阶段定下的两个常量算术上不自洽所暴露的问题（评审发现，已修）。
   现在：`MAX_ENCRYPTED_SHARE_STORE_BYTES = 8 MiB` 是唯一的持久上限，在 framing 之后、
   **且在创建任何文件之前**检查（被拒的保存不留清单文件也不留临时文件，由
   `save_rejects_a_document_whose_framing_exceeds_the_encrypted_cap` 固定）；
   `MAX_SHARE_STORE_PLAINTEXT_BYTES = 4 MiB` 降级为“密封前挡掉明显离谱清单”的粗筛，不构成承诺。

6. **只有一个最终 `schema_version`，不留中间布局。** `ShareStoreDoc::CURRENT_SCHEMA_VERSION = 1`
   是该功能分支唯一的新格式版本，符合 `docs/design-docs/engineering-principles.md:48`
   （“同一未发布功能分支默认只新增一个最终格式版本；后续切片补全同一目标格式，不得因前一切片已经提交
   而继续增加版本”）。版本门是**双向**的：

   - 读侧 `doc.schema_version != CURRENT` 即 `Corrupt`（`postcard` 只要字节流碰巧解得开就成功，
     不核对会把未来的新布局当 v1 读出错误值）。
   - 写侧**由本层盖戳**，不照抄调用方给的版本：`save` 先克隆清单再置为 `CURRENT`
     （`save_stamps_the_current_schema_version`）。单向门会让一条 `schema_version: 0`（或未来的 2）
     的清单保存成功、下一次读取永久 `Corrupt`——与第 5 条修掉的自我变砖同类。
     这里选择“拨正”而不是“拒绝”：拒绝只能报成 `Corrupt`，而那是在指责调用方的程序错误损坏了 payload。
   - `ShareStoreDoc` 的 `Default` 手写转调 `new()`，因为派生 `Default` 会把版本置 0，
     “先 `default()` 再序列化”就会写出一条谁也读不了的文档。

## 失败模式

| 情形 | 行为 |
| --- | --- |
| Space 锁定 | `load`/`save` 一律 `NotUnlocked`，`save` 不落任何字节（线格式映射 `locked`，规格 §7） |
| `SpaceAccessError::NotInitialized`（空间尚未就绪） | 同 `NotUnlocked`：会随会话稳定自愈，**不得**报成 `Corrupt` |
| 密钥轮换窗口（会话内 `pending_material` 未落地） | 同 `NotUnlocked`（`Internal(NotInitialized)` 归此档） |
| 会话查不到 `ContentKeyId::legacy_v1`（`Internal(KeyNotFound)`） | 同 `NotUnlocked`：描述的是会话状态，不是清单坏了；报成“payload 已损坏”会诱使上层为一份根本没问题的数据端出“重置白名单”入口 |
| 真正的密钥物料故障 | `Corrupt` + 保留 source chain |
| 文件不存在且已解锁 | `Ok(ShareStoreDoc::default())`（空清单即“未共享任何东西”） |
| 密文被篡改一位 | `Corrupt`，保留来源；错误渲染不回显清单文件的绝对路径 |
| 落盘文档超过 8 MiB | 截断读取后即拒，不进入解析，不放大分配 |
| `schema_version` 不是 1 | `Corrupt`（读侧）；写侧由本层盖戳，不产生这种文档 |
| 原子替换（`replace_file`）失败 | 删除临时文件后原样上抛；原清单不受影响 |
| 并发保存 | 临时名带 UUID，两个写入者不互相截断；最终由单次同目录 `rename` 定序 |
| 同机其他用户读临时文件 | unix 下 `.mode(0o600)`（默认 `0o666 & ~umask` 会让整份密文在改名前全局可读） |

瞬态失败与永久故障的这条分界（第 2–4 行）是评审发现的一部分：把“此刻读不到密钥”报成“数据坏了”，
会直接改变 UI 该不该提供重置入口，属于用户可见的错误分类，不只是日志措辞。

## 后果

- **`share_store` 留在 `SpaceAccessPorts`，`confinement` 不在。** 前者的密封密钥确实来自该组的
  唯一一个 `derive_subkey`，与其余成员共享“必须有 Space 会话”这一前提；后者只操作自己注册的根句柄，
  既不读会话也不派生子密钥，因此进独立的 `RemoteSharePorts`（`crates/uc-application/src/deps.rs`）。
  这是同一个决定的两个半边，不要把它们再合并回一个 catch-all 分组。
- 授权判定器因此天然继承这条约束：`SharedRootStoreError::NotUnlocked` 映射为固定原因 `store_locked`
  并 fail-closed 拒绝（`ShareAuthorizer`）。对端在锁屏下得到的是一次拒绝，不是一份可被绕过的清单。
- P1 内 `EncryptedShareStore` 与 `ShareAuthorizer` **都没有生产调用方**：装配只完成注入。
  真实会话下的锁定/解锁端到端行为要到 P5 的路由与 UI 验收才有证据（见“未验证项”）。
  `remote_share` 在 `uc-application` 目前是 `pub(crate) mod`，P2 接 serve 适配器时按
  [ADR-018](018-domain-oriented-application-layout.md) 经 `facade` 暴露，不是把模块重新 `pub`。
- 版本号即兼容责任：`ShareStore` 是新增文档，无历史数据要迁移；后续演进按规格 §15 的
  “未知字段忽略 + 版本递增”，且新增第二个格式版本前必须先满足 `engineering-principles.md:50`
  第 4 条。
- 尺寸上限是可用性风险而非安全边界：规格 §5.1 **没有给共享根条数设上限**，但每条根只落一个绝对路径、
  一个 label 与三个布尔 grant，8 MiB 密文相对这个形状有数个数量级余量。真触发意味着清单已经不合理，
  报 `CapacityExceeded` 是正确的 fail-closed；不要把“8 MiB”读成“可以往里塞几千条根”的承诺。
- **这份文档还有第二份副本：它随整份 profile 一起进 profile-upgrade 备份归档。**
  `crates/uc-infra-profile/src/security/profile_upgrade_backup/inventory.rs` 的 `excluded_paths` 只排除运行期
  产物（锁文件、`daemon.conn`、`EBWebView` 等）与 `logs`/`cache`/`spool` 三个目录，`vault/` 不在排除之列，
  而 `vault_dir` 就是 `<app_data_root>/vault`（`uc-core/src/app_dirs/mod.rs:79`），于是
  `<vault>/share-store-v1.json` 被复制进每一个升级备份归档。本决定原先考虑过 settings、SQLite 与
  `seal_profile_payload` 三条落点，**没有**考虑这第二份副本，故在此补记。判定是**可以接受**而非需要修，
  但接受的理由要摆准：
  - 归档里带走的仍是同一份 AEAD 密文，清单的绝对路径与 label 不以明文出现，因此 I4
    “任何持久介质上不得出现明文路径/label”**没有被打破**（这条只需核对落盘形态，已由
    `paths_and_labels_never_appear_plaintext_on_disk` 固定）。
  - 这份归档本来就是**整份 profile 的全有或全无产物**：SQLite、`settings.json`、`vault/` 里的
    其余状态文件与钥匙串条目（profile KEK、admission/content-vault 密钥、identity store）一并进入
    （`read_secrets` 与 `excluded_paths` 即此范围）。**本功能既没有引入这第二份副本，也没有扩大它的
    敏感半径**——一份能还原整台设备 profile 的归档，多一个同密钥体系下的密文文档不构成质上新的暴露。
    反过来也要如实：本 ADR **没有**核实“归档里是否含有能解开这份清单的 Space 会话密钥材料”，
    那取决于 profile 自身的密钥存放方式，属于这份归档既有范围的问题，不是本功能新增的判断。
  - 因此真正需要确认的不是要不要排除 `vault/`，而是**这份归档的保留与清理策略**——见“未验证项”
    最后一条（P5 条件）。

## 备选方案

- **写进 `settings`（明文）。** 改动面最小，但直接违反 I4 与仓库底线；`auto_save_dir` 是未被论证的
  存量偏差，不构成先例（见“决定”第 4 条）。
- **用 `AdmissionKeyManager::seal_profile_payload`。** 看起来最贴近、代码最少，但锁屏下可读，
  同时作废 MasterKey 底线与“锁定 ⇒ 不可用”约束（见“决定”第 3 条）。
- **按行存进 SQLite 并用 MasterKey 加密列。** 密钥来源与底线相容（同类先例见
  [ADR-013 本地加密索引](013-local-encrypted-search-index.md)），但规格 §5.1 定的形态就是“单个加密文档”，
  设置页对清单的操作是整体读写：无按行查询需求，却要额外背模式版本与迁移责任。
- **只按明文尺寸设容量上限。** 见“决定”第 5 条——它会写出一份自己读不回来的清单。
- **`save` 拒绝非当前 `schema_version`。** 与盖戳等效于修复故障通道，但把一个调用方的程序错误
  报成 payload 损坏（`Corrupt`），错误语义不诚实；选择盖戳。

## 未验证项

- **真实 Space 会话下的锁定/解锁路径**：P1 的三个 `NotUnlocked` 测试都以 `DeriveSpaceSubkeyPort`
  手写替身为前提，装配后的行为（`space_access_adapter` 在真实锁屏时确实返回 `NotUnlocked`）
  只有源码核对，**未实测**，归 P5 路由验收。
- **Windows/macOS 上的文件权限**：`saved_document_is_private_to_the_owner` 是 `#[cfg(unix)]` 门控，
  另两平台上 0o600 语义不存在，临时文件的实际权限**跳过**（未执行）。
- **`save`/`load` 里的同步 `std::fs` 调用**（`replace_file`、`sync_directory`）内联在 `async fn` 中：
  仓库两种先例并存，清单为千字节级、微秒量级，P1 递延，**未做基准测量**。
- **子密钥域分隔**：`SHARE_STORE_SALT`/`INFO`/`PURPOSE` 与全工作区其它 `derive_subkey` 使用点无碰撞，
  是按常量字符串逐一比对得出的（源码核对），非机械验证；新增子密钥域时应重跑这条比对。
- **真实解锁后 `save` 的重启可见性**（掉电/崩溃窗口）：`sync_all` + `sync_directory` 已就位，
  但未做掉电实测，跳过。
- **P5 条件：升级备份归档的保留与清理必须重新确认一次**（“后果”里那条第二份副本带来的唯一实际
  后续动作）。现状核对：`MAX_RETAINED_BACKUPS = 5`（`profile_upgrade_backup/store.rs:32`），
  裁剪函数 `prune_locked`（`store.rs:288`）**只在 security-materials 这一步被调用**——
  `preserve_secrets`（`security_materials.rs:13`）的两条出口各一次（幂等的提前返回 `:34` 与
  正常收尾 `:66`，一次 `prepare` 只会走到其中一条）；归档的创建步骤 `capture`（`store.rs:231`）
  **本身不裁剪**。因此这份上限依赖“同一次 `prepare` 里 capture 之后必定再跑 preserve_secrets”
  这个调用顺序，P5 接共享根管理路由后须确认三件事：① 这份 5 份上限确实生效，清单的密文副本
  不会比 profile 本身活得更久，且要核清“preserve_secrets 失败或被跳过时归档是否会累积”
  （撤销一个共享根后，旧归档里仍留有那条根路径的密文这一事实要被如实告知，不得声称
  “撤销即从所有副本消失”）；
  ② 归档目录 `profile-upgrade-backups/` 自身的权限与位置在三个宿主上都符合日志/缓存那套约定；
  ③ 若届时判定这份副本不可接受，改的是**归档范围**（把 `vault/` 或只把 `share-store-v1.json`
  加进 `excluded_paths`，`inventory.rs:70`），而不是把清单挪出 vault——挪出 vault 会同时作废本
  ADR 的第 1 条与第 3 条。
  本轮**未做**这三条确认（P1 没有任何生产调用方，也就没有真实归档），记为跳过。

## 参考

- 产品仓规格 `docs/specs/2026-10-12-device-file-share-spec.md`：§2.2（`auto_save_dir` 存量偏差）、
  §5.1（数据模型、“不进 settings”、§5.1 推论）、§9（`423 session_locked` 与锁屏放行清单）、
  §12（`locked` 错误码）、§13 I4/I5、§15（版本演进）、§18（本 ADR 的要求来源，产品仓编号 ADR-014）
- [ADR-034：共享根路径约束以 cap-std 为原语](034-share-path-confinement-cap-std.md)——同一功能的约束侧
- [ADR-013：本地加密搜索索引](013-local-encrypted-search-index.md)——MasterKey 子密钥密文落盘的相邻先例
- [ADR-018：Application 按业务领域收口](018-domain-oriented-application-layout.md)——`pub(crate)` 与 P2 的 `facade` 出口
- 执行计划 `docs/exec-plans/active/2026-10-12-device-file-share-phase1.md` 任务 4（实现）、任务 6（授权判定）、任务 7（装配）
- `docs/design-docs/engineering-principles.md:48`（单一最终格式版本）、
  `docs/design-docs/error-handling.md`（保留 source chain；允许丢弃来源的情形）
- `AGENTS.md`「持久化默认密文」与「日志脱敏」底线
