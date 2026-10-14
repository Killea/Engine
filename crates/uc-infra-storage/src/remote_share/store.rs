//! 共享根清单的加密落盘实现。
//!
//! 清单内容是用户内容（绝对路径与 label），因此整份文档先经 AEAD 密封再落盘。
//! 密封密钥由 `DeriveSpaceSubkeyPort` 从 Space 的 MasterKey 派生，Space 未解锁时
//! 派生必然失败，于是白名单在锁定状态下既不可读也不可写——规格 §5.1 有意接受这个约束。
//!
//! 这里刻意不用 `AdmissionKeyManager::seal_profile_payload`（它看起来是最接近的模板）：
//! 那条路径走 profile 级密钥，缺失时自动生成，与解锁状态完全无关。用它写清单会让
//! 白名单在锁定时依然可读，既违反"持久化默认密文必须来自 MasterKey"的底线，也抹掉
//! 规格刻意保留的"锁定 ⇒ 不可用"语义。

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

use uc_core::crypto::model::EncryptionError;
use uc_core::ports::remote_share::{ShareStoreDoc, SharedRootStoreError, SharedRootStorePort};
use uc_core::ports::space::{DeriveSpaceSubkeyPort, SpaceAccessError};

use uc_infra_crypto::{crypto_model::EncryptedBlob, secrets::MasterKey, v1_aead};
use uc_infra_local::fs::durability::{replace_file, sync_directory};

/// 域分隔用的 AAD purpose，与既有 `*_PURPOSE` 常量的成对写法一致。
const SHARE_STORE_PURPOSE: &[u8] = b"uniclipboard/share-store/v1\0";
/// 子密钥派生的 salt 与 info：salt 固定域、info 标版本，两者一起把本清单的密钥
/// 与其它 Space 子密钥（传输元数据、搜索根等）隔离开。
const SHARE_STORE_SALT: &[u8] = b"uniclipboard/share-store/salt/v1\0";
const SHARE_STORE_INFO: &[u8] = b"uniclipboard/share-store/key/v1\0";

/// 密文文档上限。共享根是极小清单，8 MiB 已远超合理值，超出即拒绝（规格 §5.1）。
/// 这是**唯一**的持久上限：读侧用它截断，写侧在 framing 之后用它拒绝。
pub(crate) const MAX_ENCRYPTED_SHARE_STORE_BYTES: usize = 8 * 1024 * 1024;

/// 明文档位**粗筛**：只是在密封前挡掉明显离谱的清单，不是持久上限，也不构成承诺。
/// 落盘规模的权威上限是 [`MAX_ENCRYPTED_SHARE_STORE_BYTES`]，必须在 framing 之后校验：
/// `EncryptedBlob` 的 JSON 把密文写成十进制数组，每个字节平均占约 3.6 个字符
/// （0..9 两个、10..99 三个、100..255 四个），所以只按明文尺寸把关会放行
/// framing 后超限的文档——`save` 成功而下一次 `load` 必然 `CapacityExceeded`。
const MAX_SHARE_STORE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// [`SharedRootStorePort`] 的加密实现：单文件、Space 子密钥、原子覆盖替换。
pub struct EncryptedShareStore {
    subkeys: Arc<dyn DeriveSpaceSubkeyPort>,
    path: PathBuf,
}

impl EncryptedShareStore {
    #[must_use]
    pub fn new(subkeys: Arc<dyn DeriveSpaceSubkeyPort>, path: PathBuf) -> Self {
        Self { subkeys, path }
    }

    /// 取本域专用子密钥。派生字节包在 `Zeroizing` 里，任何提前返回（含
    /// `from_bytes` 失败）都会先清零；装进 `MasterKey` 后由它的 `ZeroizeOnDrop`
    /// 继续负责，不自写密码学也不复制密钥物料。
    async fn subkey(&self) -> Result<MasterKey, SharedRootStoreError> {
        let derived = Zeroizing::new(
            self.subkeys
                .derive_subkey(SHARE_STORE_SALT, SHARE_STORE_INFO)
                .await
                .map_err(map_access_error)?,
        );
        MasterKey::from_bytes(&derived[..]).map_err(|source| SharedRootStoreError::Corrupt {
            // 文案中性：`subkey()` 同时在 `load` 与 `save` 两条路径上被调用，
            // 写成 "load …" 会把一次失败的**保存**报成读取故障。
            source: anyhow::Error::new(source).context("derive share store subkey"),
        })
    }
}

#[async_trait]
impl SharedRootStorePort for EncryptedShareStore {
    async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
        // 先派生子密钥再读盘：若先读盘，"文件不存在"会在锁定状态下也被回答成空清单，
        // 规格 §5.1 的"锁定 ⇒ 不可读"就只剩下有文件的那一半。
        let key = self.subkey().await?;

        let file = match tokio::fs::File::open(&self.path).await {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ShareStoreDoc::default())
            }
            Err(source) => return Err(SharedRootStoreError::Io { source }),
        };

        // 截断读取后再解析，避免超大文件先把内存吃满（规格 §5.1 fail-closed）。
        let mut ciphertext = Vec::new();
        file.take((MAX_ENCRYPTED_SHARE_STORE_BYTES + 1) as u64)
            .read_to_end(&mut ciphertext)
            .await
            .map_err(|source| SharedRootStoreError::Io { source })?;
        if ciphertext.len() > MAX_ENCRYPTED_SHARE_STORE_BYTES {
            return Err(SharedRootStoreError::CapacityExceeded);
        }

        let encrypted: EncryptedBlob = serde_json::from_slice(&ciphertext).map_err(|source| {
            SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("read share store framing"),
            }
        })?;
        encrypted
            .validate_basic()
            .map_err(|source| SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("validate share store framing"),
            })?;

        let plaintext = Zeroizing::new(
            v1_aead::decrypt_blob_xchacha(
                &key,
                &encrypted.nonce,
                &encrypted.ciphertext,
                SHARE_STORE_PURPOSE,
            )
            .map_err(|source| SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("open share store document"),
            })?,
        );

        let doc: ShareStoreDoc =
            postcard::from_bytes(&plaintext).map_err(|source| SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("decode share store document"),
            })?;
        // 必须显式核对版本：`postcard` 只要字节流碰巧解得开就返回成功，不核对就会把
        // 未来的新布局当成 v1 读出错误值（版本契约要写出来，不能靠暗示）。
        if doc.schema_version != ShareStoreDoc::CURRENT_SCHEMA_VERSION {
            // 没有下层错误可保留：这是本层自己做出的版本判定，
            // 失败原因已由 `Corrupt` 分类完整表达（error-handling.md「允许丢弃来源的情形」）。
            return Err(SharedRootStoreError::Corrupt {
                source: anyhow::anyhow!("share store schema version is unsupported"),
            });
        }
        Ok(doc)
    }

    async fn save(&self, doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
        // 未解锁时一个字节也不写：派生失败直接返回 `NotUnlocked`。
        let key = self.subkey().await?;
        // 落盘版本由本层（这份文档唯一的写者）定稿，不接受调用方给的 `schema_version`：
        // `load` 只认 `CURRENT_SCHEMA_VERSION`，于是"写侧接受任意版本"会让一条
        // `schema_version: 0`（或未来的 2）的文档保存成功、下一次读取永久 `Corrupt`——
        // 白名单自己把自己锁死，与刚修掉的尺寸上限是同类的自我变砖。
        // 拨正而不是拒绝：拒绝只能报成 `Corrupt`，而那是在指责调用方的程序错误损坏了
        // payload。清单每根只有一条路径、一个 label 与三个 grant（规格 §5.1 未给根数上限），
        // 一次浅拷贝换掉这条故障通道是值得的；`first_sync_state::mark_flag` 走的是同一做法。
        let mut stamped = doc.clone();
        stamped.schema_version = ShareStoreDoc::CURRENT_SCHEMA_VERSION;
        let plaintext = Zeroizing::new(postcard::to_stdvec(&stamped).map_err(|source| {
            SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("encode share store document"),
            }
        })?);
        if plaintext.len() > MAX_SHARE_STORE_PLAINTEXT_BYTES {
            return Err(SharedRootStoreError::CapacityExceeded);
        }

        let encrypted = v1_aead::encrypt_blob_xchacha(&key, &plaintext, SHARE_STORE_PURPOSE)
            .map_err(|source| SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("seal share store document"),
            })?;
        let ciphertext =
            serde_json::to_vec(&encrypted).map_err(|source| SharedRootStoreError::Corrupt {
                source: anyhow::Error::new(source).context("write share store framing"),
            })?;
        // 持久上限在这里落地：framing 之后、且必须在创建任何文件之前校验。
        // 只靠明文粗筛会漏掉框架放大，写出一份下一次 `load` 直接 `CapacityExceeded`
        // 的文档——白名单自己把自己锁死，而错误文本还在指责用户超出容量。
        if ciphertext.len() > MAX_ENCRYPTED_SHARE_STORE_BYTES {
            return Err(SharedRootStoreError::CapacityExceeded);
        }

        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| SharedRootStoreError::Io { source })?;
        }

        // 临时名带 UUID：同一清单可能被并发保存，固定名会让两个写入者互相截断。
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result: Result<(), SharedRootStoreError> = async {
            let mut options = tokio::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                // 临时文件承载整份密文，是本特性最敏感的产物：默认 0o666 & !umask
                // （通常 0o644/0o664）会让同机其他用户在改名前就读到它。与
                // `profile_backup_archive::private_new_file` 一样压到 0o600；那个 helper
                // 的可见性限于 `security` 子树（`pub(in super::super)`），跨到本模块
                // 需要放宽别人的隐私契约，因此这里就地设置权限，不复制其实现。
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .await
                .map_err(|source| SharedRootStoreError::Io { source })?;
            file.write_all(&ciphertext)
                .await
                .map_err(|source| SharedRootStoreError::Io { source })?;
            file.sync_all()
                .await
                .map_err(|source| SharedRootStoreError::Io { source })?;
            drop(file);
            // 覆盖式改名走 `fs::durability::replace_file`，而不是 `FsAtomicPublisher`
            // 的 no-replace 语义（`rename_no_replace_io` 只存在于 unix，且目标已存在
            // 即失败）：清单本来就要反复覆盖，no-replace 会让第二次保存必然报 Io。
            // 原子性不受影响——同目录改名仍是单次 rename。
            replace_file(&temporary, &self.path)
                .map_err(|source| SharedRootStoreError::Io { source })?;
            if let Some(parent) = self.path.parent() {
                sync_directory(parent).map_err(|source| SharedRootStoreError::Io { source })?;
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result
    }
}

/// 把空间访问失败重分类为存储层分类。
///
/// "底座此刻给不出子密钥"（未解锁、空间尚未就绪、密钥轮换还没落地、会话里查不到
/// 内容密钥）一律映射为 `NotUnlocked`：它们都会随会话稳定自己恢复，线格式对应
/// `locked`（规格 §7）。
/// 只有真正的密钥物料故障才落 `Corrupt`——那是"读到的东西不合法"，会一直坏着。
/// 把前者报成 `Corrupt` 等于用永久损坏的口吻描述一个瞬时状态，会诱使上层为一份
/// 根本没问题的白名单端上"重置"入口。
fn map_access_error(source: SpaceAccessError) -> SharedRootStoreError {
    let not_ready_now = match &source {
        SpaceAccessError::NotUnlocked | SpaceAccessError::NotInitialized => true,
        // 轮换未落地的窗口：`session.rs` 的 `derive_stable_subkey` 在
        // `pending_material.is_some()` 时返回 `EncryptionError::NotInitialized`，
        // `access.rs` 的 `map_encryption_error` 把它包进 `Internal` 透传上来。
        //
        // 会话缺 `legacy_v1` 内容密钥（`EncryptionError::KeyNotFound`）走同一档：它描述的
        // 是会话状态——内容密钥表还没按某个 Space 装好——而不是清单 payload 坏了。生产路径
        // 装表时必然带上 `legacy_v1`（`set_space_key` 直接写入，`install_space_material`
        // 缺它即拒绝安装），所以它一旦出现在 `derive_subkey` 上就意味着会话还没到位，
        // 重新解锁/重绑即可自愈；把它报成"payload 已损坏"与 `NotInitialized` 当初的误标
        // 是同一族错误。
        // 来自本调用路径的 `Internal` 只可能是这两个变体：`derive_stable_subkey` 只读内存里
        // 的会话状态，不碰 keyring、不做 IO。
        SpaceAccessError::Internal(inner) => matches!(
            inner.downcast_ref::<EncryptionError>(),
            Some(EncryptionError::NotInitialized | EncryptionError::KeyNotFound)
        ),
        _ => false,
    };
    if not_ready_now {
        // 丢弃来源的理由（error-handling.md:38-55「允许丢弃来源的情形」）：这些变体都是
        // 底座会话状态的纯校验结果、没有外部失败，`NotUnlocked` 本身不带来源字段，
        // 分类已完整表达"此刻不可用、稍后重试"。
        return SharedRootStoreError::NotUnlocked;
    }
    SharedRootStoreError::Corrupt {
        source: anyhow::Error::new(source).context("share store key material unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use tempfile::TempDir;

    use uc_core::crypto::model::EncryptionError;
    use uc_core::ports::remote_share::{ShareGrants, ShareRoot, ShareRootId, ShareStoreDoc};
    use uc_core::ports::space::{DeriveSpaceSubkeyPort, SpaceAccessError};

    /// 端口替身：仓库习惯是内联手写，不引入 `mockall`。
    struct StubSubkeys {
        unlocked: Mutex<bool>,
    }

    #[async_trait]
    impl DeriveSpaceSubkeyPort for StubSubkeys {
        async fn derive_subkey(
            &self,
            _salt: &[u8],
            _info: &[u8],
        ) -> Result<[u8; 32], SpaceAccessError> {
            if *self.unlocked.lock().expect("stub lock") {
                Ok([0x2a; 32])
            } else {
                Err(SpaceAccessError::NotUnlocked)
            }
        }
    }

    fn sample(path: &str, label: &str) -> ShareRoot {
        ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: path.to_owned(),
            label: label.to_owned(),
            grants: ShareGrants {
                read: true,
                write: false,
                delete: false,
            },
            enabled: true,
            added_at_ms: 1,
        }
    }

    /// 一并返回替身句柄：有的测试需要在运行中途翻转锁状态（"磁盘上已有清单 + 随后锁定"）。
    fn harness(unlocked: bool) -> (EncryptedShareStore, PathBuf, TempDir, Arc<StubSubkeys>) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("share-store-v1.json");
        let subkeys: Arc<StubSubkeys> = Arc::new(StubSubkeys {
            unlocked: Mutex::new(unlocked),
        });
        let port = Arc::clone(&subkeys);
        let store = EncryptedShareStore::new(port, path.clone());
        (store, path, dir, subkeys)
    }

    /// 构造"明文通过粗筛、framing 后必然超过密文上限"的清单夹具。
    /// `EncryptedBlob` 的 JSON 将密文写成十进制数组，每个字节平均占约 3.6 字符
    /// （0..9 两个、10..99 三个、100..255 四个，密文字节近似均匀），
    /// 所以 `target_plaintext_bytes` 取 3 MiB 时文档约 10.7 MiB，而明文仍低于 4 MiB 粗筛。
    fn wide_doc(target_plaintext_bytes: usize) -> ShareStoreDoc {
        const PER_ROOT: usize = 32 * 1024;
        let mut doc = ShareStoreDoc::new();
        for index in 0..(target_plaintext_bytes / PER_ROOT) {
            let path = format!("/home/hank/Downloads/{index}/{}", "p".repeat(PER_ROOT / 2));
            let label = "l".repeat(PER_ROOT / 2);
            doc.roots.push(sample(&path, &label));
        }
        doc
    }

    /// 规格 §5.1 推论：未解锁时白名单必然不可读。
    #[tokio::test]
    async fn load_reports_not_unlocked_when_locked() {
        let (store, _path, _dir, _subkeys) = harness(false);
        assert!(matches!(
            store.load().await,
            Err(SharedRootStoreError::NotUnlocked)
        ));
    }

    /// 规格 §5.1 的另一半：磁盘上已经有清单时，Space 锁定后依然必须读不出来。
    /// 只有"无文件"路径的测试固定不住这一半。
    #[tokio::test]
    async fn existing_document_becomes_unreadable_when_space_locks() {
        let (store, _path, _dir, subkeys) = harness(true);
        store.save(&ShareStoreDoc::new()).await.expect("save");

        *subkeys.unlocked.lock().expect("stub lock") = false;
        assert!(matches!(
            store.load().await,
            Err(SharedRootStoreError::NotUnlocked)
        ));
    }

    /// 未解锁时连"清单不存在"也不回答；写入同样不落任何字节。
    #[tokio::test]
    async fn save_reports_not_unlocked_and_writes_nothing_when_locked() {
        let (store, path, _dir, _subkeys) = harness(false);
        assert!(matches!(
            store.save(&ShareStoreDoc::new()).await,
            Err(SharedRootStoreError::NotUnlocked)
        ));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn missing_file_reads_as_empty_doc() {
        let (store, _path, _dir, _subkeys) = harness(true);
        assert_eq!(store.load().await.expect("load"), ShareStoreDoc::default());
    }

    #[tokio::test]
    async fn round_trips_roots_when_unlocked() {
        let (store, _path, _dir, _subkeys) = harness(true);
        let mut doc = ShareStoreDoc::new();
        doc.roots.push(sample("/home/hank/Downloads", "下载"));
        doc.roots.push(sample("/data/shared", "共享"));

        store.save(&doc).await.expect("save");
        assert_eq!(store.load().await.expect("load"), doc);
    }

    /// 清单是反复覆盖写的：第二次 `save` 必须替换旧文档而不是失败。
    #[tokio::test]
    async fn save_replaces_an_existing_document() {
        let (store, _path, _dir, _subkeys) = harness(true);
        let mut first = ShareStoreDoc::new();
        first.roots.push(sample("/home/hank/Downloads", "下载"));
        store.save(&first).await.expect("first save");

        let mut second = ShareStoreDoc::new();
        second.roots.push(sample("/data/shared", "共享"));
        store.save(&second).await.expect("second save");

        let loaded = store.load().await.expect("load");
        assert_eq!(loaded, second);
        assert_eq!(loaded.roots.len(), 1);
    }

    /// 规格 §13 I4：绝对路径与 label 都不得明文出现在盘上。
    #[tokio::test]
    async fn paths_and_labels_never_appear_plaintext_on_disk() {
        let (store, path, _dir, _subkeys) = harness(true);
        let mut doc = ShareStoreDoc::new();
        doc.roots.push(sample(
            "/home/hank/Must-Never-Leak",
            "Must-Never-Leak-Label",
        ));
        store.save(&doc).await.expect("save");

        let bytes = std::fs::read(&path).expect("read file");
        let as_text = String::from_utf8_lossy(&bytes);
        assert!(
            !as_text.contains("Must-Never-Leak"),
            "密文文档里出现了明文路径或 label"
        );
        assert!(!as_text.contains("/home/hank"));
    }

    /// 篡改一位即 fail closed，且保留来源（error-handling.md:78-84）。
    #[tokio::test]
    async fn tampered_ciphertext_fails_closed_with_source() {
        let (store, path, _dir, _subkeys) = harness(true);
        store.save(&ShareStoreDoc::new()).await.expect("save");

        // 改 `ciphertext` 数组里的一个字节，而不是文件里随手的某个 bit：落在 JSON
        // 结构上时只证明解析器拒绝了坏 framing，证明不了 AEAD 的认证性。
        let bytes = std::fs::read(&path).expect("read");
        let mut framing: serde_json::Value = serde_json::from_slice(&bytes).expect("framing json");
        let ciphertext = framing["ciphertext"]
            .as_array_mut()
            .expect("ciphertext array");
        let replaced = u64::from(ciphertext[0].as_u64().expect("ciphertext byte") == 0);
        ciphertext[0] = serde_json::Value::from(replaced);
        std::fs::write(&path, serde_json::to_vec(&framing).expect("re-encode")).expect("write");

        let error = store.load().await.expect_err("must reject tampering");
        assert!(matches!(error, SharedRootStoreError::Corrupt { .. }));
        assert!(
            std::error::Error::source(&error).is_some(),
            "错误必须保留来源链"
        );
        // 规格 §13 I4：错误渲染也不得带出清单文件的绝对路径。
        let needle = path.to_string_lossy().into_owned();
        assert!(
            !format!("{error:?}").contains(&needle),
            "错误里出现了绝对路径"
        );
    }

    /// 规格 §5.1：读取时先截断再解析，防超大分配。
    #[tokio::test]
    async fn oversized_document_is_rejected_before_decode() {
        let (store, path, _dir, _subkeys) = harness(true);
        std::fs::write(&path, vec![0u8; MAX_ENCRYPTED_SHARE_STORE_BYTES + 1]).expect("write");

        assert!(matches!(
            store.load().await,
            Err(SharedRootStoreError::CapacityExceeded)
        ));
    }

    /// 持久上限的唯一权威是密文框架后的那条检查：只校验明文档位会放行 framing 后超限
    /// 的文档（JSON 十进制数组把每字节平均放大到约 3.6 字符），于是 `save` 成功、
    /// 下一次 `load` 必然 `CapacityExceeded`——白名单自己把自己锁死，还反过来指责用户。
    #[tokio::test]
    async fn save_rejects_a_document_whose_framing_exceeds_the_encrypted_cap() {
        let (store, path, dir, _subkeys) = harness(true);
        let doc = wide_doc(3 * 1024 * 1024);

        // 夹具必须确实通过明文粗筛，否则这条测试只是在重复明文上限那条检查。
        let plaintext = postcard::to_stdvec(&doc).expect("encode fixture");
        assert!(
            plaintext.len() <= MAX_SHARE_STORE_PLAINTEXT_BYTES,
            "夹具应通过明文粗筛，从而证明拒绝来自 framing 之后的上限"
        );

        assert!(matches!(
            store.save(&doc).await,
            Err(SharedRootStoreError::CapacityExceeded)
        ));
        assert!(!path.exists(), "被拒绝的保存不得留下清单文件");
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("read dir").count(),
            0,
            "被拒绝的保存不得留下临时文件"
        );
    }

    /// 临时文件与最终文档都承载整份密文，是全特性最敏感的产物：默认 0o666 & !umask
    /// （通常 0o644）会让同机其他用户在改名前就读到它。
    #[cfg(unix)]
    #[tokio::test]
    async fn saved_document_is_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let (store, path, _dir, _subkeys) = harness(true);
        store.save(&ShareStoreDoc::new()).await.expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        // 只断言**真实保证**：除属主之外任何人都不可读写执行。
        // 原先写成 `mode & 0o777 == 0o600`，在剥掉属主位的敌意 umask 下会假失败——
        // 那种 umask 并不违反本条不变量（文件甚至更安全），断言却把它读成回归。
        assert_eq!(mode & 0o077, 0, "密文文档不应对同组与其他用户开放任何权限");
    }

    /// 读取必须显式核对 `schema_version`：`postcard` 只要字节流碰巧解得开就返回成功，
    /// 不核对就会把未来的新布局当成 v1 读出错误值。
    #[tokio::test]
    async fn future_schema_version_is_refused_on_load() {
        let (store, path, _dir, _subkeys) = harness(true);
        let key = store.subkey().await.expect("subkey");
        let mut doc = ShareStoreDoc::new();
        doc.schema_version = ShareStoreDoc::CURRENT_SCHEMA_VERSION + 1;

        let plaintext = postcard::to_stdvec(&doc).expect("encode future doc");
        let encrypted =
            v1_aead::encrypt_blob_xchacha(&key, &plaintext, SHARE_STORE_PURPOSE).expect("seal");
        std::fs::write(
            &path,
            serde_json::to_vec(&encrypted).expect("encode framing"),
        )
        .expect("write");

        let error = store.load().await.expect_err("must refuse a future schema");
        assert!(matches!(error, SharedRootStoreError::Corrupt { .. }));
        assert!(
            std::error::Error::source(&error).is_some(),
            "错误必须保留来源链"
        );
    }

    /// 版本门必须是双向的：`load` 用 `!=` 拒绝非当前版本，`save` 也必须只有一个可写版本。
    /// 否则调用方递来 `schema_version: 0`（或未来的 2）的清单会得到一次成功的保存，
    /// 下一次读取却永久 `Corrupt`——与尺寸上限那条刚堵掉的自我变砖同类。
    #[tokio::test]
    async fn save_stamps_the_current_schema_version() {
        for foreign_version in [0, ShareStoreDoc::CURRENT_SCHEMA_VERSION + 1] {
            let (store, _path, _dir, _subkeys) = harness(true);
            let mut doc = ShareStoreDoc::new();
            doc.schema_version = foreign_version;
            doc.roots.push(sample("/home/hank/Downloads", "下载"));

            store.save(&doc).await.expect("save a foreign version");

            let loaded = store.load().await.expect("readback must stay readable");
            assert_eq!(
                loaded.schema_version,
                ShareStoreDoc::CURRENT_SCHEMA_VERSION,
                "落盘版本必须由本层定稿，而不是照抄调用方给的 {foreign_version}"
            );
            assert_eq!(loaded.roots, doc.roots, "拨正版本不得改动清单内容");
        }
    }

    /// 密钥轮换尚未落地之类的瞬时窗口（`session.rs` 的 `derive_stable_subkey` 在
    /// `pending_material.is_some()` 时返回 `EncryptionError::NotInitialized`）会自己恢复，
    /// 不得报成"payload 已损坏"，否则上层会据此给出一份根本没问题数据的"重置白名单"入口。
    #[test]
    fn transient_key_unavailability_is_not_reported_as_corrupt() {
        for source in [
            SpaceAccessError::NotInitialized,
            SpaceAccessError::Internal(Box::new(EncryptionError::NotInitialized)),
            // 会话查不到 `legacy_v1` 内容密钥同样是会话状态故障，不是清单坏了。
            SpaceAccessError::Internal(Box::new(EncryptionError::KeyNotFound)),
        ] {
            assert!(
                matches!(map_access_error(source), SharedRootStoreError::NotUnlocked),
                "瞬时未就绪状态必须映射为 NotUnlocked"
            );
        }

        // 真正的密钥物料故障仍是 Corrupt，并保留来源链。
        let error = map_access_error(SpaceAccessError::corrupted_key_material());
        assert!(matches!(error, SharedRootStoreError::Corrupt { .. }));
        assert!(
            std::error::Error::source(&error).is_some(),
            "错误必须保留来源链"
        );
    }

    /// 失败的改名不得留下半截临时文件。
    #[tokio::test]
    async fn failed_save_leaves_no_temporary_file() {
        let dir = TempDir::new().expect("tempdir");
        // 目标是目录：改名必然失败，用来验证清理路径。
        let path = dir.path().join("share-store-v1.json");
        std::fs::create_dir(&path).expect("occupy the destination with a directory");
        let subkeys = Arc::new(StubSubkeys {
            unlocked: Mutex::new(true),
        });
        let store = EncryptedShareStore::new(subkeys, path);

        assert!(matches!(
            store.save(&ShareStoreDoc::new()).await,
            Err(SharedRootStoreError::Io { .. })
        ));
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(leftovers.len(), 1, "除目标目录外不应留下任何条目");
    }
}
