//! 共享根清单的读写端口。
//!
//! 清单是用户内容（绝对路径与 label），因此实现必须整体经 MasterKey 派生的
//! 子密钥加密后落盘（规格 §5.1、AGENTS.md「持久化默认密文」）。

use async_trait::async_trait;

use super::ShareStoreDoc;

#[derive(Debug, thiserror::Error)]
pub enum SharedRootStoreError {
    /// Space 未解锁，子密钥不可派生。映射到线格式 `locked`（规格 §7）。
    ///
    /// 无 `#[source]`：这是对底座锁状态的纯重分类，下层同样是纯校验、没有外部
    /// 失败，属于 `docs/design-docs/error-handling.md:44` 允许丢弃来源的情形；
    /// 任务 4 的 `map_access_error` 在丢弃点按同一条例外注明理由。
    #[error("space not unlocked; shared roots are unavailable")]
    NotUnlocked,
    #[error("shared-root store io failure")]
    Io {
        #[source]
        source: std::io::Error,
    },
    #[error("shared-root store payload is corrupt")]
    Corrupt {
        #[source]
        source: anyhow::Error,
    },
    /// 超出容量上限即拒绝，不截断后继续解析（规格 §5.1，fail-closed）。
    /// `load()` 与 `save()` 共用本变体：读取时清单超限直接报错，写入超限同样拒绝。
    #[error("shared-root store exceeded its capacity")]
    CapacityExceeded,
}

/// 共享根清单的读写。实现负责 MasterKey 子密钥加密与原子替换。
#[async_trait]
pub trait SharedRootStorePort: Send + Sync {
    async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError>;
    async fn save(&self, doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError>;
}
