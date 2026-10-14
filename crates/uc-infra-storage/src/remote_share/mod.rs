//! 设备文件共享的 infra 侧加密落盘实现：共享根清单的 AEAD 密封存储。

mod store;

pub use store::EncryptedShareStore;
