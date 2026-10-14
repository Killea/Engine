//! 设备文件共享的 Application 侧流程：fail-closed 授权判定。
//!
//! `ShareAuthorizer` 与 `SharePermit` 保持 `pub(crate)`，对外只经 `facade` 暴露
//! （ADR-018）；`RemoteShareFacade` 是 P2 serve 适配器的唯一消费入口。

pub(crate) mod authorizer;
pub(crate) mod facade;

pub use authorizer::SharePermit;
pub use facade::{RemoteShareFacade, RemoteShareFacadeDeps};
