//! 设备文件共享的 Application 侧流程：fail-closed 授权判定与 serve 处理器。
//!
//! `ShareAuthorizer` 与 `SharePermit` 保持 `pub(crate)`，对外只经 `facade` 暴露
//! （ADR-018）；`RemoteShareFacade` 是授权判定的唯一消费入口。`RemoteShareServe` 实现
//! `RemoteShareServePort`（`uc-core`），是 P2 serve 适配器的处理器入口：它把授权判定与
//! cap-std 路径约束两个事实合取，成功后才以环境权限读取元数据。

pub(crate) mod authorizer;
pub(crate) mod facade;
pub(crate) mod serve_handler;

pub use authorizer::SharePermit;
pub use facade::{RemoteShareFacade, RemoteShareFacadeDeps};
pub use serve_handler::{RemoteShareServe, RemoteShareServeDeps};
