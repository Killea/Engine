//! Application-layer workflows for UniClipboard.
//!
//! ADR-018: external crates only import `uc_application::facade` (the
//! business entry whitelist) and `uc_application::deps` (passive assembly
//! groupings). Everything else is `pub(crate)`.

pub(crate) mod application;
pub mod deps;
pub(crate) mod error;
pub mod facade;
pub(crate) mod profile;
pub(crate) mod runtime_lifecycle;

pub(crate) mod clipboard;
pub(crate) mod device;
// ADR-018：crate 根只公开 `facade` 与 `deps`，本模块保持 `pub(crate)`；对外入口经
// `facade::remote_share::RemoteShareFacade` 暴露（facade 消费 `ShareAuthorizer`）。
pub(crate) mod remote_share;
pub(crate) mod search;
pub(crate) mod settings;
pub(crate) mod space;
pub(crate) mod support;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod transfer;
