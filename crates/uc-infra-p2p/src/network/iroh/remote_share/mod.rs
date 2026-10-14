//! The `remote-share/1` control-plane iroh adapters (holder side).
//!
//! The serve adapter admits an inbound peer and resolves each [`ShareRequest`]
//! through the application-layer [`RemoteShareServePort`]. The ALPN constant and the
//! wire codec live in `uc_sync_protocol::remote_share`.

pub mod serve_adapter;

pub use serve_adapter::{IrohRemoteShareServeAdapter, IrohRemoteShareServeHandler};
pub use uc_sync_protocol::remote_share::REMOTE_SHARE_ALPN;
