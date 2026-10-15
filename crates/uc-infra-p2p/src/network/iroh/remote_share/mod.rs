//! The `remote-share/1` control-plane iroh adapters.
//!
//! The serve adapter admits an inbound peer and resolves each [`ShareRequest`]
//! through the application-layer [`RemoteShareServePort`]; the client adapter
//! dials an admitted peer and turns each domain op into one request → reply
//! exchange. The ALPN constant and the wire codec live in
//! `uc_sync_protocol::remote_share`.

pub mod client_adapter;
pub mod serve_adapter;

pub use client_adapter::IrohRemoteShareClientAdapter;
pub use serve_adapter::{IrohRemoteShareServeAdapter, IrohRemoteShareServeHandler};
pub use uc_sync_protocol::remote_share::REMOTE_SHARE_ALPN;
