//! The serve-side control-plane port for device file sharing.
//!
//! This is the contract the `remote-share/1` serve adapter (in `uc-infra-p2p`) calls
//! to answer an already-admitted peer's request. The adapter is the boundary that
//! authenticates the peer, decodes the wire frame (`uc-sync-protocol`), calls into this
//! port, and re-encodes the reply. This port is the holder-side decision: it reads the
//! encrypted shared-root store and the cap-std confinement registry, and returns only
//! holder-independent metadata.
//!
//! Layering: the return types here are **domain** types, not wire DTOs. `uc-core` must
//! not depend on `uc-sync-protocol`, so the adapter translates between the wire
//! `ShareReply`/`DenyCode` and this port's [`ShareDirectoryPage`]/[`ShareServeError`]
//! — the same "infra-local mirror kept separate from core types" split as
//! `active_clipboard_state`.
//!
//! Security invariants (spec §5.2, §13):
//! - The holder-local absolute path (`real_path`) never appears in any return type
//!   (spec §13 I2).
//! - Every user-content string field (a root `label`, an entry `name`, the pagination
//!   cursor) has a hand-written `Debug` that redacts it, matching `ShareRoot` and
//!   `ConfinedTarget` (spec §13 I4 / `AGENTS.md:24`).
//! - Denials are opaque and carry no path fragment (spec §6): [`ShareServeError`] is a
//!   payload-free classification enum.

use std::fmt;

use async_trait::async_trait;

use crate::ids::DeviceId;

use super::{ShareGrants, ShareRootId};

/// The holder's availability to serve share requests.
///
/// Maps onto the wire `Hello.state` (spec §5.3). This is a device-level fact, not a
/// per-peer one, so [`RemoteShareServePort::hello`] takes no peer. A store that cannot
/// be read is fail-closed and reports [`ShareAvailability::Locked`], never a partial
/// view (spec §5.2, §13 I5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareAvailability {
    /// The store is readable and the device is in normal service.
    Ok,
    /// The MasterKey is not unlocked, or the store cannot be read; nothing may be
    /// served. Fail-closed.
    Locked,
    /// This build does not implement the share control plane.
    Unsupported,
    /// The device has switched all sharing off (the `suspended` master flag is set).
    Suspended,
}

/// A shared root as it may be advertised to a peer: the opaque id, a label, and the
/// per-root grants.
///
/// The holder-local absolute path is deliberately **not** included (spec §13 I2): a
/// peer may not learn where a root lives on the holder.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareRootDescriptor {
    pub id: ShareRootId,
    pub label: String,
    pub grants: ShareGrants,
    pub enabled: bool,
}

/// Hand-written `Debug`: a derived impl would print `label` verbatim, the same class of
/// leak `8ada11ca` closed for `ShareRoot` (spec §13 I4). The opaque `id` stays visible
/// so a request can be correlated.
impl fmt::Debug for ShareRootDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareRootDescriptor")
            .field("id", &self.id)
            .field("label", &"[REDACTED]")
            .field("grants", &self.grants)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// A single directory entry reported to a peer.
///
/// `name` is the entry's own name (a single component, never a path). It is redacted in
/// `Debug` (spec §13 I4 / `AGENTS.md:24`): file names are user content.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareDirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

/// Hand-written `Debug`: a derived impl would print the entry's file name.
impl fmt::Debug for ShareDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareDirectoryEntry")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .field("modified_at_ms", &self.modified_at_ms)
            .finish()
    }
}

/// One page of a directory listing (spec §8 cursor pagination).
///
/// `next_after` is the cursor for the next page — the last entry's `name` — so it is
/// user content and is redacted in `Debug` too. `entries` defers to
/// [`ShareDirectoryEntry`]'s own redacting `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareDirectoryPage {
    pub entries: Vec<ShareDirectoryEntry>,
    pub next_after: Option<String>,
}

/// Hand-written `Debug`: the cursor is an entry name and must not be printed.
impl fmt::Debug for ShareDirectoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareDirectoryPage")
            .field("entries", &self.entries)
            .field(
                "next_after",
                &self.next_after.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Why a serve operation was denied or failed.
///
/// Maps onto the wire `DenyCode` (spec §5.2 / §6); the mapping is total and lives in
/// the serve adapter. Every variant is an opaque classification with no payload — no
/// path, label, file name, or lower-layer error text (spec §6, §13).
#[derive(Debug, thiserror::Error)]
pub enum ShareServeError {
    /// The store could not be read (space not unlocked / corrupt / over capacity).
    /// Fail-closed.
    #[error("shared roots are unavailable")]
    NotUnlocked,
    /// The peer is not authorized for this root and operation (root unknown or
    /// disabled, or the required grant is missing).
    #[error("operation not authorized")]
    NotAuthorized,
    /// The path (or root) does not resolve to anything the peer may see.
    #[error("path not found")]
    NotFound,
    /// The target is a directory but the operation requires a file.
    #[error("path is a directory")]
    IsADirectory,
    /// The target is a file but the operation requires a directory.
    #[error("path is not a directory")]
    NotADirectory,
    /// The name is a reserved component the peer may not address.
    #[error("name is reserved")]
    ReservedName,
    /// The whole device has sharing switched off.
    #[error("sharing is suspended")]
    Suspended,
    /// The root is authorized but not registered in the confinement registry. The
    /// registry and the store are not kept in sync by either one (see
    /// `ShareConfinementPort`); mapped to `NotFound` on the wire.
    #[error("shared root is unavailable")]
    RootGone,
    /// An I/O failure while reading the confined path.
    #[error("share control plane i/o failure")]
    Io,
}

/// The serve-side control-plane port: answer an already-admitted peer's request with
/// holder-independent metadata.
///
/// The implementer enforces the AND of the two independent facts (spec §5.2, steps
/// 3–6): a store-side authorization **and** a cap-std path confinement, and only when
/// both succeed does it touch the file system. The order is authorize-then-resolve;
/// `resolve` alone does not authorize.
///
/// `hello` is infallible (availability is a device-level state, not an error). The
/// other three return [`ShareServeError`]; an implementer maps every internal failure
/// to one of its variants and never leaks a path fragment.
#[async_trait]
pub trait RemoteShareServePort: Send + Sync {
    /// Report the holder's availability. Fail-closed: an unreadable store is
    /// [`ShareAvailability::Locked`].
    async fn hello(&self) -> ShareAvailability;

    /// List the roots this peer may see (authorized and enabled only; disabled roots
    /// are excluded and the `suspended` flag is reported as
    /// [`ShareServeError::Suspended`]). An empty `Ok(vec![])` means "authorized to see
    /// nothing", which is distinct from [`ShareServeError::NotUnlocked`].
    async fn list_roots(
        &self,
        peer: &DeviceId,
    ) -> Result<Vec<ShareRootDescriptor>, ShareServeError>;

    /// List one directory. `rel` is the path from the root; the empty string means the
    /// root's own top level (served via `resolve_root`, so the root itself is not a
    /// special-cased bypass into `resolve`). `after`/`limit` page the result (spec §8).
    async fn list(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareDirectoryPage, ShareServeError>;

    /// Stat one entry. `rel` is the path from the root; the empty string means the root
    /// itself.
    async fn stat(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareDirectoryEntry, ShareServeError>;
}
