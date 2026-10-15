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
use crate::ports::blob::BlobTicket;

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
    /// The entry is a symlink. Such entries are honest parts of the listing but
    /// cannot be addressed by any path operation (the confinement layer denies
    /// every symlink leaf), so clients should render them as inert.
    pub is_symlink: bool,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

/// Hand-written `Debug`: a derived impl would print the entry's file name.
impl fmt::Debug for ShareDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareDirectoryEntry")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("is_symlink", &self.is_symlink)
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
/// Maps onto the wire `DenyCode` (spec §5.2 / §6 / §12); the mapping is total and
/// lives in the serve adapter. Every variant is an opaque classification with no
/// payload — no path, label, file name, or lower-layer error text (spec §6, §13).
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
    /// The root is authorized but not registered in the confinement registry, or the
    /// root directory was moved/replaced on disk since registration.
    #[error("shared root is unavailable")]
    RootGone,
    /// The destination name already exists where the operation required a new name.
    #[error("destination already exists")]
    Conflict,
    /// The operation or request shape is not supported by this build/peer.
    #[error("request not supported")]
    UnsupportedRequest,
    /// A staging session or transfer does not exist (unknown id, or peer mismatch).
    /// Surfaced as `NotFound` on the wire.
    #[error("staging session not found")]
    StagingNotFound,
    /// The staged set exceeds a count/size bound (`too_many_entries` / `too_large`).
    #[error("transfer exceeds the configured limit")]
    TooLarge,
    /// The operation arrived after the point it could still be honoured
    /// (e.g. cancel after the upload was already committed).
    #[error("operation arrived too late")]
    TooLate,
    /// An I/O failure while serving the request.
    #[error("share control plane i/o failure")]
    Io,
}

/// One entry in the holder's recycle directory (`ListTrash`).
///
/// `original_rel` is the entry's former relative path inside the shared root —
/// relative only, and inside the authorized namespace (spec §7, §13 I2).
/// `trash_id` is the kernel-issued opaque name used by `Restore`.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareTrashEntry {
    pub trash_id: String,
    pub original_rel: String,
    pub deleted_at_ms: i64,
    pub is_dir: bool,
    pub size_bytes: u64,
}

/// Hand-written `Debug`: `original_rel` is user content.
impl fmt::Debug for ShareTrashEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareTrashEntry")
            .field("trash_id", &self.trash_id)
            .field("original_rel", &"[REDACTED]")
            .field("deleted_at_ms", &self.deleted_at_ms)
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

/// One page of the recycle listing.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareTrashPage {
    pub entries: Vec<ShareTrashEntry>,
    pub next_after: Option<String>,
}

/// Hand-written `Debug`: the cursor is an opaque `trash_id`, shown for correlation.
impl fmt::Debug for ShareTrashPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareTrashPage")
            .field("entries", &self.entries)
            .field("next_after", &self.next_after)
            .finish()
    }
}

/// One manifest item of a `StageUpload` request, after wire decoding.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareStageEntry {
    /// Relative path inside the staging set (and later inside `dir`).
    pub rel: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    /// The fetch credential the uploader issued for this entry's content.
    /// `Some` for every file entry; `None` for directories, which carry no
    /// bytes and are materialised at stage time.
    pub ticket: Option<BlobTicket>,
}

/// Hand-written `Debug`: `rel` is user content and `ticket` embeds a peer
/// address + digest — neither may reach a log line.
impl fmt::Debug for ShareStageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareStageEntry")
            .field("rel", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .field("ticket", &"[REDACTED]")
            .finish()
    }
}

/// One upload task's progress-correlation key.
///
/// The 16 bytes the uploader chose in `StageUpload`; the holder reports its
/// blob-pull progress under this key so the uploader's task tracker can attach
/// it to the parent transfer (spec §8.1 step 4, §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareTransferId([u8; 16]);

impl ShareTransferId {
    /// Wrap the raw 16 bytes from the wire.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// The raw bytes back onto the wire.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    /// The UUID-string form the `OutboundProgressReporterPort` correlation key
    /// expects — the same 16 bytes in canonical `8-4-4-4-12` spelling.
    pub fn as_uuid_string(&self) -> String {
        uuid::Uuid::from_bytes(self.0).to_string()
    }
}

/// The outcome of `StageUpload`: the kernel-issued staging id the client
/// addresses with `CommitUpload`/`AbortUpload`.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareStageOutcome {
    pub staging_id: String,
}

/// Hand-written `Debug`: the id is kernel-issued and opaque, safe to print.
impl fmt::Debug for ShareStageOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareStageOutcome")
            .field("staging_id", &self.staging_id)
            .finish()
    }
}

/// The outcome of `Export`: the fetch ticket + announced size the peer pulls
/// the blob with. The published bytes stay pinned under a
/// `TagReason::RemoteShareExport` lease until it expires, so the peer may fetch
/// lazily after the control-plane reply.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareExportOutcome {
    pub ticket: BlobTicket,
    pub size_bytes: u64,
}

/// Hand-written `Debug`: the ticket embeds a peer address + digest.
impl fmt::Debug for ShareExportOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareExportOutcome")
            .field("ticket", &"[REDACTED]")
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
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

    /// Create a directory at `rel` (requires `write`). The leaf must not already
    /// exist (`Conflict`); missing intermediate dirs are `NotFound`.
    async fn mkdir(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<(), ShareServeError>;

    /// Move `from` to `to` inside the same root (requires `write` + `delete`,
    /// spec §5.2). `to` existing is `Conflict`; moving the root itself is denied.
    async fn rename(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), ShareServeError>;

    /// Move `rel` into the root's recycle directory (requires `delete`) and
    /// return the kernel-issued `trash_id` the `restore` op takes as its
    /// handle. Deleting the root itself is denied.
    async fn delete(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<String, ShareServeError>;

    /// Copy `from` to `to` inside the same root (requires `write`). Directories
    /// copy recursively; symlink entries inside a copied tree are skipped.
    /// `to` existing is `Conflict`.
    async fn copy_within(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), ShareServeError>;

    /// Page through the root's recycle directory (requires `delete` — the recycle
    /// namespace is unreachable without it). `after`/`limit` page by `trash_id`.
    async fn list_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareTrashPage, ShareServeError>;

    /// Move a recycled entry back to `to` (requires `write` + `delete` — the entry
    /// leaves the holder-controlled namespace). Name collisions auto-rename.
    async fn restore(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        trash_id: &str,
        to: &str,
    ) -> Result<(), ShareServeError>;

    /// Permanently empty the root's recycle directory (requires `delete`).
    async fn empty_trash(&self, peer: &DeviceId, root: ShareRootId) -> Result<(), ShareServeError>;

    /// Open a staging set under `dir` and register a manifest slice
    /// (requires `write`). The holder immediately begins pulling every file
    /// entry's `ticket` into the staging area and reports its pull progress
    /// under `transfer_id` on the progress back-channel (spec §8.1 step 4).
    /// Returns the kernel-issued `staging_id`. May be called repeatedly; one
    /// upload task may accumulate several `staging_id`s (the request-size cap
    /// bounds one manifest slice).
    async fn stage_upload(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dir: &str,
        entries: &[ShareStageEntry],
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, ShareServeError>;

    /// Commit previously staged sets into their target dirs (requires `write`
    /// per set; the staging session remembers its own root/dir/peer). Unknown or
    /// foreign `staging_id`s are `StagingNotFound`. The call waits for any
    /// still-in-flight fetches of the set to settle, then lands every staged
    /// entry atomically; a failed fetch fails the commit and discards the set.
    async fn commit_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), ShareServeError>;

    /// Discard staged sets (requires `write` per set). Unknown ids are ignored —
    /// abort is idempotent so a cancelled upload can always be cleaned up.
    async fn abort_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), ShareServeError>;

    /// Publish `rel` as a blob (requires `read`): the verified, no-follow file
    /// handle is streamed into the local blob store under a pinned export
    /// lease, and the fetch ticket + announced size come back for the peer to
    /// pull with (spec §8.2 step 1).
    async fn export(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareExportOutcome, ShareServeError>;
}
