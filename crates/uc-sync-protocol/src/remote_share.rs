//! Wire codec for the `remote-share/1` control-plane protocol.
//!
//! This is a metadata-only request/reply exchange on one bi-stream: the client
//! (the viewer) asks the holder (the machine whose files are being shared) for
//! the authorized-root whitelist, directory pages, entry metadata, mutations,
//! recycle-directory operations, and upload staging. **No bulk bytes travel
//! here** — file content goes over the separate iroh-blobs path, and absolute
//! paths **never** appear in a frame (spec §13 I2). The holder keeps each
//! root's absolute path local; the client only ever sees an opaque `root_id`,
//! a user-facing label, and relative entry names.
//!
//! Frame layout (identical in both directions):
//!
//! ```text
//! [magic(4) = "UCRS" | version(1) | kind(1) | body_len(4, big-endian) | body]
//! ```
//!
//! * `body` is `postcard(u32 opcode)` followed by the `postcard`-encoded
//!   payload struct of that op — a [`ShareRequest`] body when `kind` is
//!   [`FrameKind::Request`], a [`ShareReply`] body when it is
//!   [`FrameKind::Reply`]. Ops with no fields encode the opcode alone.
//! * An opcode the receiver does not know decodes as
//!   `Unknown { opcode }` **instead of failing**, so the holder can answer
//!   `Denied { UnsupportedRequest }` rather than dropping the stream
//!   (spec §15: new ops are always backward compatible; a breaking frame
//!   change must bump the ALPN version, not this table).
//! * `body_len` is checked against the per-direction cap (see
//!   [`REQUEST_LIMIT`] / [`REPLY_LIMIT`]) **before** the body buffer is
//!   allocated, so a hostile peer cannot ask us to allocate an unbounded
//!   buffer ([`read_raw_with_limit`]).
//! * Capability advertising needs no separate frame: the ALPN itself is the
//!   advertisement (QUIC ALPN negotiation). A peer that does not accept
//!   [`REMOTE_SHARE_ALPN`] simply fails the handshake, which the client maps to
//!   its unreachable error.

use std::fmt;
use std::future::Future;
use std::io;
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ============================================================================
// Constants
// ============================================================================

/// ALPN for the remote-share control plane. Brand-new feature, so it starts at
/// `/1`; future breaking frame changes bump the version and keep this as a
/// legacy sibling, never reuse the string for a different frame shape.
pub const REMOTE_SHARE_ALPN: &[u8] = b"uniclipboard/remote-share/1";

/// 4-byte magic at the head of every frame. A distinct sentinel so bytes
/// arriving on a mis-routed ALPN are rejected before anything is allocated.
const WIRE_MAGIC: [u8; 4] = *b"UCRS";

/// Wire format version. Only `1` exists; anything else is a hard header error.
const WIRE_VERSION: u8 = 1;

/// `magic(4) + version(1) + kind(1) + body_len(4)`.
const HEADER_LEN: usize = 10;

/// Hard cap on a request body (64 KiB). A request is an op plus a small fixed
/// set of strings/ids (paths, cursors, a staging manifest); 64 KiB is generous
/// headroom over any legitimate request and bounds what a hostile peer can
/// make us allocate.
pub const REQUEST_LIMIT: usize = 64 * 1024;

/// Hard cap on a reply body (2 MiB). A paginated directory listing plus the
/// root whitelist fit well under this; the cap bounds the allocation on the
/// reading side.
pub const REPLY_LIMIT: usize = 2 * 1024 * 1024;

/// Per-IO deadline so a stalled peer cannot pin a serve task indefinitely.
pub const IO_DEADLINE: Duration = Duration::from_secs(30);

/// A share-root id on the wire: the 16 raw UUID bytes of
/// `uc_core::ports::remote_share::ShareRootId`. Opaque to both sides; the
/// holder resolves it to a registered root, the client never learns its value
/// is a UUID.
pub type WireShareRootId = [u8; 16];

// ============================================================================
// Frame kind
// ============================================================================

/// The one-byte `kind` field of the frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// A client -> holder request ([`ShareRequest`]).
    Request,
    /// A holder -> client reply ([`ShareReply`]).
    Reply,
}

impl FrameKind {
    const REQUEST: u8 = 1;
    const REPLY: u8 = 2;

    fn as_u8(self) -> u8 {
        match self {
            FrameKind::Request => Self::REQUEST,
            FrameKind::Reply => Self::REPLY,
        }
    }

    fn from_u8(value: u8) -> Result<Self, ShareWireError> {
        match value {
            Self::REQUEST => Ok(FrameKind::Request),
            Self::REPLY => Ok(FrameKind::Reply),
            _ => Err(ShareWireError::UnknownKind { got: value }),
        }
    }
}

// ============================================================================
// Opcodes
// ============================================================================

/// Request opcodes (`kind = Request`). Append-only within this ALPN version:
/// never renumber, never reuse a retired number — an op the holder does not
/// know must decode as `Unknown` so it can be answered, not dropped.
mod req_op {
    pub(super) const HELLO: u32 = 1;
    pub(super) const LIST_ROOTS: u32 = 2;
    pub(super) const LIST: u32 = 3;
    pub(super) const STAT: u32 = 4;
    pub(super) const MKDIR: u32 = 5;
    pub(super) const RENAME: u32 = 6;
    pub(super) const DELETE: u32 = 7;
    pub(super) const LIST_TRASH: u32 = 8;
    pub(super) const RESTORE: u32 = 9;
    pub(super) const EMPTY_TRASH: u32 = 10;
    pub(super) const COPY_WITHIN: u32 = 11;
    pub(super) const STAGE_UPLOAD: u32 = 12;
    pub(super) const COMMIT_UPLOAD: u32 = 13;
    pub(super) const ABORT_UPLOAD: u32 = 14;
    pub(super) const EXPORT: u32 = 15;
}

/// Reply opcodes (`kind = Reply`), a namespace separate from requests.
/// Same append-only rule as `req_op`.
mod rep_op {
    pub(super) const HELLO: u32 = 1;
    pub(super) const ROOTS: u32 = 2;
    pub(super) const ENTRIES: u32 = 3;
    pub(super) const ENTRY: u32 = 4;
    pub(super) const ACK: u32 = 5;
    pub(super) const STAGED: u32 = 6;
    pub(super) const DELETED: u32 = 7;
    pub(super) const TRASH_ENTRIES: u32 = 8;
    pub(super) const EXPORTED: u32 = 9;
    pub(super) const DENIED: u32 = 10;
}

// ============================================================================
// Wire DTOs
// ============================================================================

/// Per-root grant set as the holder advertises it (mirrors `ShareGrants`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireShareGrants {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

/// One authorized share root, as the holder advertises it to an admitted peer.
///
/// The holder's absolute `path` is deliberately **absent**: it never crosses
/// the wire (spec §13 I2). `label` is user content the peer shows in its
/// directory browser.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireShareRoot {
    pub id: WireShareRootId,
    pub label: String,
    pub grants: WireShareGrants,
    pub enabled: bool,
}

/// Hand-written `Debug`: `label` is user content and must never reach a log
/// line, consistent with `ShareRoot` in `uc-core`.
impl fmt::Debug for WireShareRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireShareRoot")
            .field("id", &self.id)
            .field("label", &"[REDACTED]")
            .field("grants", &self.grants)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// One entry in a directory listing, or the single result of a `Stat`.
///
/// `name` is the entry's basename (relative to the listed directory), never an
/// absolute path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDirectoryEntry {
    pub name: String,
    pub is_dir: bool,
    /// The entry is a symlink. It is listed honestly but cannot be addressed by any
    /// path operation (the confinement layer denies symlink leaves), so clients
    /// should render it inert.
    pub is_symlink: bool,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

/// Hand-written `Debug`: `name` is a filename and must never reach a log line.
impl fmt::Debug for WireDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireDirectoryEntry")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("is_symlink", &self.is_symlink)
            .field("size_bytes", &self.size_bytes)
            .field("modified_at_ms", &self.modified_at_ms)
            .finish()
    }
}

/// One entry in the holder's recycle directory, as `ListTrash` reports it.
///
/// `trash_id` is the opaque restore handle the holder issued on `Delete`;
/// `original_path` is the root-relative path the entry had when deleted (the
/// client's default restore destination), never an absolute path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTrashEntry {
    pub trash_id: String,
    pub original_path: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub deleted_at_ms: i64,
}

/// Hand-written `Debug`: `original_path` is a path fragment and must never
/// reach a log line.
impl fmt::Debug for WireTrashEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireTrashEntry")
            .field("trash_id", &self.trash_id)
            .field("original_path", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .field("deleted_at_ms", &self.deleted_at_ms)
            .finish()
    }
}

/// One manifest entry of a `StageUpload` request: a file or directory whose
/// content the holder pulls by blob ticket before `CommitUpload`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireStageEntry {
    /// Root-relative destination path of this entry once committed.
    pub rel: String,
    pub is_dir: bool,
    /// Declared content size in bytes (`0` for directories); the holder's
    /// commit re-checks every staged file against it.
    pub size_bytes: u64,
    /// Serialized `BlobTicket`: the fetch credential the holder pulls this
    /// entry's content with. Empty for directory entries, which carry no
    /// bytes. Opaque to this codec.
    pub ticket: Vec<u8>,
}

/// Hand-written `Debug`: `rel` is a path fragment and `ticket` embeds a peer
/// address + content digest — neither may reach a log line.
impl fmt::Debug for WireStageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireStageEntry")
            .field("rel", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .field("ticket", &"[REDACTED]")
            .finish()
    }
}

/// States a `Hello` reply reports about the feature right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloState {
    /// Unlocked and the feature is active; the other ops will answer.
    Ok,
    /// The holder's session is locked, so no share root can be read.
    Locked,
    /// The holder does not support this protocol shape (forward/legacy compat).
    Unsupported,
    /// The holder has the feature suspended (master switch off).
    Suspended,
}

/// Denial code for a request the holder refused, covering the whole spec §12
/// set. **Variant order is the wire discriminant** (postcard encodes the
/// variant index): append only, never reorder, never reuse.
///
/// `Locked`/`Suspended` map to the same "nothing to show" UI state as the
/// `Hello` locked/suspended replies; the rest are per-path or per-op failures
/// the client can surface next to the affected entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyCode {
    /// The holder's session is locked.
    Locked,
    /// The holder does not implement the feature at all.
    Unsupported,
    /// The opcode or request shape is not supported by this build.
    UnsupportedRequest,
    /// The feature is suspended (master switch off).
    Suspended,
    /// The peer's admission was revoked after connecting.
    Revoked,
    /// The admitted peer is not authorized for this root / operation, or the
    /// target exists with a type the verb cannot act on.
    Denied,
    /// A path component collides with a reserved name.
    ReservedName,
    /// No such root, entry, trash id, or staging id.
    NotFound,
    /// The destination name already exists where a fresh name was required.
    Conflict,
    /// The registered root vanished or was replaced underneath the holder.
    RootGone,
    /// The operation exceeds a configured quota.
    Quota,
    /// The staged set or transfer exceeds a configured count/size bound.
    TooLarge,
    /// A directory page or manifest exceeds the entry-count bound.
    TooManyEntries,
    /// The holder hit a local I/O failure while serving the request.
    Io,
    /// The transfer was cancelled by the peer or the holder.
    Cancelled,
    /// The operation arrived after the point it could still be honoured
    /// (e.g. cancel after commit).
    TooLate,
    /// The exchange was interrupted (transport reset, holder shutdown).
    Interrupted,
}

// ============================================================================
// Payload structs (postcard-encoded after the opcode)
// ============================================================================

#[derive(Serialize, Deserialize)]
struct ListPayload {
    root_id: WireShareRootId,
    path: String,
    after: Option<String>,
    limit: u32,
}

/// Shared shape of every `root_id + single path` request (Stat/Mkdir/Delete/
/// Export).
#[derive(Serialize, Deserialize)]
struct PathPayload {
    root_id: WireShareRootId,
    path: String,
}

/// Shared shape of the two same-root move ops (Rename/CopyWithin).
#[derive(Serialize, Deserialize)]
struct MovePayload {
    root_id: WireShareRootId,
    from: String,
    to: String,
}

#[derive(Serialize, Deserialize)]
struct TrashPagePayload {
    root_id: WireShareRootId,
    after: Option<String>,
    limit: u32,
}

#[derive(Serialize, Deserialize)]
struct RestorePayload {
    root_id: WireShareRootId,
    trash_id: String,
    to: String,
}

/// Shared shape of every `root_id`-only request (EmptyTrash today).
#[derive(Serialize, Deserialize)]
struct RootPayload {
    root_id: WireShareRootId,
}

#[derive(Serialize, Deserialize)]
struct StageUploadPayload {
    root_id: WireShareRootId,
    dir: String,
    transfer_id: [u8; 16],
    entries: Vec<WireStageEntry>,
}

/// Shared shape of CommitUpload/AbortUpload.
#[derive(Serialize, Deserialize)]
struct StagingIdsPayload {
    staging_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct HelloPayload {
    state: HelloState,
}

#[derive(Serialize, Deserialize)]
struct RootsPayload {
    roots: Vec<WireShareRoot>,
}

#[derive(Serialize, Deserialize)]
struct EntriesPayload {
    entries: Vec<WireDirectoryEntry>,
    next_after: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EntryPayload {
    entry: WireDirectoryEntry,
}

#[derive(Serialize, Deserialize)]
struct StagedPayload {
    staging_id: String,
}

#[derive(Serialize, Deserialize)]
struct DeletedPayload {
    trash_id: String,
}

#[derive(Serialize, Deserialize)]
struct TrashEntriesPayload {
    entries: Vec<WireTrashEntry>,
    next_after: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ExportedPayload {
    /// Serialized `BlobTicket` bytes: the fetch credential (peer address +
    /// content digest) the requester hands to the iroh-blobs path. Opaque to
    /// this codec.
    ticket: Vec<u8>,
    size_bytes: u64,
}

#[derive(Serialize, Deserialize)]
struct DeniedPayload {
    code: DenyCode,
}

// ============================================================================
// Requests / replies
// ============================================================================

/// A request the client sends to the holder.
///
/// Constructing `Unknown` is only meaningful as a decode result; encoding one
/// is rejected (a local build never emits an opcode it does not know).
#[derive(Clone, PartialEq, Eq)]
pub enum ShareRequest {
    /// Probe whether the feature is usable right now (see [`HelloState`]).
    Hello,
    /// The holder's authorized-root whitelist.
    ListRoots,
    /// A page of entries under `path` (relative; empty string = the root
    /// itself). `after` is the page cursor from a previous
    /// [`ShareReply::Entries`]; `limit` is the requested page size.
    List {
        root_id: WireShareRootId,
        path: String,
        after: Option<String>,
        limit: u32,
    },
    /// Metadata for a single entry.
    Stat {
        root_id: WireShareRootId,
        path: String,
    },
    /// Create `path` as a directory (requires `write`). The parent must exist;
    /// `path` existing is `Conflict`.
    Mkdir {
        root_id: WireShareRootId,
        path: String,
    },
    /// Move `from` to `to` inside the same root (requires `write`). `to`
    /// existing is `Conflict`.
    Rename {
        root_id: WireShareRootId,
        from: String,
        to: String,
    },
    /// Move `path` into the root's recycle directory (requires `delete`);
    /// the reply carries the `trash_id` restore handle.
    Delete {
        root_id: WireShareRootId,
        path: String,
    },
    /// A page of the root's recycle directory (requires `delete`).
    ListTrash {
        root_id: WireShareRootId,
        after: Option<String>,
        limit: u32,
    },
    /// Move a recycled entry to `to` (requires `write` + `delete`). Pass the
    /// `original_path` from [`WireTrashEntry`] to restore in place; collisions
    /// auto-rename.
    Restore {
        root_id: WireShareRootId,
        trash_id: String,
        to: String,
    },
    /// Permanently drop the root's recycle-directory contents (requires
    /// `delete`).
    EmptyTrash { root_id: WireShareRootId },
    /// Server-side copy of `from` to `to` inside the same root (requires
    /// `write`). Directories copy recursively; `to` existing is `Conflict`.
    CopyWithin {
        root_id: WireShareRootId,
        from: String,
        to: String,
    },
    /// Open an upload session under `dir` (requires `write`): the holder
    /// creates a staging area and pulls each `entries` item's blob content;
    /// the returned `staging_id` identifies the session for `CommitUpload` /
    /// `AbortUpload`. `transfer_id` is the client-chosen progress-correlation
    /// key the holder reports its blob pulls under (transfer-progress/1).
    StageUpload {
        root_id: WireShareRootId,
        dir: String,
        transfer_id: [u8; 16],
        entries: Vec<WireStageEntry>,
    },
    /// Land every fetched entry of the named staging sessions (requires
    /// `write` on the staged root). Per-file atomic; conflicts auto-rename.
    CommitUpload { staging_ids: Vec<String> },
    /// Drop the named staging sessions and any bytes already pulled.
    AbortUpload { staging_ids: Vec<String> },
    /// Ask the holder to publish `path` as blob content and reply with a
    /// fetch ticket + size (requires `read`).
    Export {
        root_id: WireShareRootId,
        path: String,
    },
    /// An opcode this build does not know. Decoded only — the holder answers
    /// `Denied { UnsupportedRequest }`.
    Unknown { opcode: u32 },
}

/// Hand-written `Debug`: paths, cursors and manifest rels are user content
/// and must never reach a log line.
impl fmt::Debug for ShareRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REDACTED: &str = "[REDACTED]";
        match self {
            Self::Hello => f.write_str("Hello"),
            Self::ListRoots => f.write_str("ListRoots"),
            Self::List { root_id, limit, .. } => f
                .debug_struct("List")
                .field("root_id", root_id)
                .field("path", &REDACTED)
                .field("after", &REDACTED)
                .field("limit", limit)
                .finish(),
            Self::Stat { root_id, .. } => f
                .debug_struct("Stat")
                .field("root_id", root_id)
                .field("path", &REDACTED)
                .finish(),
            Self::Mkdir { root_id, .. } => f
                .debug_struct("Mkdir")
                .field("root_id", root_id)
                .field("path", &REDACTED)
                .finish(),
            Self::Rename { root_id, .. } => f
                .debug_struct("Rename")
                .field("root_id", root_id)
                .field("from", &REDACTED)
                .field("to", &REDACTED)
                .finish(),
            Self::Delete { root_id, .. } => f
                .debug_struct("Delete")
                .field("root_id", root_id)
                .field("path", &REDACTED)
                .finish(),
            Self::ListTrash {
                root_id,
                after,
                limit,
            } => f
                .debug_struct("ListTrash")
                .field("root_id", root_id)
                .field("after", after)
                .field("limit", limit)
                .finish(),
            Self::Restore {
                root_id, trash_id, ..
            } => f
                .debug_struct("Restore")
                .field("root_id", root_id)
                .field("trash_id", trash_id)
                .field("to", &REDACTED)
                .finish(),
            Self::EmptyTrash { root_id } => f
                .debug_struct("EmptyTrash")
                .field("root_id", root_id)
                .finish(),
            Self::CopyWithin { root_id, .. } => f
                .debug_struct("CopyWithin")
                .field("root_id", root_id)
                .field("from", &REDACTED)
                .field("to", &REDACTED)
                .finish(),
            Self::StageUpload {
                root_id,
                transfer_id,
                entries,
                ..
            } => f
                .debug_struct("StageUpload")
                .field("root_id", root_id)
                .field("dir", &REDACTED)
                .field("transfer_id", transfer_id)
                .field("entries", entries)
                .finish(),
            Self::CommitUpload { staging_ids } => f
                .debug_struct("CommitUpload")
                .field("staging_ids", staging_ids)
                .finish(),
            Self::AbortUpload { staging_ids } => f
                .debug_struct("AbortUpload")
                .field("staging_ids", staging_ids)
                .finish(),
            Self::Export { root_id, .. } => f
                .debug_struct("Export")
                .field("root_id", root_id)
                .field("path", &REDACTED)
                .finish(),
            Self::Unknown { opcode } => f.debug_struct("Unknown").field("opcode", opcode).finish(),
        }
    }
}

/// A reply the holder sends.
#[derive(Clone, PartialEq, Eq)]
pub enum ShareReply {
    /// The answer to [`ShareRequest::Hello`].
    Hello { state: HelloState },
    /// The holder's authorized-root whitelist (answer to `ListRoots`).
    Roots { roots: Vec<WireShareRoot> },
    /// A page of directory entries (answer to `List`). `next_after` is the
    /// cursor to pass back as `after` for the next page; `None` means this is
    /// the final page.
    Entries {
        entries: Vec<WireDirectoryEntry>,
        next_after: Option<String>,
    },
    /// A single entry's metadata (answer to `Stat`).
    Entry { entry: WireDirectoryEntry },
    /// A mutation finished with nothing else to report (answer to
    /// `Mkdir`/`Rename`/`Restore`/`EmptyTrash`/`CopyWithin`/`CommitUpload`/
    /// `AbortUpload`).
    Ack,
    /// `StageUpload` accepted; `staging_id` is the handle `CommitUpload` and
    /// `AbortUpload` address.
    Staged { staging_id: String },
    /// `Delete` accepted; `trash_id` is the restore handle `Restore` takes.
    Deleted { trash_id: String },
    /// A page of recycle-directory entries (answer to `ListTrash`).
    TrashEntries {
        entries: Vec<WireTrashEntry>,
        next_after: Option<String>,
    },
    /// `Export` accepted; `ticket` is the serialized `BlobTicket` the
    /// requester fetches the content with, `size_bytes` the announced size.
    Exported { ticket: Vec<u8>, size_bytes: u64 },
    /// The request could not be served (see [`DenyCode`]).
    Denied { code: DenyCode },
    /// A reply opcode this build does not know. Decoded only — the client
    /// surfaces it as an unsupported reply.
    Unknown { opcode: u32 },
}

/// Hand-written `Debug`: the exported ticket carries a peer address + content
/// digest and must never reach a log line; entry DTOs redact their own user
/// content already.
impl fmt::Debug for ShareReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { state } => f.debug_struct("Hello").field("state", state).finish(),
            Self::Roots { roots } => f.debug_struct("Roots").field("roots", roots).finish(),
            Self::Entries { entries, .. } => f
                .debug_struct("Entries")
                .field("entries", entries)
                .field("next_after", &"[REDACTED]")
                .finish(),
            Self::Entry { entry } => f.debug_struct("Entry").field("entry", entry).finish(),
            Self::Ack => f.write_str("Ack"),
            Self::Staged { staging_id } => f
                .debug_struct("Staged")
                .field("staging_id", staging_id)
                .finish(),
            Self::Deleted { trash_id } => f
                .debug_struct("Deleted")
                .field("trash_id", trash_id)
                .finish(),
            Self::TrashEntries {
                entries,
                next_after,
            } => f
                .debug_struct("TrashEntries")
                .field("entries", entries)
                .field("next_after", next_after)
                .finish(),
            Self::Exported { size_bytes, .. } => f
                .debug_struct("Exported")
                .field("ticket", &"[REDACTED]")
                .field("size_bytes", size_bytes)
                .finish(),
            Self::Denied { code } => f.debug_struct("Denied").field("code", code).finish(),
            Self::Unknown { opcode } => f.debug_struct("Unknown").field("opcode", opcode).finish(),
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// A codec-level failure framing or parsing a remote-share frame.
#[derive(Debug, Error)]
pub enum ShareWireError {
    #[error("remote share wire I/O failed")]
    Io(#[source] io::Error),
    #[error("remote share wire operation timed out")]
    Timeout,
    #[error("remote share wire header is invalid")]
    InvalidHeader,
    #[error("remote share wire frame kind 0x{got:02X} is unknown")]
    UnknownKind { got: u8 },
    #[error("remote share wire frame length {len} exceeds maximum {max}")]
    OversizedBody { len: usize, max: usize },
    #[error("remote share wire payload is invalid")]
    InvalidPayload {
        #[source]
        source: Option<anyhow::Error>,
    },
}

impl ShareWireError {
    fn invalid_payload_from(source: impl Into<anyhow::Error>) -> Self {
        Self::InvalidPayload {
            source: Some(source.into()),
        }
    }
}

// ============================================================================
// Framing
// ============================================================================

async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: FrameKind,
    payload: &[u8],
    limit: usize,
) -> Result<(), ShareWireError> {
    if payload.is_empty() || payload.len() > limit || payload.len() > u32::MAX as usize {
        return Err(ShareWireError::OversizedBody {
            len: payload.len(),
            max: limit,
        });
    }
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&WIRE_MAGIC);
    header[4] = WIRE_VERSION;
    header[5] = kind.as_u8();
    header[6..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    run_io(writer.write_all(&header)).await?;
    run_io(writer.write_all(payload)).await
}

/// Read the header + body, validating magic / version / kind and the body
/// length cap **before** allocating the body buffer. Returns the frame kind and
/// the raw (still encoded) body.
async fn read_raw_with_limit<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<(FrameKind, Vec<u8>), ShareWireError> {
    let mut header = [0u8; HEADER_LEN];
    run_io(reader.read_exact(&mut header)).await?;
    if header[..4] != WIRE_MAGIC || header[4] != WIRE_VERSION {
        return Err(ShareWireError::InvalidHeader);
    }
    let kind = FrameKind::from_u8(header[5])?;
    let len_bytes: [u8; 4] = header[6..]
        .try_into()
        // discarded-source[no-information]: `TryFromSliceError`: `header[6..]` is a
        // fixed 4-byte slice of the header, so the length can never mismatch and the
        // error is unreachable and carries no diagnostic
        .map_err(|_| ShareWireError::InvalidHeader)?;
    let length = u32::from_be_bytes(len_bytes) as usize;
    if length == 0 || length > limit {
        return Err(ShareWireError::OversizedBody {
            len: length,
            max: limit,
        });
    }
    let mut payload = vec![0u8; length];
    run_io(reader.read_exact(&mut payload)).await?;
    Ok((kind, payload))
}

fn decode_exact<T: DeserializeOwned>(payload: &[u8]) -> Result<T, ShareWireError> {
    let (value, remaining) =
        postcard::take_from_bytes(payload).map_err(ShareWireError::invalid_payload_from)?;
    if !remaining.is_empty() {
        return Err(ShareWireError::invalid_payload_from(anyhow::Error::msg(
            "trailing bytes after the encoded body",
        )));
    }
    Ok(value)
}

/// Split a body into the explicit opcode and the remaining payload bytes. An
/// opcode this build does not know is **not** an error here — the caller maps
/// it onto `Unknown` so the exchange can be answered.
fn take_opcode(payload: &[u8]) -> Result<(u32, &[u8]), ShareWireError> {
    postcard::take_from_bytes::<u32>(payload).map_err(ShareWireError::invalid_payload_from)
}

/// Field-less ops must carry nothing after the opcode.
fn expect_empty(rest: &[u8]) -> Result<(), ShareWireError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(ShareWireError::invalid_payload_from(anyhow::Error::msg(
            "unexpected payload bytes after a field-less opcode",
        )))
    }
}

fn encode_with_payload<P: Serialize>(opcode: u32, payload: &P) -> Result<Vec<u8>, ShareWireError> {
    postcard::to_stdvec(&(opcode, payload)).map_err(ShareWireError::invalid_payload_from)
}

fn encode_bare(opcode: u32) -> Result<Vec<u8>, ShareWireError> {
    postcard::to_stdvec(&opcode).map_err(ShareWireError::invalid_payload_from)
}

fn unknown_opcode_encode_error() -> ShareWireError {
    ShareWireError::invalid_payload_from(anyhow::Error::msg(
        "cannot encode an Unknown frame; it only exists as a decode fallback",
    ))
}

fn encode_request(request: &ShareRequest) -> Result<Vec<u8>, ShareWireError> {
    match request {
        ShareRequest::Hello => encode_bare(req_op::HELLO),
        ShareRequest::ListRoots => encode_bare(req_op::LIST_ROOTS),
        ShareRequest::List {
            root_id,
            path,
            after,
            limit,
        } => encode_with_payload(
            req_op::LIST,
            &ListPayload {
                root_id: *root_id,
                path: path.clone(),
                after: after.clone(),
                limit: *limit,
            },
        ),
        ShareRequest::Stat { root_id, path } => encode_with_payload(
            req_op::STAT,
            &PathPayload {
                root_id: *root_id,
                path: path.clone(),
            },
        ),
        ShareRequest::Mkdir { root_id, path } => encode_with_payload(
            req_op::MKDIR,
            &PathPayload {
                root_id: *root_id,
                path: path.clone(),
            },
        ),
        ShareRequest::Rename { root_id, from, to } => encode_with_payload(
            req_op::RENAME,
            &MovePayload {
                root_id: *root_id,
                from: from.clone(),
                to: to.clone(),
            },
        ),
        ShareRequest::Delete { root_id, path } => encode_with_payload(
            req_op::DELETE,
            &PathPayload {
                root_id: *root_id,
                path: path.clone(),
            },
        ),
        ShareRequest::ListTrash {
            root_id,
            after,
            limit,
        } => encode_with_payload(
            req_op::LIST_TRASH,
            &TrashPagePayload {
                root_id: *root_id,
                after: after.clone(),
                limit: *limit,
            },
        ),
        ShareRequest::Restore {
            root_id,
            trash_id,
            to,
        } => encode_with_payload(
            req_op::RESTORE,
            &RestorePayload {
                root_id: *root_id,
                trash_id: trash_id.clone(),
                to: to.clone(),
            },
        ),
        ShareRequest::EmptyTrash { root_id } => {
            encode_with_payload(req_op::EMPTY_TRASH, &RootPayload { root_id: *root_id })
        }
        ShareRequest::CopyWithin { root_id, from, to } => encode_with_payload(
            req_op::COPY_WITHIN,
            &MovePayload {
                root_id: *root_id,
                from: from.clone(),
                to: to.clone(),
            },
        ),
        ShareRequest::StageUpload {
            root_id,
            dir,
            transfer_id,
            entries,
        } => encode_with_payload(
            req_op::STAGE_UPLOAD,
            &StageUploadPayload {
                root_id: *root_id,
                dir: dir.clone(),
                transfer_id: *transfer_id,
                entries: entries.clone(),
            },
        ),
        ShareRequest::CommitUpload { staging_ids } => encode_with_payload(
            req_op::COMMIT_UPLOAD,
            &StagingIdsPayload {
                staging_ids: staging_ids.clone(),
            },
        ),
        ShareRequest::AbortUpload { staging_ids } => encode_with_payload(
            req_op::ABORT_UPLOAD,
            &StagingIdsPayload {
                staging_ids: staging_ids.clone(),
            },
        ),
        ShareRequest::Export { root_id, path } => encode_with_payload(
            req_op::EXPORT,
            &PathPayload {
                root_id: *root_id,
                path: path.clone(),
            },
        ),
        ShareRequest::Unknown { .. } => Err(unknown_opcode_encode_error()),
    }
}

fn decode_request_body(payload: &[u8]) -> Result<ShareRequest, ShareWireError> {
    let (opcode, rest) = take_opcode(payload)?;
    Ok(match opcode {
        req_op::HELLO => {
            expect_empty(rest)?;
            ShareRequest::Hello
        }
        req_op::LIST_ROOTS => {
            expect_empty(rest)?;
            ShareRequest::ListRoots
        }
        req_op::LIST => {
            let p: ListPayload = decode_exact(rest)?;
            ShareRequest::List {
                root_id: p.root_id,
                path: p.path,
                after: p.after,
                limit: p.limit,
            }
        }
        req_op::STAT => {
            let p: PathPayload = decode_exact(rest)?;
            ShareRequest::Stat {
                root_id: p.root_id,
                path: p.path,
            }
        }
        req_op::MKDIR => {
            let p: PathPayload = decode_exact(rest)?;
            ShareRequest::Mkdir {
                root_id: p.root_id,
                path: p.path,
            }
        }
        req_op::RENAME => {
            let p: MovePayload = decode_exact(rest)?;
            ShareRequest::Rename {
                root_id: p.root_id,
                from: p.from,
                to: p.to,
            }
        }
        req_op::DELETE => {
            let p: PathPayload = decode_exact(rest)?;
            ShareRequest::Delete {
                root_id: p.root_id,
                path: p.path,
            }
        }
        req_op::LIST_TRASH => {
            let p: TrashPagePayload = decode_exact(rest)?;
            ShareRequest::ListTrash {
                root_id: p.root_id,
                after: p.after,
                limit: p.limit,
            }
        }
        req_op::RESTORE => {
            let p: RestorePayload = decode_exact(rest)?;
            ShareRequest::Restore {
                root_id: p.root_id,
                trash_id: p.trash_id,
                to: p.to,
            }
        }
        req_op::EMPTY_TRASH => {
            let p: RootPayload = decode_exact(rest)?;
            ShareRequest::EmptyTrash { root_id: p.root_id }
        }
        req_op::COPY_WITHIN => {
            let p: MovePayload = decode_exact(rest)?;
            ShareRequest::CopyWithin {
                root_id: p.root_id,
                from: p.from,
                to: p.to,
            }
        }
        req_op::STAGE_UPLOAD => {
            let p: StageUploadPayload = decode_exact(rest)?;
            ShareRequest::StageUpload {
                root_id: p.root_id,
                dir: p.dir,
                transfer_id: p.transfer_id,
                entries: p.entries,
            }
        }
        req_op::COMMIT_UPLOAD => {
            let p: StagingIdsPayload = decode_exact(rest)?;
            ShareRequest::CommitUpload {
                staging_ids: p.staging_ids,
            }
        }
        req_op::ABORT_UPLOAD => {
            let p: StagingIdsPayload = decode_exact(rest)?;
            ShareRequest::AbortUpload {
                staging_ids: p.staging_ids,
            }
        }
        req_op::EXPORT => {
            let p: PathPayload = decode_exact(rest)?;
            ShareRequest::Export {
                root_id: p.root_id,
                path: p.path,
            }
        }
        // An opcode this build does not know keeps the stream alive: the serve
        // side answers `Denied{UnsupportedRequest}` (spec §15). Whatever
        // payload bytes followed are ignored — the frame cap already bounded
        // the allocation.
        unknown => ShareRequest::Unknown { opcode: unknown },
    })
}

fn encode_reply(reply: &ShareReply) -> Result<Vec<u8>, ShareWireError> {
    match reply {
        ShareReply::Hello { state } => {
            encode_with_payload(rep_op::HELLO, &HelloPayload { state: *state })
        }
        ShareReply::Roots { roots } => encode_with_payload(
            rep_op::ROOTS,
            &RootsPayload {
                roots: roots.clone(),
            },
        ),
        ShareReply::Entries {
            entries,
            next_after,
        } => encode_with_payload(
            rep_op::ENTRIES,
            &EntriesPayload {
                entries: entries.clone(),
                next_after: next_after.clone(),
            },
        ),
        ShareReply::Entry { entry } => encode_with_payload(
            rep_op::ENTRY,
            &EntryPayload {
                entry: entry.clone(),
            },
        ),
        ShareReply::Ack => encode_bare(rep_op::ACK),
        ShareReply::Staged { staging_id } => encode_with_payload(
            rep_op::STAGED,
            &StagedPayload {
                staging_id: staging_id.clone(),
            },
        ),
        ShareReply::Deleted { trash_id } => encode_with_payload(
            rep_op::DELETED,
            &DeletedPayload {
                trash_id: trash_id.clone(),
            },
        ),
        ShareReply::TrashEntries {
            entries,
            next_after,
        } => encode_with_payload(
            rep_op::TRASH_ENTRIES,
            &TrashEntriesPayload {
                entries: entries.clone(),
                next_after: next_after.clone(),
            },
        ),
        ShareReply::Exported { ticket, size_bytes } => encode_with_payload(
            rep_op::EXPORTED,
            &ExportedPayload {
                ticket: ticket.clone(),
                size_bytes: *size_bytes,
            },
        ),
        ShareReply::Denied { code } => {
            encode_with_payload(rep_op::DENIED, &DeniedPayload { code: *code })
        }
        ShareReply::Unknown { .. } => Err(unknown_opcode_encode_error()),
    }
}

fn decode_reply_body(payload: &[u8]) -> Result<ShareReply, ShareWireError> {
    let (opcode, rest) = take_opcode(payload)?;
    Ok(match opcode {
        rep_op::HELLO => {
            let p: HelloPayload = decode_exact(rest)?;
            ShareReply::Hello { state: p.state }
        }
        rep_op::ROOTS => {
            let p: RootsPayload = decode_exact(rest)?;
            ShareReply::Roots { roots: p.roots }
        }
        rep_op::ENTRIES => {
            let p: EntriesPayload = decode_exact(rest)?;
            ShareReply::Entries {
                entries: p.entries,
                next_after: p.next_after,
            }
        }
        rep_op::ENTRY => {
            let p: EntryPayload = decode_exact(rest)?;
            ShareReply::Entry { entry: p.entry }
        }
        rep_op::ACK => {
            expect_empty(rest)?;
            ShareReply::Ack
        }
        rep_op::STAGED => {
            let p: StagedPayload = decode_exact(rest)?;
            ShareReply::Staged {
                staging_id: p.staging_id,
            }
        }
        rep_op::DELETED => {
            let p: DeletedPayload = decode_exact(rest)?;
            ShareReply::Deleted {
                trash_id: p.trash_id,
            }
        }
        rep_op::TRASH_ENTRIES => {
            let p: TrashEntriesPayload = decode_exact(rest)?;
            ShareReply::TrashEntries {
                entries: p.entries,
                next_after: p.next_after,
            }
        }
        rep_op::EXPORTED => {
            let p: ExportedPayload = decode_exact(rest)?;
            ShareReply::Exported {
                ticket: p.ticket,
                size_bytes: p.size_bytes,
            }
        }
        rep_op::DENIED => {
            let p: DeniedPayload = decode_exact(rest)?;
            ShareReply::Denied { code: p.code }
        }
        unknown => ShareReply::Unknown { opcode: unknown },
    })
}

async fn run_io<T>(future: impl Future<Output = io::Result<T>>) -> Result<T, ShareWireError> {
    tokio::time::timeout(IO_DEADLINE, future)
        .await
        // discarded-source[timeout]: `Elapsed`: the timeout itself is the classification
        .map_err(|_| ShareWireError::Timeout)?
        .map_err(ShareWireError::Io)
}

/// Serialize + send a request frame (`kind = Request`, capped at
/// [`REQUEST_LIMIT`]). The caller closes the send half after this returns.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &ShareRequest,
) -> Result<(), ShareWireError> {
    let payload = encode_request(request)?;
    write_raw(writer, FrameKind::Request, &payload, REQUEST_LIMIT).await
}

/// Read one request frame and decode it into a [`ShareRequest`]. An opcode the
/// receiver does not know becomes [`ShareRequest::Unknown`], never a decode
/// error — the serve side answers it with `Denied { UnsupportedRequest }`.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ShareRequest, ShareWireError> {
    let (kind, payload) = read_raw_with_limit(reader, REQUEST_LIMIT).await?;
    if kind != FrameKind::Request {
        return Err(ShareWireError::UnknownKind { got: kind.as_u8() });
    }
    decode_request_body(&payload)
}

/// Serialize + send a reply frame (`kind = Reply`, capped at [`REPLY_LIMIT`]).
/// The caller closes the send half after this returns.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: &ShareReply,
) -> Result<(), ShareWireError> {
    let payload = encode_reply(reply)?;
    write_raw(writer, FrameKind::Reply, &payload, REPLY_LIMIT).await
}

/// Read one reply frame and decode it into a [`ShareReply`]. An opcode the
/// receiver does not know becomes [`ShareReply::Unknown`], never a decode
/// error.
pub async fn read_reply<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ShareReply, ShareWireError> {
    let (kind, payload) = read_raw_with_limit(reader, REPLY_LIMIT).await?;
    if kind != FrameKind::Reply {
        return Err(ShareWireError::UnknownKind { got: kind.as_u8() });
    }
    decode_reply_body(&payload)
}
