//! Wire codec for the `remote-share/1` control-plane protocol.
//!
//! This is a metadata-only request/reply exchange on one bi-stream: the client
//! (the viewer) asks the holder (the machine whose files are being shared) for
//! the authorized-root whitelist, a directory page, or a single entry's
//! metadata. **No bulk bytes travel here** — file content goes over the
//! separate iroh-blobs path, and absolute paths **never** appear in a frame
//! (spec §13 I2). The holder keeps each root's absolute path local; the client
//! only ever sees an opaque `root_id`, a user-facing label, and relative entry
//! names.
//!
//! Frame layout (identical in both directions):
//!
//! ```text
//! [magic(4) = "UCRS" | version(1) | kind(1) | body_len(4, big-endian) | body]
//! ```
//!
//! * `body` is a `postcard`-encoded [`ShareRequest`] when `kind` is
//!   [`FrameKind::Request`] and a [`ShareReply`] when it is
//!   [`FrameKind::Reply`].
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

/// Hard cap on a request body (64 KiB). A request is an op + at most one
/// relative path + one page cursor; 64 KiB is generous headroom over any
/// legitimate request and bounds what a hostile peer can make us allocate.
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
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

/// Hand-written `Debug`: `name` is a filename and must never reach a log line.
impl fmt::Debug for WireDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireDirectoryEntry")
            .field("name", &"[REDACTED]")
            .field("is_dir", &self.is_dir)
            .field("size_bytes", &self.size_bytes)
            .field("modified_at_ms", &self.modified_at_ms)
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

/// Denial code for a `ListRoots` / `List` / `Stat` that could not be served.
///
/// `NotUnlocked` and `Suspended` map to the same "nothing to show" UI state as
/// the `Hello` locked/suspended replies; the others are per-path failures the
/// client can surface next to the affected entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyCode {
    /// The holder's session is locked.
    NotUnlocked,
    /// The admitted peer is not authorized for this root / operation.
    NotAuthorized,
    /// No such root or entry.
    NotFound,
    /// `path` is a file, but a directory was required.
    NotADirectory,
    /// `path` is a directory, but a file was required.
    IsADirectory,
    /// A path component collides with a reserved name.
    ReservedName,
    /// The feature is suspended.
    Suspended,
    /// The holder hit a local I/O failure while serving the path.
    Io,
}

/// A request the client sends to the holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareRequest {
    /// Probe whether the feature is usable right now (see [`HelloState`]).
    Hello,
    /// The holder's authorized-root whitelist.
    ListRoots,
    /// A page of entries under `path` (relative; empty string = the root
    /// itself). `after` is the page cursor from a previous [`ShareReply::Entries`];
    /// `limit` is the requested page size.
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
}

/// A reply the holder sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The request could not be served (see [`DenyCode`]).
    Denied { code: DenyCode },
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
    let payload = postcard::to_stdvec(request).map_err(ShareWireError::invalid_payload_from)?;
    write_raw(writer, FrameKind::Request, &payload, REQUEST_LIMIT).await
}

/// Read one request frame and decode it into a [`ShareRequest`].
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ShareRequest, ShareWireError> {
    let (kind, payload) = read_raw_with_limit(reader, REQUEST_LIMIT).await?;
    if kind != FrameKind::Request {
        return Err(ShareWireError::UnknownKind { got: kind.as_u8() });
    }
    decode_exact(&payload)
}

/// Serialize + send a reply frame (`kind = Reply`, capped at [`REPLY_LIMIT`]).
/// The caller closes the send half after this returns.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: &ShareReply,
) -> Result<(), ShareWireError> {
    let payload = postcard::to_stdvec(reply).map_err(ShareWireError::invalid_payload_from)?;
    write_raw(writer, FrameKind::Reply, &payload, REPLY_LIMIT).await
}

/// Read one reply frame and decode it into a [`ShareReply`].
pub async fn read_reply<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ShareReply, ShareWireError> {
    let (kind, payload) = read_raw_with_limit(reader, REPLY_LIMIT).await?;
    if kind != FrameKind::Reply {
        return Err(ShareWireError::UnknownKind { got: kind.as_u8() });
    }
    decode_exact(&payload)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn sample_root(id_byte: u8) -> WireShareRoot {
        let mut id = [0u8; 16];
        id[0] = id_byte;
        WireShareRoot {
            id,
            label: "Documents".to_owned(),
            grants: WireShareGrants {
                read: true,
                write: true,
                delete: false,
            },
            enabled: true,
        }
    }

    fn sample_entry(name: &str, is_dir: bool) -> WireDirectoryEntry {
        WireDirectoryEntry {
            name: name.to_owned(),
            is_dir,
            size_bytes: 1234,
            modified_at_ms: 1_700_000_000_000,
        }
    }

    async fn request_round_trip(request: &ShareRequest) -> Result<ShareRequest, ShareWireError> {
        let (mut client, mut server) = duplex(128 * 1024);
        let r = request.clone();
        let sender = tokio::spawn(async move {
            write_request(&mut client, &r).await.expect("write request");
            client.shutdown().await.expect("shutdown");
        });
        let got = read_request(&mut server).await?;
        sender.await.unwrap();
        Ok(got)
    }

    async fn reply_round_trip(reply: &ShareReply) -> Result<ShareReply, ShareWireError> {
        let (mut client, mut server) = duplex(4 * 1024 * 1024);
        let r = reply.clone();
        let sender = tokio::spawn(async move {
            write_reply(&mut client, &r).await.expect("write reply");
            client.shutdown().await.expect("shutdown");
        });
        let got = read_reply(&mut server).await?;
        sender.await.unwrap();
        Ok(got)
    }

    /// 1. A fully-populated List request round-trips field-for-field.
    #[tokio::test]
    async fn list_request_round_trips() {
        let mut root_id = [0u8; 16];
        root_id[15] = 0xAB;
        let request = ShareRequest::List {
            root_id,
            path: "sub dir/nested".to_owned(),
            after: Some("cursor-2".to_owned()),
            limit: 50,
        };
        let got = request_round_trip(&request).await.expect("round trip");
        assert_eq!(got, request);
    }

    /// 2. Each reply shape round-trips (Hello, Roots, Entries, Entry, Denied).
    #[tokio::test]
    async fn reply_variants_round_trip() {
        for reply in [
            ShareReply::Hello {
                state: HelloState::Locked,
            },
            ShareReply::Roots {
                roots: vec![sample_root(1), sample_root(2)],
            },
            ShareReply::Entries {
                entries: vec![sample_entry("a", true), sample_entry("b.txt", false)],
                next_after: Some("c".to_owned()),
            },
            ShareReply::Entry {
                entry: sample_entry("x", false),
            },
            ShareReply::Denied {
                code: DenyCode::NotAuthorized,
            },
        ] {
            let got = reply_round_trip(&reply).await.expect("round trip");
            assert_eq!(got, reply);
        }
    }

    /// 3. A frame with the wrong magic is rejected at the header check, before
    /// allocating the body buffer.
    #[tokio::test]
    async fn read_rejects_bad_magic() {
        let (mut client, mut server) = duplex(64);
        let sender = tokio::spawn(async move {
            client
                .write_all(&[b'X', b'Y', b'Z', b'W', 1, 1, 0, 0, 0, 0])
                .await
                .ok();
            client.shutdown().await.ok();
        });
        let err = read_request(&mut server)
            .await
            .expect_err("bad magic must be rejected");
        assert!(matches!(err, ShareWireError::InvalidHeader));
        sender.await.unwrap();
    }

    /// 4. A frame with the wrong version is rejected at the header check.
    #[tokio::test]
    async fn read_rejects_bad_version() {
        let (mut client, mut server) = duplex(64);
        let sender = tokio::spawn(async move {
            client
                .write_all(&[b'U', b'C', b'R', b'S', 9, 1, 0, 0, 0, 0])
                .await
                .ok();
            client.shutdown().await.ok();
        });
        let err = read_request(&mut server)
            .await
            .expect_err("bad version must be rejected");
        assert!(matches!(err, ShareWireError::InvalidHeader));
        sender.await.unwrap();
    }

    /// 5. An unknown kind byte is rejected explicitly, not misinterpreted.
    #[tokio::test]
    async fn read_rejects_unknown_kind() {
        let (mut client, mut server) = duplex(64);
        let sender = tokio::spawn(async move {
            client
                .write_all(&[b'U', b'C', b'R', b'S', 1, 0x7F, 0, 0, 0, 0])
                .await
                .ok();
            client.shutdown().await.ok();
        });
        let err = read_request(&mut server)
            .await
            .expect_err("unknown kind must be rejected");
        match err {
            ShareWireError::UnknownKind { got } => assert_eq!(got, 0x7F),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
        sender.await.unwrap();
    }

    /// 6. A request claiming a body over the 64 KiB cap is rejected at the
    /// length field, before allocating the body buffer.
    #[tokio::test]
    async fn read_request_rejects_oversized_body() {
        let (mut client, mut server) = duplex(64);
        let oversized = REQUEST_LIMIT + 1;
        let sender = tokio::spawn(async move {
            let mut header = [0u8; HEADER_LEN];
            header[..4].copy_from_slice(&WIRE_MAGIC);
            header[4] = WIRE_VERSION;
            header[5] = FrameKind::Request.as_u8();
            header[6..].copy_from_slice(&(oversized as u32).to_be_bytes());
            client.write_all(&header).await.ok();
            client.shutdown().await.ok();
        });
        let err = read_request(&mut server)
            .await
            .expect_err("oversized body must be rejected");
        match err {
            ShareWireError::OversizedBody { len, max } => {
                assert_eq!(len, oversized);
                assert_eq!(max, REQUEST_LIMIT);
            }
            other => panic!("expected OversizedBody, got {other:?}"),
        }
        sender.await.unwrap();
    }

    /// 7. A reply claiming a body over the 2 MiB cap is rejected at the length
    /// field, before allocating.
    #[tokio::test]
    async fn read_reply_rejects_oversized_body() {
        let (mut client, mut server) = duplex(64);
        let oversized = REPLY_LIMIT + 1;
        let sender = tokio::spawn(async move {
            let mut header = [0u8; HEADER_LEN];
            header[..4].copy_from_slice(&WIRE_MAGIC);
            header[4] = WIRE_VERSION;
            header[5] = FrameKind::Reply.as_u8();
            header[6..].copy_from_slice(&(oversized as u32).to_be_bytes());
            client.write_all(&header).await.ok();
            client.shutdown().await.ok();
        });
        let err = read_reply(&mut server)
            .await
            .expect_err("oversized reply must be rejected");
        match err {
            ShareWireError::OversizedBody { len, max } => {
                assert_eq!(len, oversized);
                assert_eq!(max, REPLY_LIMIT);
            }
            other => panic!("expected OversizedBody, got {other:?}"),
        }
        sender.await.unwrap();
    }

    /// 8. A frame whose body carries trailing bytes is rejected, not silently
    /// truncated.
    #[tokio::test]
    async fn read_rejects_trailing_bytes() {
        let (mut client, mut server) = duplex(4 * 1024);
        let reply = ShareReply::Hello {
            state: HelloState::Ok,
        };
        let good = postcard::to_stdvec(&reply).expect("encode");
        let sender = tokio::spawn({
            let good = good.clone();
            async move {
                let mut body = good;
                body.push(0xFF);
                let mut frame = [0u8; HEADER_LEN];
                frame[..4].copy_from_slice(&WIRE_MAGIC);
                frame[4] = WIRE_VERSION;
                frame[5] = FrameKind::Reply.as_u8();
                frame[6..].copy_from_slice(&(body.len() as u32).to_be_bytes());
                client.write_all(&frame).await.ok();
                client.write_all(&body).await.ok();
                client.shutdown().await.ok();
            }
        });
        let err = read_reply(&mut server)
            .await
            .expect_err("trailing bytes must be rejected");
        assert!(matches!(err, ShareWireError::InvalidPayload { .. }));
        sender.await.unwrap();
    }

    /// 9. A truncated frame (partial header) surfaces as an I/O error, not a
    /// panic.
    #[tokio::test]
    async fn read_surfaces_truncation_as_io() {
        let (mut client, mut server) = duplex(64);
        let sender = tokio::spawn(async move {
            client.write_all(&[b'U', b'C']).await.ok();
            client.shutdown().await.ok();
        });
        let err = read_request(&mut server)
            .await
            .expect_err("truncation must surface as error");
        assert!(matches!(err, ShareWireError::Io(_)));
        sender.await.unwrap();
    }

    /// 10. A kind mismatch on the reading side (a Reply frame read where a
    /// Request is expected) is rejected.
    #[tokio::test]
    async fn read_request_rejects_a_reply_frame() {
        let (mut client, mut server) = duplex(4 * 1024);
        let reply = ShareReply::Hello {
            state: HelloState::Ok,
        };
        let sender = tokio::spawn(async move {
            write_reply(&mut client, &reply).await.expect("write reply");
            client.shutdown().await.expect("shutdown");
        });
        let err = read_request(&mut server)
            .await
            .expect_err("a reply frame must not parse as a request");
        match err {
            ShareWireError::UnknownKind { got } => assert_eq!(got, FrameKind::Reply.as_u8()),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
        sender.await.unwrap();
    }

    /// 11. The redacting `Debug` impls never leak the user-facing `label` or the
    /// entry `name` into a log line.
    #[test]
    fn debug_redacts_label_and_name() {
        let root = sample_root(7);
        let entry = sample_entry("secret-file.txt", false);
        let root_text = format!("{root:?}");
        let entry_text = format!("{entry:?}");
        assert!(
            !root_text.contains("Documents"),
            "Debug leaked the root label"
        );
        assert!(
            !entry_text.contains("secret-file.txt"),
            "Debug leaked the entry name"
        );
        assert!(root_text.contains("[REDACTED]"));
        assert!(entry_text.contains("[REDACTED]"));
    }
}
