//! Iroh-backed implementation of [`RemoteShareClientPort`] (requester side).
//!
//! One exchange per op: resolve the peer's stored address, dial it on
//! [`REMOTE_SHARE_ALPN`], open one bi-stream, write the [`ShareRequest`], read
//! back the [`ShareReply`], then close the connection (mirroring the
//! pull-client's asymmetric teardown — the serve side waits on
//! `connection.closed()`; closing here resolves its barrier immediately).
//!
//! No outer deadline is imposed: a `CommitUpload` legitimately waits for the
//! holder's in-flight blob pulls to settle before replying, so a fixed budget
//! would misclassify slow-but-healthy commits. Stalls are still bounded —
//! every individual read/write inside the codec carries the wire
//! `IO_DEADLINE` (30s), and dial is bounded by the staggered-retry policy.
//!
//! Failure mapping:
//! * Missing / undecodable stored address, dial failure, or a wire-level read
//!   timeout → [`RemoteShareClientError::Unreachable`].
//! * A typed `Denied { code }` reply →
//!   [`RemoteShareClientError::Refused`] with the domain-mirrored
//!   [`ShareClientDeny`].
//! * A reply opcode that does not match the request's expected variant →
//!   [`RemoteShareClientError::UnexpectedReply`].
//! * Stream write / read / codec failure → [`RemoteShareClientError::Io`].

use std::sync::Arc;

use async_trait::async_trait;
use iroh::{Endpoint, EndpointAddr};
use tracing::instrument;

use uc_core::ids::DeviceId;
use uc_core::ports::remote_share::{
    RemoteShareClientError, RemoteShareClientPort, ShareAvailability, ShareClientDeny,
    ShareDirectoryEntry, ShareDirectoryPage, ShareExportOutcome, ShareRootDescriptor, ShareRootId,
    ShareStageEntry, ShareStageOutcome, ShareTransferId, ShareTrashEntry, ShareTrashPage,
};
use uc_core::ports::PeerAddressRepositoryPort;
use uc_observability_contract::{error_source::io_error_kind, uc_debug, uc_warn};
use uc_sync_protocol::remote_share::{
    self as share_wire, DenyCode, HelloState, ShareReply, ShareRequest, ShareWireError,
    WireDirectoryEntry, WireShareRoot, WireStageEntry, WireTrashEntry, REMOTE_SHARE_ALPN,
};

use super::super::connect::connect_with_staggered_retry;
use super::super::peer_address_resolver::PeerAddressResolver;

/// Requests arbitrary remote-share ops against one peer over the share ALPN.
/// Reuses the shared endpoint + `peer_addr_repo` so the exchange rides the
/// same NAT/relay mapping the other ALPNs established.
pub struct IrohRemoteShareClientAdapter {
    endpoint: Arc<Endpoint>,
    peer_address_resolver: PeerAddressResolver,
}

impl IrohRemoteShareClientAdapter {
    pub fn new(
        endpoint: Arc<Endpoint>,
        peer_addr_repo: Arc<dyn PeerAddressRepositoryPort>,
    ) -> Self {
        Self {
            endpoint,
            peer_address_resolver: PeerAddressResolver::new(peer_addr_repo),
        }
    }

    /// Resolve the peer's current [`EndpointAddr`]. `None` (no record,
    /// undecodable blob, or repo error) maps to `Unreachable`. Mirrors the
    /// pull client's `resolve_addr`.
    async fn resolve_addr(&self, target: &DeviceId) -> Option<EndpointAddr> {
        match self.peer_address_resolver.resolve(target).await {
            Ok(address) => address,
            Err(error) => {
                uc_warn!(
                    error_kind = error.kind(),
                    "remote-share address resolution failed; treating peer as unreachable"
                );
                None
            }
        }
    }

    /// One full request → reply exchange against `peer`.
    async fn exchange(
        &self,
        peer: &DeviceId,
        request: &ShareRequest,
    ) -> Result<ShareReply, RemoteShareClientError> {
        // 1. Resolve address; missing / bad record = unreachable.
        let addr = match self.resolve_addr(peer).await {
            Some(addr) => addr,
            None => return Err(RemoteShareClientError::Unreachable),
        };

        // 2. Dial. Dial failure = unreachable (no typed iroh error leaks up).
        let connection = match connect_with_staggered_retry(
            Arc::clone(&self.endpoint),
            addr,
            REMOTE_SHARE_ALPN,
            "remote-share",
            uc_observability_contract::diagnostics::connectivity::AddressInputSource::Stored,
        )
        .await
        {
            Ok(connection) => connection,
            Err(err) => {
                uc_debug!(
                    error_kind = "dial_failed",
                    io_error_kind = io_error_kind(&err),
                    "remote-share: dial failed, treating as Unreachable"
                );
                return Err(RemoteShareClientError::Unreachable);
            }
        };

        // 3. Open one bi-stream, write the request, close the send half.
        let (mut send, mut recv) = connection.open_bi().await.map_err(|err| {
            RemoteShareClientError::Io(anyhow::Error::from(err).context("open_bi").into())
        })?;

        share_wire::write_request(&mut send, request)
            .await
            .map_err(|err| {
                RemoteShareClientError::Io(anyhow::Error::from(err).context("request write").into())
            })?;
        send.finish().map_err(|err| {
            RemoteShareClientError::Io(anyhow::Error::from(err).context("send.finish").into())
        })?;

        // 4. Read the reply frame. A wire-level IO deadline that fires means
        //    the holder stalled mid-exchange — same classification as the
        //    pull client gives its 10s deadline: the peer is unreachable.
        let reply = share_wire::read_reply(&mut recv)
            .await
            .map_err(|err| match err {
                ShareWireError::Timeout => RemoteShareClientError::Unreachable,
                other => RemoteShareClientError::Io(
                    anyhow::Error::from(other).context("reply read").into(),
                ),
            })?;

        // 5. Actively close once the reply frame is fully read — resolves the
        //    serve side's close barrier immediately (see the pull client).
        connection.close(0u32.into(), b"remote-share-complete");

        Ok(reply)
    }
}

/// Extract the expected reply variant, mapping `Denied`/`Unknown`/mismatch
/// uniformly for every op.
fn expect_reply<T>(
    reply: ShareReply,
    pick: impl FnOnce(ShareReply) -> Option<T>,
) -> Result<T, RemoteShareClientError> {
    match reply {
        ShareReply::Denied { code } => Err(RemoteShareClientError::Refused(deny_to_client(code))),
        ShareReply::Unknown { .. } => Err(RemoteShareClientError::Refused(
            ShareClientDeny::UnsupportedRequest,
        )),
        other => pick(other).ok_or(RemoteShareClientError::UnexpectedReply),
    }
}

#[async_trait]
impl RemoteShareClientPort for IrohRemoteShareClientAdapter {
    #[instrument(skip_all)]
    async fn hello(&self, peer: &DeviceId) -> Result<ShareAvailability, RemoteShareClientError> {
        let reply = self.exchange(peer, &ShareRequest::Hello).await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Hello { state } => Some(hello_from_wire(state)),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn list_roots(
        &self,
        peer: &DeviceId,
    ) -> Result<Vec<ShareRootDescriptor>, RemoteShareClientError> {
        let reply = self.exchange(peer, &ShareRequest::ListRoots).await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Roots { roots } => {
                Some(roots.into_iter().map(descriptor_from_wire).collect())
            }
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn list(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareDirectoryPage, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::List {
                    root_id: root.as_bytes(),
                    path: rel.to_owned(),
                    after: after.map(str::to_owned),
                    limit,
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Entries {
                entries,
                next_after,
            } => Some(ShareDirectoryPage {
                entries: entries.into_iter().map(entry_from_wire).collect(),
                next_after,
            }),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn stat(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareDirectoryEntry, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Stat {
                    root_id: root.as_bytes(),
                    path: rel.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Entry { entry } => Some(entry_from_wire(entry)),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn mkdir(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Mkdir {
                    root_id: root.as_bytes(),
                    path: rel.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn rename(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Rename {
                    root_id: root.as_bytes(),
                    from: from.to_owned(),
                    to: to.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn delete(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<String, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Delete {
                    root_id: root.as_bytes(),
                    path: rel.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Deleted { trash_id } => Some(trash_id),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn list_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareTrashPage, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::ListTrash {
                    root_id: root.as_bytes(),
                    after: after.map(str::to_owned),
                    limit,
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::TrashEntries {
                entries,
                next_after,
            } => Some(ShareTrashPage {
                entries: entries.into_iter().map(trash_entry_from_wire).collect(),
                next_after,
            }),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn restore(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        trash_id: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Restore {
                    root_id: root.as_bytes(),
                    trash_id: trash_id.to_owned(),
                    to: to.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn empty_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::EmptyTrash {
                    root_id: root.as_bytes(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn copy_within(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::CopyWithin {
                    root_id: root.as_bytes(),
                    from: from.to_owned(),
                    to: to.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn stage_upload(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dir: &str,
        entries: &[ShareStageEntry],
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::StageUpload {
                    root_id: root.as_bytes(),
                    dir: dir.to_owned(),
                    transfer_id: *transfer_id.as_bytes(),
                    entries: entries.iter().map(stage_entry_to_wire).collect(),
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Staged { staging_id } => Some(ShareStageOutcome { staging_id }),
            _ => None,
        })
    }

    #[instrument(skip_all)]
    async fn commit_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::CommitUpload {
                    staging_ids: staging_ids.to_vec(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn abort_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::AbortUpload {
                    staging_ids: staging_ids.to_vec(),
                },
            )
            .await?;
        expect_reply(reply, |reply| {
            matches!(reply, ShareReply::Ack).then_some(())
        })
    }

    #[instrument(skip_all)]
    async fn export(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareExportOutcome, RemoteShareClientError> {
        let reply = self
            .exchange(
                peer,
                &ShareRequest::Export {
                    root_id: root.as_bytes(),
                    path: rel.to_owned(),
                },
            )
            .await?;
        expect_reply(reply, |reply| match reply {
            ShareReply::Exported { ticket, size_bytes } => Some(ShareExportOutcome {
                ticket: uc_core::ports::blob::BlobTicket::from_bytes(ticket),
                size_bytes,
            }),
            _ => None,
        })
    }
}

// ============================================================================
// Wire -> domain conversion
// ============================================================================

fn hello_from_wire(state: HelloState) -> ShareAvailability {
    match state {
        HelloState::Ok => ShareAvailability::Ok,
        HelloState::Locked => ShareAvailability::Locked,
        HelloState::Unsupported => ShareAvailability::Unsupported,
        HelloState::Suspended => ShareAvailability::Suspended,
    }
}

fn descriptor_from_wire(root: WireShareRoot) -> ShareRootDescriptor {
    ShareRootDescriptor {
        id: ShareRootId::from_wire_bytes(root.id),
        label: root.label,
        grants: uc_core::ports::remote_share::ShareGrants {
            read: root.grants.read,
            write: root.grants.write,
            delete: root.grants.delete,
        },
        enabled: root.enabled,
    }
}

fn entry_from_wire(entry: WireDirectoryEntry) -> ShareDirectoryEntry {
    ShareDirectoryEntry {
        name: entry.name,
        is_dir: entry.is_dir,
        is_symlink: entry.is_symlink,
        size_bytes: entry.size_bytes,
        modified_at_ms: entry.modified_at_ms,
    }
}

fn trash_entry_from_wire(entry: WireTrashEntry) -> ShareTrashEntry {
    ShareTrashEntry {
        trash_id: entry.trash_id,
        original_rel: entry.original_path,
        deleted_at_ms: entry.deleted_at_ms,
        is_dir: entry.is_dir,
        size_bytes: entry.size_bytes,
    }
}

fn stage_entry_to_wire(entry: &ShareStageEntry) -> WireStageEntry {
    WireStageEntry {
        rel: entry.rel.clone(),
        is_dir: entry.is_dir,
        size_bytes: entry.size_bytes,
        ticket: entry
            .ticket
            .as_ref()
            .map(|ticket| ticket.as_bytes().to_vec())
            .unwrap_or_default(),
    }
}

fn deny_to_client(code: DenyCode) -> ShareClientDeny {
    match code {
        DenyCode::Locked => ShareClientDeny::Locked,
        DenyCode::Unsupported => ShareClientDeny::Unsupported,
        DenyCode::UnsupportedRequest => ShareClientDeny::UnsupportedRequest,
        DenyCode::Suspended => ShareClientDeny::Suspended,
        DenyCode::Revoked => ShareClientDeny::Revoked,
        DenyCode::Denied => ShareClientDeny::Denied,
        DenyCode::ReservedName => ShareClientDeny::ReservedName,
        DenyCode::NotFound => ShareClientDeny::NotFound,
        DenyCode::Conflict => ShareClientDeny::Conflict,
        DenyCode::RootGone => ShareClientDeny::RootGone,
        DenyCode::Quota => ShareClientDeny::Quota,
        DenyCode::TooLarge => ShareClientDeny::TooLarge,
        DenyCode::TooManyEntries => ShareClientDeny::TooManyEntries,
        DenyCode::Io => ShareClientDeny::Io,
        DenyCode::Cancelled => ShareClientDeny::Cancelled,
        DenyCode::TooLate => ShareClientDeny::TooLate,
        DenyCode::Interrupted => ShareClientDeny::Interrupted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::Utc;
    use iroh::endpoint::Connection;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh::{RelayMode, SecretKey};
    use tokio::sync::Mutex;

    use uc_core::membership::{MemberRepositoryPort, MembershipError, SpaceMember};
    use uc_core::ports::remote_share::{RemoteShareServePort, ShareServeError};
    use uc_core::ports::security::IdentityFingerprintFactoryPort;
    use uc_core::ports::{PeerAddressError, PeerAddressRecord};
    use uc_core::MemberSyncPreferences;
    use uc_infra_crypto::identity_fingerprint::Sha256IdentityFingerprintFactory;
    use uc_sync_protocol::remote_share::write_reply;

    use crate::network::iroh::remote_share::serve_adapter::IrohRemoteShareServeAdapter;

    // ----- test doubles ------------------------------------------------------

    /// In-memory peer-address store the client's resolver reads.
    #[derive(Default)]
    struct MemRepo {
        inner: Mutex<HashMap<String, PeerAddressRecord>>,
    }
    #[async_trait]
    impl PeerAddressRepositoryPort for MemRepo {
        async fn get(
            &self,
            device: &DeviceId,
        ) -> Result<Option<PeerAddressRecord>, PeerAddressError> {
            Ok(self.inner.lock().await.get(device.as_str()).cloned())
        }
        async fn upsert(&self, record: &PeerAddressRecord) -> Result<(), PeerAddressError> {
            self.inner
                .lock()
                .await
                .insert(record.device_id.as_str().to_string(), record.clone());
            Ok(())
        }
        async fn list(&self) -> Result<Vec<PeerAddressRecord>, PeerAddressError> {
            Ok(self.inner.lock().await.values().cloned().collect())
        }
        async fn remove(&self, device: &DeviceId) -> Result<(), PeerAddressError> {
            self.inner.lock().await.remove(device.as_str());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemMemberRepo {
        inner: Mutex<HashMap<String, SpaceMember>>,
    }
    crate::network::iroh::inbound_peer::member_table_identity_directory!(MemMemberRepo);
    #[async_trait]
    impl MemberRepositoryPort for MemMemberRepo {
        async fn get(&self, device_id: &DeviceId) -> Result<Option<SpaceMember>, MembershipError> {
            Ok(self.inner.lock().await.get(device_id.as_str()).cloned())
        }
        async fn list(&self) -> Result<Vec<SpaceMember>, MembershipError> {
            Ok(self.inner.lock().await.values().cloned().collect())
        }
        async fn save(&self, member: &SpaceMember) -> Result<(), MembershipError> {
            self.inner
                .lock()
                .await
                .insert(member.device_id.as_str().to_string(), member.clone());
            Ok(())
        }
        async fn remove(&self, device_id: &DeviceId) -> Result<bool, MembershipError> {
            Ok(self.inner.lock().await.remove(device_id.as_str()).is_some())
        }
    }

    /// Serve port answering each op with a canned result. Ops not under test
    /// in a given verdict keep their `Ok` default; a verdict flips exactly the
    /// field it exercises. `ShareServeError` is not `Clone`, so denial knobs are
    /// stored as unit-variant constructors.
    struct ScriptedServe {
        hello: ShareAvailability,
        roots: Vec<ShareRootDescriptor>,
        page: ShareDirectoryPage,
        entry: ShareDirectoryEntry,
        trash_page: ShareTrashPage,
        stage_id: String,
        export: ShareExportOutcome,
        mkdir_error: Option<fn() -> ShareServeError>,
        commit_error: Option<fn() -> ShareServeError>,
    }

    impl ScriptedServe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                hello: ShareAvailability::Ok,
                roots: Vec::new(),
                page: ShareDirectoryPage {
                    entries: Vec::new(),
                    next_after: None,
                },
                entry: ShareDirectoryEntry {
                    name: "note.txt".to_owned(),
                    is_dir: false,
                    is_symlink: false,
                    size_bytes: 42,
                    modified_at_ms: 1_700_000_000_000,
                },
                trash_page: ShareTrashPage {
                    entries: Vec::new(),
                    next_after: None,
                },
                stage_id: "stg-1".to_owned(),
                export: ShareExportOutcome {
                    ticket: uc_core::ports::blob::BlobTicket::from_bytes(vec![0xAB, 0xCD]),
                    size_bytes: 7,
                },
                mkdir_error: None,
                commit_error: None,
            })
        }
    }

    #[async_trait]
    impl RemoteShareServePort for ScriptedServe {
        async fn hello(&self) -> ShareAvailability {
            self.hello
        }
        async fn list_roots(
            &self,
            _peer: &DeviceId,
        ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
            Ok(self.roots.clone())
        }
        async fn list(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareDirectoryPage, ShareServeError> {
            Ok(ShareDirectoryPage {
                entries: self.page.entries.clone(),
                next_after: self.page.next_after.clone(),
            })
        }
        async fn stat(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareDirectoryEntry, ShareServeError> {
            Ok(ShareDirectoryEntry {
                name: self.entry.name.clone(),
                is_dir: self.entry.is_dir,
                is_symlink: self.entry.is_symlink,
                size_bytes: self.entry.size_bytes,
                modified_at_ms: self.entry.modified_at_ms,
            })
        }
        async fn mkdir(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<(), ShareServeError> {
            match self.mkdir_error {
                Some(deny) => Err(deny()),
                None => Ok(()),
            }
        }
        async fn rename(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), ShareServeError> {
            Ok(())
        }
        async fn delete(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<String, ShareServeError> {
            Ok("trash-1".to_owned())
        }
        async fn copy_within(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), ShareServeError> {
            Ok(())
        }
        async fn list_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareTrashPage, ShareServeError> {
            Ok(ShareTrashPage {
                entries: self.trash_page.entries.clone(),
                next_after: self.trash_page.next_after.clone(),
            })
        }
        async fn restore(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _trash_id: &str,
            _to: &str,
        ) -> Result<(), ShareServeError> {
            Ok(())
        }
        async fn empty_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
        ) -> Result<(), ShareServeError> {
            Ok(())
        }
        async fn stage_upload(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _dir: &str,
            _entries: &[ShareStageEntry],
            _transfer_id: ShareTransferId,
        ) -> Result<ShareStageOutcome, ShareServeError> {
            Ok(ShareStageOutcome {
                staging_id: self.stage_id.clone(),
            })
        }
        async fn commit_upload(
            &self,
            _peer: &DeviceId,
            _staging_ids: &[String],
        ) -> Result<(), ShareServeError> {
            match self.commit_error {
                Some(deny) => Err(deny()),
                None => Ok(()),
            }
        }
        async fn abort_upload(
            &self,
            _peer: &DeviceId,
            _staging_ids: &[String],
        ) -> Result<(), ShareServeError> {
            Ok(())
        }
        async fn export(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareExportOutcome, ShareServeError> {
            Ok(ShareExportOutcome {
                ticket: uc_core::ports::blob::BlobTicket::from_bytes(
                    self.export.ticket.as_bytes().to_vec(),
                ),
                size_bytes: self.export.size_bytes,
            })
        }
    }

    /// A rogue holder that reads the request then writes one fixed reply —
    /// exercises the client's `UnexpectedReply` handling without any admission
    /// gate (a reply-shape violation, not an identity check).
    #[derive(Debug)]
    struct RogueReply {
        reply: ShareReply,
    }

    impl ProtocolHandler for RogueReply {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => return Ok(()),
            };
            if share_wire::read_request(&mut recv).await.is_ok()
                && write_reply(&mut send, &self.reply).await.is_ok()
            {
                send.finish().ok();
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
            Ok(())
        }
    }

    /// A rogue holder that answers with a reply opcode this build does not
    /// know. `ShareReply::Unknown` is a decode-only fallback the encoder
    /// refuses, so the frame is written as raw bytes.
    #[derive(Debug)]
    struct RogueUnknownReply;

    impl ProtocolHandler for RogueUnknownReply {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => return Ok(()),
            };
            if share_wire::read_request(&mut recv).await.is_ok() {
                // Frame: "UCRS" | version | kind=Reply(2) | len=2 | opcode 0x7F
                // plus a spare trailing byte — the decoder maps the unknown
                // opcode onto `ShareReply::Unknown` and ignores the rest.
                let frame: [u8; 12] = [
                    b'U', b'C', b'R', b'S', 0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x7F, 0x00,
                ];
                if send.write_all(&frame).await.is_ok() {
                    send.finish().ok();
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
            Ok(())
        }
    }

    // ----- harness -----------------------------------------------------------

    async fn bind_endpoint_with(seed: [u8; 32]) -> Arc<Endpoint> {
        Arc::new(
            Endpoint::builder(iroh::endpoint::presets::N0)
                .secret_key(SecretKey::from_bytes(&seed))
                .alpns(vec![REMOTE_SHARE_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .expect("bind endpoint"),
        )
    }

    async fn wait_for_direct_addrs(endpoint: &Endpoint) {
        for _ in 0..100 {
            if !endpoint.addr().addrs.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("endpoint never published direct addresses");
    }

    fn make_member(seed: [u8; 32], device_id: &str) -> SpaceMember {
        let factory = Sha256IdentityFingerprintFactory;
        let sk = SecretKey::from_bytes(&seed);
        let fp = factory
            .from_public_key(sk.public().as_bytes())
            .expect("derive fingerprint for test member");
        SpaceMember {
            device_id: DeviceId::new(device_id),
            device_name: "Test Device".to_string(),
            identity_fingerprint: fp,
            joined_at: Utc::now(),
            sync_preferences: MemberSyncPreferences::default(),
        }
    }

    async fn seed_addr(repo: &MemRepo, device: &DeviceId, addr: &EndpointAddr) {
        let blob = postcard::to_stdvec(addr).expect("postcard encode EndpointAddr");
        repo.upsert(&PeerAddressRecord {
            device_id: device.clone(),
            addr_blob: blob,
            observed_at: Utc::now(),
        })
        .await
        .expect("upsert");
    }

    /// Spawn a real serve adapter for `requester` as a member; returns its addr.
    async fn spawn_serve(
        serve_seed: [u8; 32],
        requester_seed: [u8; 32],
        serve: Arc<dyn RemoteShareServePort>,
    ) -> (EndpointAddr, Router) {
        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        member_repo
            .save(&make_member(requester_seed, "requester"))
            .await
            .expect("save member");
        let endpoint = bind_endpoint_with(serve_seed).await;
        wait_for_direct_addrs(&endpoint).await;
        let adapter = IrohRemoteShareServeAdapter::new(
            crate::network::iroh::inbound_peer::member_table_directory(member_repo),
            Arc::new(crate::network::iroh::StaticPeerAdmission(true)),
            Arc::new(Sha256IdentityFingerprintFactory),
            serve,
        );
        let router = Router::builder((*endpoint).clone())
            .accept(REMOTE_SHARE_ALPN, adapter.handler())
            .spawn();
        (endpoint.addr(), router)
    }

    /// Client wired to `requester_seed` with `serve_addr` stored under `holder`.
    async fn client_for(
        requester_seed: [u8; 32],
        serve_addr: &EndpointAddr,
    ) -> (IrohRemoteShareClientAdapter, DeviceId) {
        let endpoint = bind_endpoint_with(requester_seed).await;
        wait_for_direct_addrs(&endpoint).await;
        let repo = Arc::new(MemRepo::default());
        let target = DeviceId::new("holder");
        seed_addr(&repo, &target, serve_addr).await;
        (IrohRemoteShareClientAdapter::new(endpoint, repo), target)
    }

    fn root_id() -> ShareRootId {
        let mut id = [0u8; 16];
        id[0] = 7;
        ShareRootId::from_wire_bytes(id)
    }

    // ----- verdicts ----------------------------------------------------------

    /// Verdict 1 — `hello` + `list_roots` round-trip over a real loopback pair:
    /// the reply variants decode and domain fields (grants/label) survive.
    #[tokio::test]
    async fn hello_and_list_roots_round_trip() {
        let requester_seed = [0x51u8; 32];
        let serve_seed = [0x52u8; 32];

        let mut scripted = ScriptedServe::new();
        Arc::get_mut(&mut scripted).unwrap().roots = vec![ShareRootDescriptor {
            id: root_id(),
            label: "Documents".to_owned(),
            grants: uc_core::ports::remote_share::ShareGrants {
                read: true,
                write: true,
                delete: false,
            },
            enabled: true,
        }];
        let (serve_addr, router) = spawn_serve(serve_seed, requester_seed, scripted).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        let availability = client.hello(&target).await.expect("hello succeeds");
        assert_eq!(availability, ShareAvailability::Ok);

        let roots = client.list_roots(&target).await.expect("roots succeed");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, root_id());
        assert!(roots[0].grants.read && roots[0].grants.write && !roots[0].grants.delete);

        router.shutdown().await.ok();
    }

    /// Verdict 2 — `list`/`stat`/`list_trash` decode paged payloads including the
    /// `next_after` cursor and the `is_symlink` flag.
    #[tokio::test]
    async fn browse_ops_round_trip_pages_and_flags() {
        let requester_seed = [0x53u8; 32];
        let serve_seed = [0x54u8; 32];

        let mut scripted = ScriptedServe::new();
        {
            let scripted = Arc::get_mut(&mut scripted).unwrap();
            scripted.page = ShareDirectoryPage {
                entries: vec![
                    ShareDirectoryEntry {
                        name: "src".to_owned(),
                        is_dir: true,
                        is_symlink: false,
                        size_bytes: 0,
                        modified_at_ms: 10,
                    },
                    ShareDirectoryEntry {
                        name: "link".to_owned(),
                        is_dir: false,
                        is_symlink: true,
                        size_bytes: 9,
                        modified_at_ms: 11,
                    },
                ],
                next_after: Some("link".to_owned()),
            };
            scripted.trash_page = ShareTrashPage {
                entries: vec![ShareTrashEntry {
                    trash_id: "t-9".to_owned(),
                    original_rel: "old/removed".to_owned(),
                    deleted_at_ms: 22,
                    is_dir: false,
                    size_bytes: 3,
                }],
                next_after: None,
            };
        }
        let (serve_addr, router) = spawn_serve(serve_seed, requester_seed, scripted).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        let page = client
            .list(&target, root_id(), "", None, 200)
            .await
            .expect("list succeeds");
        assert_eq!(page.entries.len(), 2);
        assert!(page.entries[0].is_dir);
        assert!(page.entries[1].is_symlink);
        assert_eq!(page.next_after.as_deref(), Some("link"));

        let entry = client
            .stat(&target, root_id(), "note.txt")
            .await
            .expect("stat succeeds");
        assert_eq!(entry.name, "note.txt");
        assert_eq!(entry.size_bytes, 42);

        let trash = client
            .list_trash(&target, root_id(), None, 50)
            .await
            .expect("trash page succeeds");
        assert_eq!(trash.entries.len(), 1);
        assert_eq!(trash.entries[0].trash_id, "t-9");
        assert_eq!(trash.entries[0].original_rel, "old/removed");

        router.shutdown().await.ok();
    }

    /// Verdict 3 — mutation verbs: `Ack` replies map to `Ok`, `Deleted` yields
    /// the `trash_id` handle.
    #[tokio::test]
    async fn mutation_ops_round_trip() {
        let requester_seed = [0x55u8; 32];
        let serve_seed = [0x56u8; 32];

        let (serve_addr, router) =
            spawn_serve(serve_seed, requester_seed, ScriptedServe::new()).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        client
            .mkdir(&target, root_id(), "new-dir")
            .await
            .expect("mkdir succeeds");
        client
            .rename(&target, root_id(), "a", "b")
            .await
            .expect("rename succeeds");
        client
            .copy_within(&target, root_id(), "a", "c")
            .await
            .expect("copy succeeds");
        client
            .restore(&target, root_id(), "t-1", "restored")
            .await
            .expect("restore succeeds");
        client
            .empty_trash(&target, root_id())
            .await
            .expect("empty succeeds");
        let trash_id = client
            .delete(&target, root_id(), "gone")
            .await
            .expect("delete succeeds");
        assert_eq!(trash_id, "trash-1");

        router.shutdown().await.ok();
    }

    /// Verdict 4 — transfer verbs: `staging_id` returns, `commit`/`abort` map
    /// `Ack` to `Ok`, and `export` returns the decoded ticket + size.
    #[tokio::test]
    async fn transfer_ops_round_trip() {
        let requester_seed = [0x57u8; 32];
        let serve_seed = [0x58u8; 32];

        let (serve_addr, router) =
            spawn_serve(serve_seed, requester_seed, ScriptedServe::new()).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        let outcome = client
            .stage_upload(
                &target,
                root_id(),
                "dest",
                &[ShareStageEntry {
                    rel: "f.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 5,
                    ticket: Some(uc_core::ports::blob::BlobTicket::from_bytes(vec![9])),
                }],
                ShareTransferId::from_bytes([1; 16]),
            )
            .await
            .expect("stage succeeds");
        assert_eq!(outcome.staging_id, "stg-1");

        client
            .commit_upload(&target, &["stg-1".to_owned()])
            .await
            .expect("commit succeeds");
        client
            .abort_upload(&target, &["stg-2".to_owned()])
            .await
            .expect("abort succeeds");

        let export = client
            .export(&target, root_id(), "f.bin")
            .await
            .expect("export succeeds");
        assert_eq!(export.ticket.as_bytes(), &[0xAB, 0xCD]);
        assert_eq!(export.size_bytes, 7);

        router.shutdown().await.ok();
    }

    /// Verdict 5 — typed `Denied` replies map to `Refused` with the mirrored
    /// deny code. First pass: a mixed holder (mkdir→Denied, commit→TooLate,
    /// stat succeeds). Second pass: an all-deny holder sweeps the table.
    #[tokio::test]
    async fn denied_maps_to_refused() {
        let requester_seed = [0x59u8; 32];
        let serve_seed = [0x5Au8; 32];

        let mut scripted = ScriptedServe::new();
        {
            let scripted = Arc::get_mut(&mut scripted).unwrap();
            scripted.mkdir_error = Some(|| ShareServeError::NotAuthorized);
            scripted.commit_error = Some(|| ShareServeError::TooLate);
        }
        let (serve_addr, router) = spawn_serve(serve_seed, requester_seed, scripted).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        match client.mkdir(&target, root_id(), "x").await {
            Err(RemoteShareClientError::Refused(deny)) => {
                assert_eq!(deny, ShareClientDeny::Denied)
            }
            other => panic!("expected Refused(Denied), got {other:?}"),
        }
        match client.commit_upload(&target, &["s".to_owned()]).await {
            Err(RemoteShareClientError::Refused(deny)) => {
                assert_eq!(deny, ShareClientDeny::TooLate)
            }
            other => panic!("expected Refused(TooLate), got {other:?}"),
        }
        // The same holder still answers a clean op — denial is per-request.
        client
            .stat(&target, root_id(), "note.txt")
            .await
            .expect("stat succeeds");

        router.shutdown().await.ok();

        // Second holder: every op denies with a distinct code.
        let requester_seed = [0x5Bu8; 32];
        let serve_seed = [0x5Cu8; 32];
        struct DenyServe;
        #[async_trait]
        impl RemoteShareServePort for DenyServe {
            async fn hello(&self) -> ShareAvailability {
                ShareAvailability::Ok
            }
            async fn list_roots(
                &self,
                _peer: &DeviceId,
            ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
                Err(ShareServeError::NotUnlocked)
            }
            async fn list(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
                _after: Option<&str>,
                _limit: u32,
            ) -> Result<ShareDirectoryPage, ShareServeError> {
                Err(ShareServeError::NotFound)
            }
            async fn stat(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
            ) -> Result<ShareDirectoryEntry, ShareServeError> {
                Err(ShareServeError::NotFound)
            }
            async fn mkdir(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::ReservedName)
            }
            async fn rename(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _from: &str,
                _to: &str,
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::Conflict)
            }
            async fn delete(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
            ) -> Result<String, ShareServeError> {
                Err(ShareServeError::RootGone)
            }
            async fn copy_within(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _from: &str,
                _to: &str,
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::TooLarge)
            }
            async fn list_trash(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _after: Option<&str>,
                _limit: u32,
            ) -> Result<ShareTrashPage, ShareServeError> {
                Err(ShareServeError::Suspended)
            }
            async fn restore(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _trash_id: &str,
                _to: &str,
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::NotFound)
            }
            async fn empty_trash(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::Io)
            }
            async fn stage_upload(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _dir: &str,
                _entries: &[ShareStageEntry],
                _transfer_id: ShareTransferId,
            ) -> Result<ShareStageOutcome, ShareServeError> {
                Err(ShareServeError::TooLarge)
            }
            async fn commit_upload(
                &self,
                _peer: &DeviceId,
                _staging_ids: &[String],
            ) -> Result<(), ShareServeError> {
                Err(ShareServeError::TooLate)
            }
            async fn abort_upload(
                &self,
                _peer: &DeviceId,
                _staging_ids: &[String],
            ) -> Result<(), ShareServeError> {
                Ok(())
            }
            async fn export(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
            ) -> Result<ShareExportOutcome, ShareServeError> {
                Err(ShareServeError::UnsupportedRequest)
            }
        }
        let (serve_addr, router) =
            spawn_serve(serve_seed, requester_seed, Arc::new(DenyServe)).await;
        let (client, target) = client_for(requester_seed, &serve_addr).await;

        let cases = [
            (
                client
                    .list(&target, root_id(), "", None, 1)
                    .await
                    .map(|_| ()),
                ShareClientDeny::NotFound,
            ),
            (
                client.mkdir(&target, root_id(), "x").await,
                ShareClientDeny::ReservedName,
            ),
            (
                client.rename(&target, root_id(), "a", "b").await,
                ShareClientDeny::Conflict,
            ),
            (
                client.delete(&target, root_id(), "x").await.map(|_| ()),
                ShareClientDeny::RootGone,
            ),
            (
                client.copy_within(&target, root_id(), "a", "b").await,
                ShareClientDeny::TooLarge,
            ),
            (
                client
                    .list_trash(&target, root_id(), None, 1)
                    .await
                    .map(|_| ()),
                ShareClientDeny::Suspended,
            ),
            (
                client.empty_trash(&target, root_id()).await,
                ShareClientDeny::Io,
            ),
            (
                client.commit_upload(&target, &["s".to_owned()]).await,
                ShareClientDeny::TooLate,
            ),
        ];
        for (result, expected) in cases {
            match result {
                Err(RemoteShareClientError::Refused(deny)) => assert_eq!(deny, expected),
                other => panic!("expected Refused({expected:?}), got {other:?}"),
            }
        }
        match client.export(&target, root_id(), "x").await {
            Err(RemoteShareClientError::Refused(deny)) => {
                assert_eq!(deny, ShareClientDeny::UnsupportedRequest)
            }
            other => panic!("expected Refused(UnsupportedRequest), got {other:?}"),
        }
        match client.list_roots(&target).await {
            Err(RemoteShareClientError::Refused(deny)) => {
                assert_eq!(deny, ShareClientDeny::Locked)
            }
            other => panic!("expected Refused(Locked), got {other:?}"),
        }

        router.shutdown().await.ok();
    }

    /// Verdict 6 — no stored address → `Unreachable` without touching the
    /// network.
    #[tokio::test]
    async fn missing_address_is_unreachable() {
        let endpoint = bind_endpoint_with([0x61u8; 32]).await;
        let repo = Arc::new(MemRepo::default());
        let client = IrohRemoteShareClientAdapter::new(endpoint, repo);

        match client.hello(&DeviceId::new("never-seen")).await {
            Err(RemoteShareClientError::Unreachable) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    /// Verdict 7 — the stored address points at a peer that does not serve the
    /// share ALPN → dial fails → `Unreachable`.
    #[tokio::test]
    async fn wrong_alpn_peer_is_unreachable() {
        // An endpoint bound for a different ALPN; connecting on the share ALPN
        // fails the protocol negotiation locally and quickly.
        let other = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(SecretKey::from_bytes(&[0x62u8; 32]))
            .alpns(vec![b"uniclipboard/other/1".to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind other endpoint");
        wait_for_direct_addrs(&other).await;

        let endpoint = bind_endpoint_with([0x63u8; 32]).await;
        wait_for_direct_addrs(&endpoint).await;
        let repo = Arc::new(MemRepo::default());
        let target = DeviceId::new("not-a-share-peer");
        seed_addr(&repo, &target, &other.addr()).await;
        let client = IrohRemoteShareClientAdapter::new(endpoint, repo);

        match client.hello(&target).await {
            Err(RemoteShareClientError::Unreachable) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }

    /// Verdict 8 — a reply variant that doesn't match the request is a protocol
    /// violation → `UnexpectedReply` (rogue holder answers `Roots` to `Hello`).
    #[tokio::test]
    async fn mismatched_reply_is_unexpected() {
        let rogue = bind_endpoint_with([0x64u8; 32]).await;
        wait_for_direct_addrs(&rogue).await;
        let router = Router::builder((*rogue).clone())
            .accept(
                REMOTE_SHARE_ALPN,
                RogueReply {
                    reply: ShareReply::Roots { roots: vec![] },
                },
            )
            .spawn();

        let (client, target) = client_for([0x65u8; 32], &rogue.addr()).await;
        match client.hello(&target).await {
            Err(RemoteShareClientError::UnexpectedReply) => {}
            other => panic!("expected UnexpectedReply, got {other:?}"),
        }

        router.shutdown().await.ok();
    }

    /// Verdict 9 — a wire reply opcode this build does not know decodes to
    /// `Unknown` and maps to `Refused(UnsupportedRequest)` — a newer holder
    /// answering an op it can't serve still yields a typed client failure.
    #[tokio::test]
    async fn unknown_reply_maps_to_unsupported_request() {
        let rogue = bind_endpoint_with([0x66u8; 32]).await;
        wait_for_direct_addrs(&rogue).await;
        let router = Router::builder((*rogue).clone())
            .accept(REMOTE_SHARE_ALPN, RogueUnknownReply)
            .spawn();

        let (client, target) = client_for([0x67u8; 32], &rogue.addr()).await;
        match client.hello(&target).await {
            Err(RemoteShareClientError::Refused(deny)) => {
                assert_eq!(deny, ShareClientDeny::UnsupportedRequest)
            }
            other => panic!("expected Refused(UnsupportedRequest), got {other:?}"),
        }

        router.shutdown().await.ok();
    }
}
