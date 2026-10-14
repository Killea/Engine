//! Iroh-backed accept handler for the `remote-share/1` control plane (holder side).
//!
//! Registered under [`REMOTE_SHARE_ALPN`]. Each inbound connection runs one
//! request → reply exchange: the requester (the viewer) sends a
//! [`ShareRequest`], the handler admits the peer, resolves the request through the
//! application-layer [`RemoteShareServePort`] (authorize + confine + read), and writes
//! back a [`ShareReply`] — metadata or a typed denial. **No bulk bytes travel here**;
//! file content goes over the separate iroh-blobs path.
//!
//! ## Admission
//!
//! Same member-fingerprint admission as the active-clipboard pull path: the inbound
//! `remote_id()` is resolved to a `DeviceId` via the shared [`InboundPeerGate`], and
//! unknown peers are dropped before any request is read. The serve port itself then
//! enforces the per-root authorization + path confinement (see
//! `RemoteShareServe` in `uc-application`).
//!
//! ## Domain → wire
//!
//! The serve port returns domain types (no holder-local paths); this adapter is the
//! single place that maps them onto the wire DTOs and maps a [`ShareServeError`] onto
//! the payload-free [`DenyCode`]. A root that is authorized but not registered in the
//! confinement registry (`RootGone`) has no distinct wire code and surfaces as
//! `NotFound` (fail-closed, opaque).

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use uc_application::deps::PeerIdentityDirectoryPort;
use uc_core::ids::DeviceId;
use uc_core::membership::PeerAdmissionPort;
use uc_core::ports::remote_share::{
    RemoteShareServePort, ShareAvailability, ShareDirectoryEntry, ShareRootDescriptor, ShareRootId,
    ShareServeError,
};
use uc_core::ports::security::IdentityFingerprintFactoryPort;
use uc_observability_contract::{
    diagnostics::connectivity::InboundPeerProtocol, error_source::io_error_kind, uc_debug, uc_warn,
};
use uc_sync_protocol::remote_share::{
    self as share_wire, DenyCode, HelloState, ShareReply, ShareRequest, WireDirectoryEntry,
    WireShareGrants, WireShareRoot,
};

use super::super::inbound_peer::InboundPeerGate;

/// Upper bound on waiting for the requester to drain + close after we write the reply.
/// A cooperative requester closes within a couple of round trips; this only caps the
/// pathological "reads reply but never closes" peer so one bad peer can't pin an
/// accept task.
const CLOSE_BARRIER_TIMEOUT: Duration = Duration::from_secs(3);

/// Serve-side adapter. Resolves `remote_id → DeviceId` for admission and delegates
/// request resolution to the application-layer serve port.
pub struct IrohRemoteShareServeAdapter {
    state: Arc<HandlerState>,
}

struct HandlerState {
    gate: InboundPeerGate,
    serve: Arc<dyn RemoteShareServePort>,
}

impl IrohRemoteShareServeAdapter {
    pub fn new(
        identities: Arc<dyn PeerIdentityDirectoryPort>,
        peer_admission: Arc<dyn PeerAdmissionPort>,
        fingerprint_factory: Arc<dyn IdentityFingerprintFactoryPort>,
        serve: Arc<dyn RemoteShareServePort>,
    ) -> Self {
        Self {
            state: Arc::new(HandlerState {
                gate: InboundPeerGate::new(
                    InboundPeerProtocol::RemoteShare,
                    identities,
                    peer_admission,
                    fingerprint_factory,
                ),
                serve,
            }),
        }
    }

    /// Cheap clone-able handle registered with iroh's `RouterBuilder`.
    pub fn handler(&self) -> IrohRemoteShareServeHandler {
        IrohRemoteShareServeHandler {
            state: Arc::clone(&self.state),
        }
    }
}

#[derive(Clone)]
pub struct IrohRemoteShareServeHandler {
    state: Arc<HandlerState>,
}

impl std::fmt::Debug for IrohRemoteShareServeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohRemoteShareServeHandler")
            .finish_non_exhaustive()
    }
}

impl IrohRemoteShareServeHandler {
    /// Resolve one admitted peer's request through the serve port and map the result
    /// onto a wire [`ShareReply`].
    async fn serve_request(&self, peer: &DeviceId, request: &ShareRequest) -> ShareReply {
        match request {
            ShareRequest::Hello => ShareReply::Hello {
                state: availability_to_hello_state(self.state.serve.hello().await),
            },
            ShareRequest::ListRoots => match self.state.serve.list_roots(peer).await {
                Ok(roots) => ShareReply::Roots {
                    roots: roots.into_iter().map(descriptor_to_wire).collect(),
                },
                Err(error) => ShareReply::Denied {
                    code: serve_error_to_deny_code(error),
                },
            },
            ShareRequest::List {
                root_id,
                path,
                after,
                limit,
            } => {
                let root = ShareRootId::from_wire_bytes(*root_id);
                match self
                    .state
                    .serve
                    .list(peer, root, path, after.as_deref(), *limit)
                    .await
                {
                    Ok(page) => ShareReply::Entries {
                        entries: page.entries.iter().map(entry_to_wire).collect(),
                        next_after: page.next_after.clone(),
                    },
                    Err(error) => ShareReply::Denied {
                        code: serve_error_to_deny_code(error),
                    },
                }
            }
            ShareRequest::Stat { root_id, path } => {
                let root = ShareRootId::from_wire_bytes(*root_id);
                match self.state.serve.stat(peer, root, path).await {
                    Ok(entry) => ShareReply::Entry {
                        entry: entry_to_wire(&entry),
                    },
                    Err(error) => ShareReply::Denied {
                        code: serve_error_to_deny_code(error),
                    },
                }
            }
        }
    }
}

impl ProtocolHandler for IrohRemoteShareServeHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let remote_bytes: [u8; 32] = *remote.as_bytes();

        // 1. Member-fingerprint admission only. Unknown peers never reach the serve
        //    port, and no request bytes are read for them.
        let peer = match self.state.gate.admit(&remote_bytes).await {
            Ok(device) => device,
            Err(rejection) => {
                self.state.gate.record_rejection(rejection);
                return Ok(());
            }
        };

        // 2. Accept the bi-stream. The requester opens it, writes the request, and
        //    reads our reply on the same stream.
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(err) => {
                uc_warn!(
                    error_kind = "accept_bi",
                    io_error_kind = io_error_kind(&err),
                    "remote-share serve: accept_bi failed; dropping connection"
                );
                return Ok(());
            }
        };

        // 3. Read the request frame. A codec failure (bad magic, oversize, non-UTF8)
        //    drops the connection — the field is untrusted peer input and the codec
        //    validates lengths before allocating.
        let request = match share_wire::read_request(&mut recv).await {
            Ok(req) => req,
            Err(err) => {
                uc_warn!(
                    error_kind = "request_decode",
                    io_error_kind = io_error_kind(&err),
                    "remote-share serve: request decode failed; dropping connection"
                );
                return Ok(());
            }
        };

        // 4. Resolve through the serve port and map to a wire reply.
        let reply = self.serve_request(&peer, &request).await;

        // 5. Write the reply frame, then close the send half.
        if let Err(err) = share_wire::write_reply(&mut send, &reply).await {
            uc_warn!(
                error_kind = "reply_write",
                io_error_kind = io_error_kind(&err),
                "remote-share serve: reply write failed; dropping connection"
            );
            return Ok(());
        }
        if let Err(err) = send.finish() {
            uc_debug!(
                error_kind = "send_finish",
                io_error_kind = io_error_kind(&err),
                "remote-share serve: send.finish failed"
            );
        }

        // 6. Wait for the requester to drain + close before dropping the connection,
        //    so the QUIC teardown does not race its final read.
        let _ = tokio::time::timeout(CLOSE_BARRIER_TIMEOUT, connection.closed()).await;
        Ok(())
    }
}

// ============================================================================
// Domain → wire mapping
// ============================================================================

fn availability_to_hello_state(availability: ShareAvailability) -> HelloState {
    match availability {
        ShareAvailability::Ok => HelloState::Ok,
        ShareAvailability::Locked => HelloState::Locked,
        ShareAvailability::Unsupported => HelloState::Unsupported,
        ShareAvailability::Suspended => HelloState::Suspended,
    }
}

fn descriptor_to_wire(descriptor: ShareRootDescriptor) -> WireShareRoot {
    WireShareRoot {
        id: descriptor.id.as_bytes(),
        label: descriptor.label,
        grants: WireShareGrants {
            read: descriptor.grants.read,
            write: descriptor.grants.write,
            delete: descriptor.grants.delete,
        },
        enabled: descriptor.enabled,
    }
}

fn entry_to_wire(entry: &ShareDirectoryEntry) -> WireDirectoryEntry {
    WireDirectoryEntry {
        name: entry.name.clone(),
        is_dir: entry.is_dir,
        size_bytes: entry.size_bytes,
        modified_at_ms: entry.modified_at_ms,
    }
}

/// Map a serve error onto the wire denial code. The mapping is total: the only
/// non-1:1 case is `RootGone` (an authorized-but-unregistered root), which has no
/// distinct wire code and surfaces as `NotFound`.
fn serve_error_to_deny_code(error: ShareServeError) -> DenyCode {
    match error {
        ShareServeError::NotUnlocked => DenyCode::NotUnlocked,
        ShareServeError::NotAuthorized => DenyCode::NotAuthorized,
        ShareServeError::NotFound => DenyCode::NotFound,
        ShareServeError::IsADirectory => DenyCode::IsADirectory,
        ShareServeError::NotADirectory => DenyCode::NotADirectory,
        ShareServeError::ReservedName => DenyCode::ReservedName,
        ShareServeError::Suspended => DenyCode::Suspended,
        ShareServeError::RootGone => DenyCode::NotFound,
        ShareServeError::Io => DenyCode::Io,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uc_core::membership::MemberRepositoryPort;

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::Utc;
    use iroh::protocol::Router;
    use iroh::{Endpoint, RelayMode, SecretKey};
    use tokio::sync::Mutex;

    use uc_core::membership::{MembershipError, SpaceMember};
    use uc_core::ports::remote_share::{ShareDirectoryPage, ShareGrants};
    use uc_core::MemberSyncPreferences;

    use uc_infra_crypto::identity_fingerprint::Sha256IdentityFingerprintFactory;
    use uc_sync_protocol::remote_share::{
        read_reply, write_request, WireShareRootId, REMOTE_SHARE_ALPN,
    };

    // ----- test doubles ------------------------------------------------------

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

    fn root_id() -> ShareRootId {
        let mut id = [0u8; 16];
        id[0] = 1;
        ShareRootId::from_wire_bytes(id)
    }

    fn sample_root_descriptor(id: WireShareRootId) -> ShareRootDescriptor {
        ShareRootDescriptor {
            id: ShareRootId::from_wire_bytes(id),
            label: "Documents".to_owned(),
            grants: ShareGrants {
                read: true,
                write: true,
                delete: false,
            },
            enabled: true,
        }
    }

    /// A `RemoteShareServePort` that answers each op with a canned value.
    struct StubServe {
        hello: ShareAvailability,
        roots: Arc<Mutex<Vec<ShareRootDescriptor>>>,
        entries: Arc<Mutex<Vec<ShareDirectoryEntry>>>,
    }

    impl StubServe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                hello: ShareAvailability::Ok,
                roots: Arc::new(Mutex::new(Vec::new())),
                entries: Arc::new(Mutex::new(Vec::new())),
            })
        }
    }

    #[async_trait]
    impl RemoteShareServePort for StubServe {
        async fn hello(&self) -> ShareAvailability {
            self.hello
        }
        async fn list_roots(
            &self,
            _peer: &DeviceId,
        ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
            Ok(self.roots.lock().await.clone())
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
                entries: self.entries.lock().await.clone(),
                next_after: None,
            })
        }
        async fn stat(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareDirectoryEntry, ShareServeError> {
            Ok(ShareDirectoryEntry {
                name: "note.txt".to_owned(),
                is_dir: false,
                size_bytes: 42,
                modified_at_ms: 1_700_000_000_000,
            })
        }
    }

    /// A serve port that panics if reached — proves an unknown peer never reaches it.
    struct NeverServe;
    #[async_trait]
    impl RemoteShareServePort for NeverServe {
        async fn hello(&self) -> ShareAvailability {
            panic!("serve reached past the admission gate")
        }
        async fn list_roots(
            &self,
            _peer: &DeviceId,
        ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
            panic!("serve reached past the admission gate")
        }
        async fn list(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareDirectoryPage, ShareServeError> {
            panic!("serve reached past the admission gate")
        }
        async fn stat(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareDirectoryEntry, ShareServeError> {
            panic!("serve reached past the admission gate")
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

    async fn spawn_serve(
        seed: [u8; 32],
        member_repo: Arc<dyn MemberRepositoryPort>,
        serve: Arc<dyn RemoteShareServePort>,
    ) -> (Arc<Endpoint>, Router) {
        let endpoint = bind_endpoint_with(seed).await;
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
        (endpoint, router)
    }

    /// Open a bi-stream, send a request, return the decoded reply.
    async fn share_request(
        sender_seed: [u8; 32],
        receiver_addr: iroh::EndpointAddr,
        request: &ShareRequest,
    ) -> Result<ShareReply, String> {
        let sender = bind_endpoint_with(sender_seed).await;
        wait_for_direct_addrs(&sender).await;
        let conn = sender
            .connect(receiver_addr, REMOTE_SHARE_ALPN)
            .await
            .expect("dial serve");
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|err| format!("open stream: {err}"))?;
        write_request(&mut send, request)
            .await
            .map_err(|err| format!("write request: {err}"))?;
        send.finish()
            .map_err(|err| format!("finish request: {err}"))?;
        let reply = read_reply(&mut recv)
            .await
            .map_err(|err| format!("read reply: {err}"));
        let _ = conn.closed().await;
        reply
    }

    // ----- verdicts ----------------------------------------------------------

    /// Verdict 1 — a known member's `ListRoots` is served: the descriptors reach the
    /// serve port and round-trip as wire roots (id bytes + grants preserved).
    #[tokio::test]
    async fn member_list_roots_is_served() {
        let sender_seed = [0x11u8; 32];
        let receiver_seed = [0x22u8; 32];

        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        member_repo
            .save(&make_member(sender_seed, "member-a"))
            .await
            .unwrap();

        let serve = StubServe::new();
        let mut rid = [0u8; 16];
        rid[15] = 0xAB;
        serve.roots.lock().await.push(sample_root_descriptor(rid));
        let (endpoint, router) = spawn_serve(
            receiver_seed,
            Arc::clone(&member_repo),
            Arc::clone(&serve) as _,
        )
        .await;

        let reply = share_request(sender_seed, endpoint.addr(), &ShareRequest::ListRoots)
            .await
            .expect("reply decodes");
        match reply {
            ShareReply::Roots { roots } => {
                assert_eq!(roots.len(), 1);
                assert_eq!(roots[0].id, rid);
                assert!(roots[0].grants.read && roots[0].grants.write && !roots[0].grants.delete);
            }
            other => panic!("expected Roots, got {other:?}"),
        }

        router.shutdown().await.ok();
    }

    /// Verdict 2 — a `Hello` on an unlocked, active holder reports `Ok`.
    #[tokio::test]
    async fn member_hello_reports_ok() {
        let sender_seed = [0x33u8; 32];
        let receiver_seed = [0x44u8; 32];
        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        member_repo
            .save(&make_member(sender_seed, "member-a"))
            .await
            .unwrap();

        let serve = StubServe::new();
        let (endpoint, router) = spawn_serve(
            receiver_seed,
            Arc::clone(&member_repo),
            Arc::clone(&serve) as _,
        )
        .await;

        let reply = share_request(sender_seed, endpoint.addr(), &ShareRequest::Hello)
            .await
            .expect("reply decodes");
        assert_eq!(
            reply,
            ShareReply::Hello {
                state: HelloState::Ok
            }
        );

        router.shutdown().await.ok();
    }

    /// Verdict 3 — a `List` reply carries the domain entries verbatim and maps the
    /// root id correctly; a `Stat` reply carries a single entry.
    #[tokio::test]
    async fn member_list_and_stat_are_served() {
        let sender_seed = [0x55u8; 32];
        let receiver_seed = [0x66u8; 32];
        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        member_repo
            .save(&make_member(sender_seed, "member-a"))
            .await
            .unwrap();

        let serve = StubServe::new();
        serve.entries.lock().await.push(ShareDirectoryEntry {
            name: "a.txt".to_owned(),
            is_dir: false,
            size_bytes: 7,
            modified_at_ms: 123,
        });
        let (endpoint, router) = spawn_serve(
            receiver_seed,
            Arc::clone(&member_repo),
            Arc::clone(&serve) as _,
        )
        .await;

        let rid = root_id().as_bytes();
        let list_reply = share_request(
            sender_seed,
            endpoint.addr(),
            &ShareRequest::List {
                root_id: rid,
                path: String::new(),
                after: None,
                limit: 100,
            },
        )
        .await
        .expect("list reply decodes");
        match list_reply {
            ShareReply::Entries {
                entries,
                next_after,
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "a.txt");
                assert_eq!(entries[0].size_bytes, 7);
                assert!(next_after.is_none());
            }
            other => panic!("expected Entries, got {other:?}"),
        }

        let stat_reply = share_request(
            sender_seed,
            endpoint.addr(),
            &ShareRequest::Stat {
                root_id: rid,
                path: "note.txt".to_owned(),
            },
        )
        .await
        .expect("stat reply decodes");
        match stat_reply {
            ShareReply::Entry { entry } => {
                assert_eq!(entry.name, "note.txt");
                assert_eq!(entry.size_bytes, 42);
            }
            other => panic!("expected Entry, got {other:?}"),
        }

        router.shutdown().await.ok();
    }

    /// Verdict 4 — an unknown peer (fingerprint not in the member repo) is dropped at
    /// the admission gate; the serve port is never reached and the dial gets no reply
    /// frame (the read hits EOF → io error).
    #[tokio::test]
    async fn unknown_peer_is_dropped_before_serve() {
        let sender_seed = [0x77u8; 32];
        let receiver_seed = [0x88u8; 32];

        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        let (endpoint, router) = spawn_serve(
            receiver_seed,
            Arc::clone(&member_repo),
            Arc::new(NeverServe),
        )
        .await;

        let reply = share_request(sender_seed, endpoint.addr(), &ShareRequest::Hello).await;
        assert!(reply.is_err(), "unknown peer must not get a reply frame");

        router.shutdown().await.ok();
    }

    /// Verdict 5 — a serve error maps to the right wire denial code (here `RootGone`
    /// → `NotFound`), and a locked holder's `list_roots` → `NotUnlocked`.
    #[tokio::test]
    async fn serve_errors_map_to_deny_codes() {
        // RootGone → NotFound on a List.
        struct RootGoneServe;
        #[async_trait]
        impl RemoteShareServePort for RootGoneServe {
            async fn hello(&self) -> ShareAvailability {
                ShareAvailability::Ok
            }
            async fn list_roots(
                &self,
                _peer: &DeviceId,
            ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
                Ok(Vec::new())
            }
            async fn list(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
                _after: Option<&str>,
                _limit: u32,
            ) -> Result<ShareDirectoryPage, ShareServeError> {
                Err(ShareServeError::RootGone)
            }
            async fn stat(
                &self,
                _peer: &DeviceId,
                _root: ShareRootId,
                _rel: &str,
            ) -> Result<ShareDirectoryEntry, ShareServeError> {
                Err(ShareServeError::RootGone)
            }
        }

        let sender_seed = [0x99u8; 32];
        let receiver_seed = [0xAAu8; 32];
        let member_repo: Arc<dyn MemberRepositoryPort> = Arc::new(MemMemberRepo::default());
        member_repo
            .save(&make_member(sender_seed, "member-a"))
            .await
            .unwrap();
        let (endpoint, router) = spawn_serve(
            receiver_seed,
            Arc::clone(&member_repo),
            Arc::new(RootGoneServe),
        )
        .await;

        let rid = root_id().as_bytes();
        let reply = share_request(
            sender_seed,
            endpoint.addr(),
            &ShareRequest::List {
                root_id: rid,
                path: String::new(),
                after: None,
                limit: 10,
            },
        )
        .await
        .expect("denial reply decodes");
        assert_eq!(
            reply,
            ShareReply::Denied {
                code: DenyCode::NotFound
            }
        );

        router.shutdown().await.ok();
    }
}
