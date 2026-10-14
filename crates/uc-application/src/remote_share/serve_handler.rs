//! The device-file-share serve handler: turn an already-admitted peer's control-plane
//! request into holder-independent metadata.
//!
//! This is the `RemoteShareServePort` implementation the `remote-share/1` serve adapter
//! (in `uc-infra-p2p`) calls behind `Arc<dyn _>`. It is the single place that enforces
//! the two-fact AND that `ShareConfinementPort::resolve` and the authorizer each enforce
//! only half of (spec §5.2, steps 3–6):
//!
//!   1. **authorize** — the store says `peer` may `op` on `root` (fail-closed);
//!   2. **confine** — the cap-std registry resolves the peer's relative path under
//!      `root` to a `ConfinedTarget`;
//! and only when both succeed does it
//!   3. **read** — open `real_path` under the process's environment permission and
//!      collect metadata.
//!
//! The ordering is fixed: authorize before confine, and a successful `resolve` is never
//! treated as authorization on its own (see the `ShareConfinementPort` docs).
//!
//! The file-system reads are blocking (`std::fs`), so they run on the blocking thread
//! pool via `spawn_blocking` — the confinement port's own system calls are synchronous
//! and the caller must not assume they are offloaded.
//!
//! No holder-local path crosses this boundary: the reads operate on `real_path` (a
//! `ConfinedTarget` field that is redacted in `Debug` and never placed in a log), and
//! the returned pages carry only names, sizes, and mtimes. The read-only residual — a
//! `real_path` can change between confine and read — is documented in ADR-034 and is
//! closed by the capability-handle redesign (a P2 prerequisite, out of scope here).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use uc_core::ids::DeviceId;
use uc_core::ports::remote_share::{
    is_well_formed_relative, ConfineError, ConfinedTarget, RemoteShareServePort, ShareAvailability,
    ShareConfinementPort, ShareDirectoryEntry, ShareDirectoryPage, ShareOperation,
    ShareRootDescriptor, ShareRootId, ShareServeError, SharedRootStorePort,
};

use crate::remote_share::authorizer::ShareAuthorizer;

/// Ports the serve handler consumes.
pub struct RemoteShareServeDeps {
    /// The encrypted shared-root store. Unreadable (space locked) ⇒ fail-closed.
    pub share_store: Arc<dyn SharedRootStorePort>,
    /// The cap-std confinement registry (root lifecycle + path resolution).
    pub confinement: Arc<dyn ShareConfinementPort>,
}

/// The serve-side handler. Thread-safe; put in `Arc`.
pub struct RemoteShareServe {
    store: Arc<dyn SharedRootStorePort>,
    authorizer: ShareAuthorizer,
    confinement: Arc<dyn ShareConfinementPort>,
}

impl RemoteShareServe {
    pub fn new(deps: RemoteShareServeDeps) -> Self {
        let RemoteShareServeDeps {
            share_store,
            confinement,
        } = deps;
        Self {
            store: share_store.clone(),
            authorizer: ShareAuthorizer::new(share_store),
            confinement,
        }
    }

    /// Re-check that the store authorizes `peer` for `op` on `root`; fail-closed on any
    /// denial or store failure.
    async fn require_authorized(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        op: ShareOperation,
    ) -> Result<(), ShareServeError> {
        if self.authorizer.authorize(peer, root, op).await.is_none() {
            return Err(ShareServeError::NotAuthorized);
        }
        Ok(())
    }

    /// Resolve `rel` under `root` to a `ConfinedTarget`, enforcing the host-independent
    /// wire grammar on any non-empty `rel`. The empty `rel` lists/stats the root itself
    /// via the explicit `resolve_root` port method, not a `""`/`.` sentinel into
    /// `resolve`.
    async fn resolve_target(
        &self,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ConfinedTarget, ShareServeError> {
        if rel.is_empty() {
            return self
                .confinement
                .resolve_root(root)
                .await
                .map_err(map_confine);
        }
        // A non-empty relative path must satisfy the wire grammar before it is walked;
        // a malformed path is an opaque denial, not a `Denied` echo of the input.
        if !is_well_formed_relative(rel) {
            return Err(ShareServeError::NotAuthorized);
        }
        self.confinement
            .resolve(root, rel)
            .await
            .map_err(map_confine)
    }
}

#[async_trait]
impl RemoteShareServePort for RemoteShareServe {
    async fn hello(&self) -> ShareAvailability {
        match self.store.load().await {
            Ok(doc) => {
                if doc.suspended {
                    ShareAvailability::Suspended
                } else {
                    ShareAvailability::Ok
                }
            }
            // Fail-closed: an unreadable store (locked / corrupt / over-capacity) is
            // reported as Locked, never as Ok or a partial view.
            Err(_) => ShareAvailability::Locked,
        }
    }

    async fn list_roots(
        &self,
        peer: &DeviceId,
    ) -> Result<Vec<ShareRootDescriptor>, ShareServeError> {
        // `peer` is carried for correlation and future per-device tightening; the current
        // decision granularity is root + grant, not per-device (see ShareAuthorizer).
        let _ = peer;
        let doc = self
            .store
            .load()
            .await
            // discarded-source[business-outcome]: `SharedRootStoreError`: the wire
            // `DenyCode` is a fixed classification enum with no source slot; a store
            // failure is reclassified to `NotUnlocked` (fail-closed) and is already
            // logged at its origin by the store implementation.
            .map_err(|_| ShareServeError::NotUnlocked)?;
        if doc.suspended {
            return Err(ShareServeError::Suspended);
        }
        Ok(doc
            .roots
            .iter()
            .filter(|root| root.enabled)
            .map(|root| ShareRootDescriptor {
                id: root.id,
                label: root.label.clone(),
                grants: root.grants,
                enabled: root.enabled,
            })
            .collect())
    }

    async fn list(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareDirectoryPage, ShareServeError> {
        // Step 1: authorize (store). A successful step 2 below is never authorization.
        self.require_authorized(peer, root, ShareOperation::List)
            .await?;
        // Step 2: confine (path).
        let target = self.resolve_target(root, rel).await?;
        // Step 3: read under environment permission, off the async runtime.
        let real_path = target.real_path.clone();
        let cursor = after.map(str::to_owned);
        tokio::task::spawn_blocking(move || read_dir_confined(&real_path, cursor.as_deref(), limit))
            .await
            // discarded-source[no-information]: `JoinError`: a task abort or runtime
            // teardown carries no share-specific diagnostic; the wire only knows `Io`.
            .map_err(|_| ShareServeError::Io)?
    }

    async fn stat(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareDirectoryEntry, ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Read)
            .await?;
        let target = self.resolve_target(root, rel).await?;
        let real_path = target.real_path.clone();
        let name = entry_name(rel, &real_path);
        tokio::task::spawn_blocking(move || stat_confined(&real_path, &name))
            .await
            // discarded-source[no-information]: `JoinError`: a task abort or runtime
            // teardown carries no share-specific diagnostic; the wire only knows `Io`.
            .map_err(|_| ShareServeError::Io)?
    }
}

/// Map a confinement error to the serve taxonomy.
fn map_confine(error: ConfineError) -> ShareServeError {
    match error {
        ConfineError::Denied => ShareServeError::NotAuthorized,
        ConfineError::ReservedName => ShareServeError::ReservedName,
        ConfineError::RootGone => ShareServeError::RootGone,
        // The confinement `Io { source }` variant discards the source here: it is a
        // reclassification into the payload-free wire `Io` code, which has no slot for
        // a lower-layer error.
        ConfineError::Io { .. } => ShareServeError::Io,
    }
}

/// A `std::io::Error` from a confined read maps to the opaque `Io` code.
fn share_io_error(error: std::io::Error) -> ShareServeError {
    // discarded-source[no-information]: `std::io::Error`: it carries no path or
    // diagnostic that the payload-free wire `Io` code would surface.
    let _ = error;
    ShareServeError::Io
}

/// List `real_path`'s entries, paginated by name (spec §8). Blocking; run on the
/// blocking pool. Any I/O failure is the opaque `Io` code.
fn read_dir_confined(
    real_path: &Path,
    after: Option<&str>,
    limit: u32,
) -> Result<ShareDirectoryPage, ShareServeError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(real_path).map_err(share_io_error)? {
        names.push(
            entry
                .map_err(share_io_error)?
                .file_name()
                .to_string_lossy()
                .into_owned(),
        );
    }
    // A stable lexicographic order makes the `after` cursor well-defined across pages.
    names.sort();
    let start = match after {
        Some(cursor) => names
            .iter()
            .position(|name| name.as_str() > cursor)
            .unwrap_or(names.len()),
        None => 0,
    };
    let page_names: Vec<&str> = names
        .iter()
        .skip(start)
        .take(limit as usize)
        .map(String::as_str)
        .collect();
    let entries = page_names
        .iter()
        .map(|name| entry_meta(real_path.join(*name), *name))
        .collect::<Result<Vec<_>, _>>()?;
    let consumed = start + page_names.len();
    // The cursor is the last returned name, and only while more entries follow it.
    let next_after = if page_names.last().is_some() && consumed < names.len() {
        page_names.last().copied().map(str::to_owned)
    } else {
        None
    };
    Ok(ShareDirectoryPage {
        entries,
        next_after,
    })
}

/// The metadata for one listed entry, by its full confined path.
fn entry_meta(path: PathBuf, name: &str) -> Result<ShareDirectoryEntry, ShareServeError> {
    let meta = std::fs::metadata(&path).map_err(share_io_error)?;
    Ok(ShareDirectoryEntry {
        name: name.to_owned(),
        is_dir: meta.is_dir(),
        size_bytes: meta.len(),
        modified_at_ms: mtime_ms(meta.modified().ok()),
    })
}

/// The entry's display name for a `stat`: the final component of `rel`, or the root's
/// own name when `rel` is empty.
fn entry_name(rel: &str, real_path: &Path) -> String {
    if rel.is_empty() {
        real_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        rel.rsplit('/').next().unwrap_or(rel).to_owned()
    }
}

/// The metadata for a `stat` target, by its full confined path.
fn stat_confined(real_path: &Path, name: &str) -> Result<ShareDirectoryEntry, ShareServeError> {
    let meta = std::fs::metadata(real_path).map_err(share_io_error)?;
    Ok(ShareDirectoryEntry {
        name: name.to_owned(),
        is_dir: meta.is_dir(),
        size_bytes: meta.len(),
        modified_at_ms: mtime_ms(meta.modified().ok()),
    })
}

/// `SystemTime` → unix milliseconds, failing safe to `0` (a pre-epoch or unsupported
/// mtime is not an error worth surfacing over the metadata channel).
fn mtime_ms(modified: Option<SystemTime>) -> i64 {
    modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use uc_core::ports::remote_share::{
        ShareGrants, ShareRoot, ShareStoreDoc, SharedRootStoreError,
    };

    /// A `SharedRootStorePort` backed by an in-memory doc or a forced failure.
    enum StoreState {
        Doc(ShareStoreDoc),
        Fail(SharedRootStoreError),
    }

    struct StubStore {
        state: Mutex<StoreState>,
    }

    impl StubStore {
        fn with(doc: ShareStoreDoc) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(StoreState::Doc(doc)),
            })
        }
        fn failing(error: SharedRootStoreError) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(StoreState::Fail(error)),
            })
        }
    }

    #[async_trait]
    impl SharedRootStorePort for StubStore {
        async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
            // discarded-source[lock-poisoned]: `PoisonError`: the stub is single-threaded in
            // tests and a poison carries no diagnostic.
            let guard = self
                .state
                .lock()
                .map_err(|_| SharedRootStoreError::CapacityExceeded)?;
            match &*guard {
                StoreState::Doc(doc) => Ok(doc.clone()),
                StoreState::Fail(error) => {
                    // The failure is reconstructed fresh each call so the stub stays
                    // fail-closed across repeated reads (the error payloads are not Clone).
                    Err(match error {
                        SharedRootStoreError::NotUnlocked => SharedRootStoreError::NotUnlocked,
                        SharedRootStoreError::CapacityExceeded => {
                            SharedRootStoreError::CapacityExceeded
                        }
                        SharedRootStoreError::Io { .. } => SharedRootStoreError::Io {
                            source: std::io::Error::other("stub"),
                        },
                        SharedRootStoreError::Corrupt { .. } => SharedRootStoreError::Corrupt {
                            source: anyhow::anyhow!("stub"),
                        },
                    })
                }
            }
        }
        async fn save(&self, _doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
            Ok(())
        }
    }

    /// A `ShareConfinementPort` that resolves under a fixed temp root and can be forced
    /// to deny, mirroring the registry/store mismatch the AND is meant to catch.
    #[derive(Clone, Copy)]
    enum ConfineBehavior {
        Resolve,
        Deny,
        RootGone,
    }

    struct StubConfinement {
        root_id: ShareRootId,
        root_path: PathBuf,
        behavior: Mutex<ConfineBehavior>,
    }

    impl StubConfinement {
        fn with(root_id: ShareRootId, root_path: PathBuf) -> Arc<Self> {
            Arc::new(Self {
                root_id,
                root_path,
                behavior: Mutex::new(ConfineBehavior::Resolve),
            })
        }
        fn set_behavior(&self, behavior: ConfineBehavior) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let mut guard = self.behavior.lock().map_err(|_| ()).unwrap();
            *guard = behavior;
        }
    }

    #[async_trait]
    impl ShareConfinementPort for StubConfinement {
        async fn register_root(
            &self,
            _root: ShareRootId,
            _path: &Path,
        ) -> Result<(), ConfineError> {
            Ok(())
        }
        async fn unregister_root(&self, _root: ShareRootId) {}
        async fn is_registered(&self, root: ShareRootId) -> bool {
            root == self.root_id
        }
        async fn resolve(
            &self,
            root: ShareRootId,
            client_rel: &str,
        ) -> Result<ConfinedTarget, ConfineError> {
            if root != self.root_id {
                return Err(ConfineError::RootGone);
            }
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let behavior = *self.behavior.lock().map_err(|_| ()).unwrap();
            match behavior {
                ConfineBehavior::Deny => Err(ConfineError::Denied),
                ConfineBehavior::RootGone => Err(ConfineError::RootGone),
                ConfineBehavior::Resolve => {
                    if !is_well_formed_relative(client_rel) {
                        return Err(ConfineError::Denied);
                    }
                    let mut joined = self.root_path.clone();
                    for segment in client_rel.split('/') {
                        joined.push(segment);
                    }
                    Ok(ConfinedTarget {
                        root,
                        real_path: joined,
                        relative: PathBuf::from(client_rel),
                    })
                }
            }
        }
        async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
            if root != self.root_id {
                return Err(ConfineError::RootGone);
            }
            // A root that is gone (or that denies) does so for the root itself as well,
            // not just for sub-paths: both resolutions consult the same behavior.
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let behavior = *self.behavior.lock().map_err(|_| ()).unwrap();
            match behavior {
                ConfineBehavior::Deny => Err(ConfineError::Denied),
                ConfineBehavior::RootGone => Err(ConfineError::RootGone),
                ConfineBehavior::Resolve => Ok(ConfinedTarget {
                    root,
                    real_path: self.root_path.clone(),
                    relative: PathBuf::new(),
                }),
            }
        }
    }

    fn peer() -> DeviceId {
        DeviceId::new("test-peer")
    }

    fn read_only_grants() -> ShareGrants {
        ShareGrants {
            read: true,
            write: false,
            delete: false,
        }
    }

    /// A store + confinement agreeing on `root_id` under `dir`, both authorized and
    /// resolving. Returns the handler plus the `root_id`.
    fn happy_setup(dir: &Path) -> (RemoteShareServe, ShareRootId, Arc<StubConfinement>) {
        let root = ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: dir.to_string_lossy().into_owned(),
            label: "docs".to_owned(),
            grants: read_only_grants(),
            enabled: true,
            added_at_ms: 0,
        };
        let root_id = root.id;
        let mut doc = ShareStoreDoc::new();
        doc.roots.push(root);

        let store = StubStore::with(doc);
        let confinement = StubConfinement::with(root_id, dir.to_path_buf());
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: confinement.clone(),
        });
        (handler, root_id, confinement)
    }

    #[tokio::test]
    async fn hello_ok_suspended_and_locked() {
        // Ok.
        let tmp = tempfile::tempdir().unwrap();
        let (handler, _root, _conf) = happy_setup(tmp.path());
        assert_eq!(handler.hello().await, ShareAvailability::Ok);

        // Suspended.
        let root_id = ShareRootId(uuid::Uuid::new_v4());
        let root = ShareRoot {
            id: root_id,
            path: "/tmp/x".to_owned(),
            label: "x".to_owned(),
            grants: read_only_grants(),
            enabled: true,
            added_at_ms: 0,
        };
        let mut doc = ShareStoreDoc::new();
        doc.suspended = true;
        doc.roots.push(root);
        let store = StubStore::with(doc);
        let conf = StubConfinement::with(root_id, PathBuf::from("/tmp/x"));
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
        });
        assert_eq!(handler.hello().await, ShareAvailability::Suspended);

        // Locked (store fails to read) — fail-closed.
        let store = StubStore::failing(SharedRootStoreError::NotUnlocked);
        let conf =
            StubConfinement::with(ShareRootId(uuid::Uuid::new_v4()), PathBuf::from("/tmp/x"));
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
        });
        assert_eq!(handler.hello().await, ShareAvailability::Locked);
    }

    #[tokio::test]
    async fn list_roots_lists_only_enabled_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = happy_setup(tmp.path());
        let roots = handler.list_roots(&peer()).await.unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, root_id);
        assert_eq!(roots[0].grants, read_only_grants());

        // A disabled root is excluded from the advertised set.
        let root = ShareRoot {
            id: root_id,
            path: "/tmp/x".to_owned(),
            label: "x".to_owned(),
            grants: read_only_grants(),
            enabled: false,
            added_at_ms: 0,
        };
        let mut doc = ShareStoreDoc::new();
        doc.roots.push(root);
        let store = StubStore::with(doc);
        let conf = StubConfinement::with(root_id, tmp.path().to_path_buf());
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
        });
        assert!(handler.list_roots(&peer()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_roots_locked_fails_closed() {
        let store = StubStore::failing(SharedRootStoreError::NotUnlocked);
        let conf =
            StubConfinement::with(ShareRootId(uuid::Uuid::new_v4()), PathBuf::from("/tmp/x"));
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
        });
        assert!(matches!(
            handler.list_roots(&peer()).await,
            Err(ShareServeError::NotUnlocked)
        ));
    }

    #[tokio::test]
    async fn list_root_top_level_returns_sorted_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dir.join("zeta")).unwrap();
        std::fs::write(dir.join("alpha.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.join("mid")).unwrap();

        let (handler, root_id, _conf) = happy_setup(dir);
        let page = handler.list(&peer(), root_id, "", None, 100).await.unwrap();
        // Sorted by name: alpha.txt, mid, zeta.
        let names: Vec<String> = page.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["alpha.txt", "mid", "zeta"]);
        assert!(page.entries[0].is_dir == false && page.entries[0].size_bytes == 5);
        assert!(page.entries[1].is_dir);
        assert!(page.next_after.is_none());
    }

    #[tokio::test]
    async fn list_paginates_by_name_cursor() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for name in ["a", "b", "c", "d"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let (handler, root_id, _conf) = happy_setup(dir);

        let first = handler.list(&peer(), root_id, "", None, 2).await.unwrap();
        assert_eq!(
            first
                .entries
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(first.next_after.as_deref(), Some("b"));

        let second = handler
            .list(&peer(), root_id, "", Some("b"), 2)
            .await
            .unwrap();
        assert_eq!(
            second
                .entries
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            vec!["c", "d"]
        );
        assert!(second.next_after.is_none());
    }

    /// The two-fact AND: the store authorizes but the confinement denies ⇒ denied, even
    /// though the path would otherwise resolve.
    #[tokio::test]
    async fn confined_resolution_alone_does_not_authorize() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, conf) = happy_setup(tmp.path());
        // Store authorizes (enabled, read grant) but the registry rejects the path.
        conf.set_behavior(ConfineBehavior::Deny);
        assert!(matches!(
            handler.list(&peer(), root_id, "alpha.txt", None, 10).await,
            Err(ShareServeError::NotAuthorized)
        ));
    }

    /// The reverse half of the AND: the path resolves but the store has disabled the
    /// root ⇒ denied, even though `resolve` would succeed.
    #[tokio::test]
    async fn authorize_then_resolve_requires_both() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: tmp.path().to_string_lossy().into_owned(),
            label: "docs".to_owned(),
            grants: read_only_grants(),
            enabled: false, // disabled in the store
            added_at_ms: 0,
        };
        let root_id = root.id;
        let mut doc = ShareStoreDoc::new();
        doc.roots.push(root);
        let store = StubStore::with(doc);
        // The registry still resolves the path (root registered).
        let conf = StubConfinement::with(root_id, tmp.path().to_path_buf());
        std::fs::write(tmp.path().join("alpha.txt"), b"secret").unwrap();
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
        });
        assert!(matches!(
            handler.list(&peer(), root_id, "alpha.txt", None, 10).await,
            Err(ShareServeError::NotAuthorized)
        ));
    }

    #[tokio::test]
    async fn malformed_relative_is_denied_opaquely() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = happy_setup(tmp.path());
        for bad in ["../outside", "/etc/passwd", "a/\\b", ""] {
            // `""` lists the root (allowed); traversal and absolute paths are denied.
            if bad.is_empty() {
                assert!(handler.list(&peer(), root_id, "", None, 1).await.is_ok());
            } else {
                assert!(
                    matches!(
                        handler.list(&peer(), root_id, bad, None, 1).await,
                        Err(ShareServeError::NotAuthorized)
                    ),
                    "should deny {bad:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn root_gone_maps_from_confine() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, conf) = happy_setup(tmp.path());
        conf.set_behavior(ConfineBehavior::RootGone);
        assert!(matches!(
            handler.list(&peer(), root_id, "", None, 1).await,
            Err(ShareServeError::RootGone)
        ));
    }

    #[tokio::test]
    async fn stat_returns_entry_metadata_and_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/note.txt"), b"0123456789").unwrap();

        let (handler, root_id, _conf) = happy_setup(dir);
        let entry = handler
            .stat(&peer(), root_id, "sub/note.txt")
            .await
            .unwrap();
        assert_eq!(entry.name, "note.txt");
        assert!(!entry.is_dir);
        assert_eq!(entry.size_bytes, 10);
        assert!(entry.modified_at_ms > 0, "mtime should be post-epoch");

        // The root itself (empty rel) stats to a directory named after the root dir.
        let root_entry = handler.stat(&peer(), root_id, "").await.unwrap();
        assert!(root_entry.is_dir);
    }

    #[tokio::test]
    async fn stat_missing_path_is_io() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = happy_setup(tmp.path());
        // The path is well-formed and authorized, but the file does not exist.
        assert!(matches!(
            handler.stat(&peer(), root_id, "nope.txt").await,
            Err(ShareServeError::Io)
        ));
    }

    /// Redaction: the domain types' `Debug` must never print a file name or a root
    /// label (spec §13 I4).
    #[test]
    fn debug_redacts_names_and_labels() {
        let entry = ShareDirectoryEntry {
            name: "secret-file.txt".to_owned(),
            is_dir: false,
            size_bytes: 1,
            modified_at_ms: 0,
        };
        assert!(!format!("{entry:?}").contains("secret-file.txt"));

        let page = ShareDirectoryPage {
            entries: vec![entry.clone()],
            next_after: Some("cursor-name.txt".to_owned()),
        };
        let text = format!("{page:?}");
        assert!(!text.contains("secret-file.txt"));
        assert!(!text.contains("cursor-name.txt"));

        let root = ShareRootDescriptor {
            id: ShareRootId(uuid::Uuid::new_v4()),
            label: "secret-label".to_owned(),
            grants: ShareGrants::default(),
            enabled: true,
        };
        assert!(!format!("{root:?}").contains("secret-label"));
    }

    /// A `Duration` is unused here except to keep the `std::time` import honest if the
    /// mtime helpers change; the test asserts `mtime_ms` fails safe to a non-negative
    /// value for a near-epoch time.
    #[test]
    fn mtime_ms_is_non_negative() {
        let now = SystemTime::now();
        assert!(mtime_ms(Some(now)) >= 0);
        assert_eq!(mtime_ms(None), 0);
        // A post-epoch time well in the future still yields a finite i64.
        let future = SystemTime::now() + Duration::from_secs(3_600);
        assert!(mtime_ms(Some(future)) > 0);
    }
}
