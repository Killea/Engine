//! The device-file-share serve handler: turn an already-admitted peer's control-plane
//! request into holder-independent results.
//!
//! This is the `RemoteShareServePort` implementation the `remote-share/1` serve adapter
//! (in `uc-infra-p2p`) calls behind `Arc<dyn _>`. It is the single place that enforces
//! the two-fact AND that `ShareConfinementPort` and the authorizer each enforce only
//! half of (spec §5.2, steps 3–6):
//!
//!   1. **authorize** — the store says `peer` may `op` on `root` (fail-closed);
//!   2. **confine** — the cap-std registry resolves the peer's relative path under
//!      `root` to a `ConfinedTarget` (an opaque capability, not a path);
//! and only when both succeed does it
//!   3. **act** — call the matching port verb (`target_read_dir`, `target_rename`,
//!      `commit_staging`, …), which re-checks the token's registration generation and
//!      operates relative to the retained directory fd.
//!
//! The ordering is fixed: authorize before confine, and a successful `resolve` is never
//! treated as authorization on its own (see the `ShareConfinementPort` docs). There is
//! no path between "checked" and "acted on": the checked object and the acted-on
//! object are the same fd inside the token.
//!
//! Upload staging is a cross-request flow: `stage_upload`/`commit_upload`/
//! `abort_upload`/`export` authorize and resolve here, then hand the admitted
//! work to `transfer::ShareTransferCoordinator`, which owns the staging-session
//! table, the bounded blob fetches, progress back-channel reporting, and the
//! export ticket lease (spec §8).
//!
//! No holder-local path crosses this boundary: every verb runs inside the port
//! on retained handles, and the returned domain types carry only names, sizes,
//! mtimes, kernel-issued ids, and opaque blob tickets.

use std::sync::Arc;

use async_trait::async_trait;
use uc_core::file_transfer::OutboundProgressReporterPort;
use uc_core::ids::DeviceId;
use uc_core::ports::blob::BlobTransferPort;
use uc_core::ports::remote_share::{
    is_well_formed_relative, ConfineError, ConfinedTarget, ConflictPolicy, RemoteShareServePort,
    ShareAvailability, ShareConfinementPort, ShareDirectoryEntry, ShareDirectoryPage,
    ShareExportOutcome, ShareOperation, ShareRootDescriptor, ShareRootId, ShareServeError,
    ShareStageEntry, ShareStageOutcome, ShareTransferId, ShareTrashEntry, ShareTrashPage,
    SharedRootStorePort,
};

use crate::remote_share::authorizer::ShareAuthorizer;
use crate::remote_share::transfer::ShareTransferCoordinator;

/// Ports the serve handler consumes.
pub struct RemoteShareServeDeps {
    /// The encrypted shared-root store. Unreadable (space locked) ⇒ fail-closed.
    pub share_store: Arc<dyn SharedRootStorePort>,
    /// The cap-std confinement registry (root lifecycle + path resolution + verbs).
    pub confinement: Arc<dyn ShareConfinementPort>,
    /// The blob store upload pulls fetch from and exports publish into.
    pub blobs: Arc<dyn BlobTransferPort>,
    /// The progress back-channel byte counts are reported over, keyed by the
    /// client-chosen `transfer_id` (spec §8.1 step 4).
    pub progress: Arc<dyn OutboundProgressReporterPort>,
}

/// The serve-side handler. Thread-safe; put in `Arc`.
pub struct RemoteShareServe {
    store: Arc<dyn SharedRootStorePort>,
    authorizer: ShareAuthorizer,
    confinement: Arc<dyn ShareConfinementPort>,
    /// Staging sessions, fetch workers, progress aggregation, and export
    /// leases — the transfer mechanics behind the admitted verbs.
    transfers: ShareTransferCoordinator,
}

impl RemoteShareServe {
    pub fn new(deps: RemoteShareServeDeps) -> Self {
        let RemoteShareServeDeps {
            share_store,
            confinement,
            blobs,
            progress,
        } = deps;
        Self {
            store: share_store.clone(),
            authorizer: ShareAuthorizer::new(share_store),
            transfers: ShareTransferCoordinator::new(confinement.clone(), blobs, progress),
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
    /// wire grammar on any non-empty `rel`. The empty `rel` addresses the root itself
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
        // Step 2: confine (path → retained-handle target).
        let target = self.resolve_target(root, rel).await?;
        // Step 3: the verb runs relative to the token's retained fd — the listed
        // directory is the checked directory, not a re-parsed path.
        let mut entries = self
            .confinement
            .target_read_dir(&target)
            .await
            .map_err(map_confine)?;
        // A stable lexicographic order makes the `after` cursor well-defined across pages.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let start = match after {
            Some(cursor) => entries
                .iter()
                .position(|entry| entry.name.as_str() > cursor)
                .unwrap_or(entries.len()),
            None => 0,
        };
        let page: Vec<_> = entries.iter().skip(start).take(limit as usize).collect();
        let mut out = Vec::with_capacity(page.len());
        for entry in &page {
            let meta = self
                .confinement
                .target_child_metadata(&target, &entry.name)
                .await
                .map_err(map_confine)?;
            out.push(ShareDirectoryEntry {
                name: entry.name.clone(),
                is_dir: meta.is_dir,
                is_symlink: entry.is_symlink,
                size_bytes: meta.size_bytes,
                modified_at_ms: meta.modified_at_ms,
            });
        }
        let consumed = start + out.len();
        // The cursor is the last returned name, and only while more entries follow it.
        let next_after = if out.last().is_some() && consumed < entries.len() {
            out.last().map(|entry| entry.name.clone())
        } else {
            None
        };
        Ok(ShareDirectoryPage {
            entries: out,
            next_after,
        })
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
        let meta = self
            .confinement
            .target_metadata(&target)
            .await
            .map_err(map_confine)?;
        Ok(ShareDirectoryEntry {
            name: meta.name,
            is_dir: meta.is_dir,
            // lstat semantics: a symlink is neither a dir nor a regular file.
            is_symlink: !meta.is_dir && !meta.is_file,
            size_bytes: meta.size_bytes,
            modified_at_ms: meta.modified_at_ms,
        })
    }

    async fn mkdir(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<(), ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Write)
            .await?;
        let target = self.resolve_target(root, rel).await?;
        self.confinement
            .target_create_dir(&target)
            .await
            .map_err(map_confine)
    }

    async fn rename(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), ShareServeError> {
        // Spec §5.2: rename moves an existing name — write + delete together.
        self.require_authorized(peer, root, ShareOperation::Rename)
            .await?;
        let from_target = self.resolve_target(root, from).await?;
        let to_target = self.resolve_target(root, to).await?;
        self.confinement
            .target_rename(&from_target, &to_target)
            .await
            .map_err(map_confine)
    }

    async fn delete(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<String, ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Delete)
            .await?;
        let target = self.resolve_target(root, rel).await?;
        self.confinement
            .target_move_to_trash(&target)
            .await
            .map_err(map_confine)
    }

    async fn copy_within(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        from: &str,
        to: &str,
    ) -> Result<(), ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Write)
            .await?;
        let from_target = self.resolve_target(root, from).await?;
        let to_target = self.resolve_target(root, to).await?;
        self.confinement
            .target_copy_into(&from_target, &to_target)
            .await
            .map_err(map_confine)
    }

    async fn list_trash(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ShareTrashPage, ShareServeError> {
        // The recycle namespace is only reachable through the delete grant.
        self.require_authorized(peer, root, ShareOperation::Delete)
            .await?;
        let page = self
            .confinement
            .list_trash(root, after, limit)
            .await
            .map_err(map_confine)?;
        Ok(ShareTrashPage {
            entries: page
                .entries
                .into_iter()
                .map(|entry| ShareTrashEntry {
                    trash_id: entry.trash_id,
                    original_rel: entry.original_rel,
                    deleted_at_ms: entry.deleted_at_ms,
                    is_dir: entry.is_dir,
                    size_bytes: entry.size_bytes,
                })
                .collect(),
            next_after: page.next_after,
        })
    }

    async fn restore(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        trash_id: &str,
        to: &str,
    ) -> Result<(), ShareServeError> {
        // Restoring moves an entry out of the holder-controlled namespace back into
        // the user tree: same write + delete requirement as rename (spec §5.2).
        self.require_authorized(peer, root, ShareOperation::Rename)
            .await?;
        let to_target = self.resolve_target(root, to).await?;
        self.confinement
            .restore_from_trash(root, trash_id, &to_target)
            .await
            .map_err(map_confine)?;
        Ok(())
    }

    async fn empty_trash(&self, peer: &DeviceId, root: ShareRootId) -> Result<(), ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Delete)
            .await?;
        self.confinement
            .empty_trash(root)
            .await
            .map_err(map_confine)
    }

    async fn stage_upload(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        dir: &str,
        entries: &[ShareStageEntry],
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Write)
            .await?;
        let dir_target = self.resolve_target(root, dir).await?;
        // The destination must be a real directory before any staging space is opened.
        let meta = self
            .confinement
            .target_metadata(&dir_target)
            .await
            .map_err(map_confine)?;
        if !meta.is_dir {
            return Err(ShareServeError::NotADirectory);
        }
        // Admitted: the coordinator opens the kernel staging set, spawns the
        // bounded per-entry pulls, and starts progress reporting under
        // `transfer_id` — this call returns once the session is registered.
        self.transfers
            .open_upload(peer, root, dir_target, entries.to_vec(), transfer_id)
            .await
    }

    async fn commit_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), ShareServeError> {
        for staging_id in staging_ids {
            let session = self.transfers.take_upload(peer, staging_id)?;
            // Re-authorize against the session's recorded root — grants may have
            // changed since `stage_upload` opened the set (spec §5.2).
            if let Err(error) = self
                .require_authorized(peer, session.root(), ShareOperation::Write)
                .await
            {
                self.transfers.restore_upload(staging_id, session);
                return Err(error);
            }
            // Wait for the set's fetches to settle; a failed or cancelled set
            // can never land — its staging dir is discarded and the session
            // stays out of the table.
            session.wait_settled().await;
            if session.is_uncommittable() {
                // discarded-source[best-effort-cleanup]: `ConfineError`: the
                // staging dir is inert residue; the registration sweep reclaims
                // it even if this removal fails.
                let _ = self
                    .confinement
                    .abort_staging(session.root(), staging_id)
                    .await;
                return Err(ShareServeError::Io);
            }
            match self
                .confinement
                .commit_staging(
                    session.root(),
                    staging_id,
                    session.dir(),
                    session.staged(),
                    ConflictPolicy::AutoRename,
                )
                .await
            {
                Ok(()) => self.transfers.mark_committed(staging_id),
                Err(error) => {
                    // Keep the session so an incomplete commit can be retried or
                    // aborted explicitly.
                    self.transfers.restore_upload(staging_id, session);
                    return Err(map_confine(error));
                }
            }
        }
        Ok(())
    }

    async fn abort_upload(
        &self,
        peer: &DeviceId,
        staging_ids: &[String],
    ) -> Result<(), ShareServeError> {
        for staging_id in staging_ids {
            // Tombstoned ids stop the batch (`too_late`); unknown ids are a
            // no-op and foreign ids are unprobeable — both handled inside.
            self.transfers.abort_upload(peer, staging_id).await?;
        }
        Ok(())
    }

    async fn export(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        rel: &str,
    ) -> Result<ShareExportOutcome, ShareServeError> {
        self.require_authorized(peer, root, ShareOperation::Read)
            .await?;
        let target = self.resolve_target(root, rel).await?;
        let meta = self
            .confinement
            .target_metadata(&target)
            .await
            .map_err(map_confine)?;
        if meta.is_dir {
            return Err(ShareServeError::IsADirectory);
        }
        // The checked fd is the capability: publish streams it no-follow —
        // the object verified above is the object read, not a re-opened path.
        let file = self
            .confinement
            .target_open_read(&target)
            .await
            .map_err(map_confine)?;
        self.transfers.publish_export(file, meta.size_bytes).await
    }
}

/// Map a confinement error to the serve taxonomy. Shared with the transfer
/// coordinator (`transfer.rs`), which applies the same taxonomy to the verbs
/// it calls on admitted staging sessions.
pub(crate) fn map_confine(error: ConfineError) -> ShareServeError {
    match error {
        ConfineError::Denied => ShareServeError::NotAuthorized,
        ConfineError::ReservedName => ShareServeError::ReservedName,
        ConfineError::RootGone => ShareServeError::RootGone,
        ConfineError::NotFound => ShareServeError::NotFound,
        ConfineError::Conflict => ShareServeError::Conflict,
        ConfineError::NotADirectory => ShareServeError::NotADirectory,
        ConfineError::IsADirectory => ShareServeError::IsADirectory,
        // The confinement `Io { source }` variant discards the source here: it is a
        // reclassification into the payload-free wire `Io` code, which has no slot for
        // a lower-layer error.
        ConfineError::Io { .. } => ShareServeError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use bytes::Bytes;
    use tokio::sync::Notify;
    use uc_core::file_transfer::{FileTransferCancellationReason, OutboundProgressStatus};
    use uc_core::ports::blob::{BlobDigest, BlobError, BlobProgressSink, BlobTicket, TagReason};
    use uc_core::ports::remote_share::{
        ConfinedDirEntry, ConfinedMetadata, ConfinedTargetToken, ConfinedTrashEntry,
        ConfinedTrashPage, ShareGrants, ShareRoot, ShareStagedEntry, ShareStoreDoc,
        SharedRootStoreError,
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

    /// The opaque token the stub hands back: `ConfinedTarget::new` requires a
    /// `ConfinedTargetToken`, but the stub resolves paths from `target.relative`
    /// directly, so the token carries nothing.
    struct StubToken;

    impl ConfinedTargetToken for StubToken {
        fn as_any(&self) -> &dyn Any {
            self
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
        /// trash_id → (original_rel, is_dir). Trash meta lives in memory; the stub is
        /// a test double, not a persistent implementation.
        trash: Mutex<HashMap<String, (String, bool)>>,
    }

    impl StubConfinement {
        fn with(root_id: ShareRootId, root_path: PathBuf) -> Arc<Self> {
            Arc::new(Self {
                root_id,
                root_path,
                behavior: Mutex::new(ConfineBehavior::Resolve),
                trash: Mutex::new(HashMap::new()),
            })
        }
        fn set_behavior(&self, behavior: ConfineBehavior) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let mut guard = self.behavior.lock().map_err(|_| ()).unwrap();
            *guard = behavior;
        }
        fn gate(&self) -> Result<(), ConfineError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let behavior = *self.behavior.lock().map_err(|_| ConfineError::Denied)?;
            match behavior {
                ConfineBehavior::Deny => Err(ConfineError::Denied),
                ConfineBehavior::RootGone => Err(ConfineError::RootGone),
                ConfineBehavior::Resolve => Ok(()),
            }
        }
        fn path_of(&self, target: &ConfinedTarget) -> PathBuf {
            self.root_path.join(&target.relative)
        }
        fn io_kind(error: std::io::Error) -> ConfineError {
            match error.kind() {
                std::io::ErrorKind::NotFound => ConfineError::NotFound,
                std::io::ErrorKind::AlreadyExists => ConfineError::Conflict,
                _ => ConfineError::Io { source: error },
            }
        }
        fn meta_of(path: &Path, name: String) -> Result<ConfinedMetadata, ConfineError> {
            let meta = std::fs::symlink_metadata(path).map_err(Self::io_kind)?;
            Ok(ConfinedMetadata {
                name,
                is_dir: meta.is_dir(),
                is_file: meta.is_file(),
                size_bytes: meta.len(),
                modified_at_ms: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0),
            })
        }
        fn trash_dir(&self) -> PathBuf {
            self.root_path
                .join(format!(".uniclipboard-trash-{}", self.root_id.0))
        }
        fn staging_dir(&self, staging_id: &str) -> PathBuf {
            self.root_path
                .join(format!(".uniclipboard-staging-{staging_id}"))
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
            self.gate()?;
            if !is_well_formed_relative(client_rel) {
                return Err(ConfineError::Denied);
            }
            Ok(ConfinedTarget::new(
                root,
                PathBuf::from(client_rel),
                Arc::new(StubToken),
            ))
        }
        async fn resolve_root(&self, root: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
            if root != self.root_id {
                return Err(ConfineError::RootGone);
            }
            self.gate()?;
            Ok(ConfinedTarget::new(
                root,
                PathBuf::new(),
                Arc::new(StubToken),
            ))
        }

        async fn target_metadata(
            &self,
            target: &ConfinedTarget,
        ) -> Result<ConfinedMetadata, ConfineError> {
            self.gate()?;
            let path = self.path_of(target);
            let name = if target.relative.as_os_str().is_empty() {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                target
                    .relative
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            Self::meta_of(&path, name)
        }

        async fn target_child_metadata(
            &self,
            target: &ConfinedTarget,
            name: &str,
        ) -> Result<ConfinedMetadata, ConfineError> {
            self.gate()?;
            Self::meta_of(&self.path_of(target).join(name), name.to_owned())
        }

        async fn target_read_dir(
            &self,
            target: &ConfinedTarget,
        ) -> Result<Vec<ConfinedDirEntry>, ConfineError> {
            self.gate()?;
            let mut out = Vec::new();
            for entry in std::fs::read_dir(self.path_of(target)).map_err(Self::io_kind)? {
                let entry = entry.map_err(Self::io_kind)?;
                let file_type = entry.file_type().map_err(Self::io_kind)?;
                out.push(ConfinedDirEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir: file_type.is_dir(),
                    is_file: file_type.is_file(),
                    is_symlink: file_type.is_symlink(),
                });
            }
            Ok(out)
        }

        async fn target_open_read(
            &self,
            target: &ConfinedTarget,
        ) -> Result<std::fs::File, ConfineError> {
            self.gate()?;
            std::fs::File::open(self.path_of(target)).map_err(Self::io_kind)
        }

        async fn target_create_dir(&self, target: &ConfinedTarget) -> Result<(), ConfineError> {
            self.gate()?;
            std::fs::create_dir(self.path_of(target)).map_err(Self::io_kind)
        }

        async fn target_rename(
            &self,
            from: &ConfinedTarget,
            to: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            self.gate()?;
            if to.root != from.root {
                return Err(ConfineError::Denied);
            }
            let dest = self.path_of(to);
            if dest.exists() {
                return Err(ConfineError::Conflict);
            }
            std::fs::rename(self.path_of(from), dest).map_err(Self::io_kind)
        }

        async fn target_copy_into(
            &self,
            from: &ConfinedTarget,
            to: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            self.gate()?;
            if to.root != from.root {
                return Err(ConfineError::Denied);
            }
            let dest = self.path_of(to);
            if dest.exists() {
                return Err(ConfineError::Conflict);
            }
            let src = self.path_of(from);
            if src.is_dir() {
                std::fs::create_dir(&dest).map_err(Self::io_kind)?;
                for entry in std::fs::read_dir(&src).map_err(Self::io_kind)? {
                    let entry = entry.map_err(Self::io_kind)?;
                    if entry.file_type().map_err(Self::io_kind)?.is_symlink() {
                        continue;
                    }
                    let child_dest = dest.join(entry.file_name());
                    if entry.path().is_dir() {
                        std::fs::create_dir(&child_dest).map_err(Self::io_kind)?;
                    } else {
                        std::fs::copy(entry.path(), &child_dest).map_err(Self::io_kind)?;
                    }
                }
                Ok(())
            } else {
                std::fs::copy(src, dest).map_err(Self::io_kind)?;
                Ok(())
            }
        }

        async fn target_move_to_trash(
            &self,
            target: &ConfinedTarget,
        ) -> Result<String, ConfineError> {
            self.gate()?;
            if target.relative.as_os_str().is_empty() {
                return Err(ConfineError::Denied);
            }
            let trash_id = uuid::Uuid::new_v4().to_string();
            let entry_dir = self.trash_dir().join(&trash_id);
            std::fs::create_dir_all(&entry_dir).map_err(Self::io_kind)?;
            std::fs::rename(self.path_of(target), entry_dir.join("payload"))
                .map_err(Self::io_kind)?;
            let is_dir = entry_dir.join("payload").is_dir();
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.trash.lock().map_err(|_| ConfineError::Denied)?.insert(
                trash_id.clone(),
                (target.relative.to_string_lossy().into_owned(), is_dir),
            );
            Ok(trash_id)
        }

        async fn list_trash(
            &self,
            _root: ShareRootId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ConfinedTrashPage, ConfineError> {
            self.gate()?;
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            let guard = self.trash.lock().map_err(|_| ConfineError::Denied)?;
            let mut ids: Vec<&String> = guard.keys().collect();
            ids.sort();
            let entries = ids
                .into_iter()
                .map(|id| {
                    let (original_rel, is_dir) = &guard[id];
                    ConfinedTrashEntry {
                        trash_id: id.clone(),
                        original_rel: original_rel.clone(),
                        deleted_at_ms: 0,
                        is_dir: *is_dir,
                        size_bytes: 0,
                    }
                })
                .collect();
            Ok(ConfinedTrashPage {
                entries,
                next_after: None,
            })
        }

        async fn restore_from_trash(
            &self,
            _root: ShareRootId,
            trash_id: &str,
            to: &ConfinedTarget,
        ) -> Result<String, ConfineError> {
            self.gate()?;
            let entry_dir = self.trash_dir().join(trash_id);
            if !entry_dir.exists() {
                return Err(ConfineError::NotFound);
            }
            let dest = self.path_of(to);
            let final_leaf = if dest.exists() {
                format!(
                    "{} (restored)",
                    to.relative
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                )
            } else {
                to.relative
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            let final_path = dest.with_file_name(&final_leaf);
            std::fs::rename(entry_dir.join("payload"), &final_path).map_err(Self::io_kind)?;
            // discarded-source[best-effort-cleanup]: `std::io::Error`: leftover entry dir.
            let _ = std::fs::remove_dir(&entry_dir);
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            if let Ok(mut guard) = self.trash.lock() {
                guard.remove(trash_id);
            }
            Ok(final_leaf)
        }

        async fn empty_trash(&self, _root: ShareRootId) -> Result<(), ConfineError> {
            self.gate()?;
            if self.trash_dir().exists() {
                std::fs::remove_dir_all(self.trash_dir()).map_err(Self::io_kind)?;
            }
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            if let Ok(mut guard) = self.trash.lock() {
                guard.clear();
            }
            Ok(())
        }

        async fn create_staging(&self, _root: ShareRootId) -> Result<String, ConfineError> {
            self.gate()?;
            let staging_id = uuid::Uuid::new_v4().to_string();
            std::fs::create_dir(self.staging_dir(&staging_id)).map_err(Self::io_kind)?;
            Ok(staging_id)
        }

        async fn staging_entry_path(
            &self,
            _root: ShareRootId,
            staging_id: &str,
            rel: &str,
            is_dir: bool,
        ) -> Result<PathBuf, ConfineError> {
            self.gate()?;
            if !is_well_formed_relative(rel) {
                return Err(ConfineError::Denied);
            }
            let path = self.staging_dir(staging_id).join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(Self::io_kind)?;
            }
            if is_dir {
                std::fs::create_dir_all(&path).map_err(Self::io_kind)?;
            }
            Ok(path)
        }

        async fn commit_staging(
            &self,
            _root: ShareRootId,
            staging_id: &str,
            dir: &ConfinedTarget,
            entries: &[ShareStagedEntry],
            _policy: ConflictPolicy,
        ) -> Result<(), ConfineError> {
            self.gate()?;
            let staging_dir = self.staging_dir(staging_id);
            if !staging_dir.exists() {
                return Err(ConfineError::NotFound);
            }
            let dest_dir = self.path_of(dir);
            for entry in entries {
                let staged = staging_dir.join(&entry.rel);
                let dest = dest_dir.join(&entry.rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(Self::io_kind)?;
                }
                let final_dest = if dest.exists() {
                    let stem = dest
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let ext = dest
                        .extension()
                        .map(|e| format!(".{}", e.to_string_lossy()))
                        .unwrap_or_default();
                    dest.with_file_name(format!("{stem} (1){ext}"))
                } else {
                    dest
                };
                std::fs::rename(&staged, &final_dest).map_err(Self::io_kind)?;
            }
            std::fs::remove_dir_all(&staging_dir).map_err(Self::io_kind)
        }

        async fn abort_staging(
            &self,
            _root: ShareRootId,
            staging_id: &str,
        ) -> Result<(), ConfineError> {
            self.gate()?;
            let dir = self.staging_dir(staging_id);
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(Self::io_kind)?;
            }
            Ok(())
        }
    }

    /// Blob-side behaviour the stub plays out during `fetch_to_path`.
    #[derive(Clone, Copy)]
    enum StubBlobBehavior {
        /// Writes the canned payload and reports progress like a real pull.
        Serve,
        /// Fails immediately (a dead remote source).
        Fail,
        /// Blocks until `shutdown_inflight_fetch` releases it, then fails —
        /// the shape an aborted in-flight pull takes.
        Gate,
    }

    /// A `BlobTransferPort` test double: fetches write a deterministic payload,
    /// publishes capture what the export path streamed in.
    struct StubBlobs {
        payload: Vec<u8>,
        behavior: Mutex<StubBlobBehavior>,
        /// Releases gated fetches; `shutdown_inflight_fetch` notifies it.
        gate: Notify,
        /// `shutdown_inflight_fetch` invocations — the cancellation observable.
        shutdowns: Mutex<usize>,
        /// The last published (reason, bytes) pair.
        published: Mutex<Option<(TagReason, Vec<u8>)>>,
    }

    impl StubBlobs {
        fn serving(payload: &[u8]) -> Arc<Self> {
            Self::with(payload, StubBlobBehavior::Serve)
        }
        fn with(payload: &[u8], behavior: StubBlobBehavior) -> Arc<Self> {
            Arc::new(Self {
                payload: payload.to_vec(),
                behavior: Mutex::new(behavior),
                gate: Notify::new(),
                shutdowns: Mutex::new(0),
                published: Mutex::new(None),
            })
        }
        fn shutdowns(&self) -> usize {
            self.shutdowns.lock().map(|g| *g).unwrap_or(0)
        }
        fn last_published(&self) -> Option<(TagReason, Vec<u8>)> {
            self.published.lock().ok()?.clone()
        }
    }

    #[async_trait]
    impl BlobTransferPort for StubBlobs {
        async fn publish(&self, _c: Bytes, _r: TagReason) -> Result<BlobDigest, BlobError> {
            Ok(BlobDigest::from_bytes([1; 32]))
        }
        async fn publish_path(&self, _p: &Path, _r: TagReason) -> Result<BlobDigest, BlobError> {
            Ok(BlobDigest::from_bytes([2; 32]))
        }
        async fn publish_reader(
            &self,
            mut source: std::fs::File,
            reason: TagReason,
        ) -> Result<BlobDigest, BlobError> {
            let mut buf = Vec::new();
            source
                .read_to_end(&mut buf)
                .map_err(|e| BlobError::Internal(Box::new(e)))?;
            let mut digest = [0u8; 32];
            digest[0] = buf.len() as u8;
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            if let Ok(mut guard) = self.published.lock() {
                *guard = Some((reason, buf));
            }
            Ok(BlobDigest::from_bytes(digest))
        }
        async fn issue_ticket(&self, digest: &BlobDigest) -> Result<BlobTicket, BlobError> {
            Ok(BlobTicket::from_bytes(digest.as_bytes().to_vec()))
        }
        async fn fetch(
            &self,
            ticket: &BlobTicket,
            _progress: Option<&dyn BlobProgressSink>,
        ) -> Result<Bytes, BlobError> {
            Ok(Bytes::copy_from_slice(ticket.as_bytes()))
        }
        async fn fetch_to_path(
            &self,
            ticket: &BlobTicket,
            target_path: &Path,
            progress: Option<&dyn BlobProgressSink>,
        ) -> Result<BlobDigest, BlobError> {
            let behavior = *self
                .behavior
                .lock()
                .map_err(|_| BlobError::Internal(Box::new(std::io::Error::other("poisoned"))))?;
            match behavior {
                StubBlobBehavior::Fail => Err(BlobError::Unavailable(Box::new(
                    std::io::Error::other("stubbed fetch failure"),
                ))),
                StubBlobBehavior::Gate => {
                    self.gate.notified().await;
                    Err(BlobError::Unavailable(Box::new(std::io::Error::other(
                        "fetch torn down",
                    ))))
                }
                StubBlobBehavior::Serve => {
                    if let Some(sink) = progress {
                        sink.report(self.payload.len() as u64, Some(self.payload.len() as u64))
                            .await;
                    }
                    std::fs::write(target_path, &self.payload)
                        .map_err(|e| BlobError::Internal(Box::new(e)))?;
                    self.digest_of(ticket)
                }
            }
        }
        async fn shutdown_inflight_fetch(&self, _t: &BlobTicket) -> Result<(), BlobError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            if let Ok(mut guard) = self.shutdowns.lock() {
                *guard += 1;
            }
            self.gate.notify_waiters();
            Ok(())
        }
        async fn has(&self, _d: &BlobDigest) -> Result<bool, BlobError> {
            Ok(false)
        }
        async fn tag(&self, _d: &BlobDigest, _r: TagReason) -> Result<(), BlobError> {
            Ok(())
        }
        async fn untag(&self, _r: TagReason) -> Result<(), BlobError> {
            Ok(())
        }
        fn digest_of(&self, ticket: &BlobTicket) -> Result<BlobDigest, BlobError> {
            let mut digest = [0u8; 32];
            let bytes = ticket.as_bytes();
            let n = bytes.len().min(32);
            digest[..n].copy_from_slice(&bytes[..n]);
            Ok(BlobDigest::from_bytes(digest))
        }
    }

    /// Recorded progress frame — the uploader-side observable of a session.
    struct ProgressFrame {
        transfer_id: String,
        bytes: u64,
        status: OutboundProgressStatus,
    }

    /// An `OutboundProgressReporterPort` that records every frame.
    struct StubProgress {
        frames: Mutex<Vec<ProgressFrame>>,
    }

    impl StubProgress {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                frames: Mutex::new(Vec::new()),
            })
        }
        fn frames(&self) -> Vec<(String, u64, OutboundProgressStatus)> {
            match self.frames.lock() {
                Ok(guard) => guard
                    .iter()
                    .map(|f| (f.transfer_id.clone(), f.bytes, f.status))
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
    }

    #[async_trait]
    impl OutboundProgressReporterPort for StubProgress {
        async fn report(
            &self,
            _target: &DeviceId,
            transfer_id: &str,
            bytes_transferred: u64,
            _total_bytes: Option<u64>,
            status: OutboundProgressStatus,
        ) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            if let Ok(mut guard) = self.frames.lock() {
                guard.push(ProgressFrame {
                    transfer_id: transfer_id.to_owned(),
                    bytes: bytes_transferred,
                    status,
                });
            }
        }
    }

    /// A fresh transfer id plus the UUID-string key progress frames carry.
    fn transfer_id() -> (ShareTransferId, String) {
        let id = uuid::Uuid::new_v4();
        (ShareTransferId::from_bytes(*id.as_bytes()), id.to_string())
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

    fn full_grants() -> ShareGrants {
        ShareGrants {
            read: true,
            write: true,
            delete: true,
        }
    }

    /// A store + confinement agreeing on `root_id` under `dir`, both authorized and
    /// resolving. Returns the handler plus the `root_id`.
    fn happy_setup(dir: &Path) -> (RemoteShareServe, ShareRootId, Arc<StubConfinement>) {
        setup_with_grants(dir, read_only_grants())
    }

    fn setup_with_grants(
        dir: &Path,
        grants: ShareGrants,
    ) -> (RemoteShareServe, ShareRootId, Arc<StubConfinement>) {
        setup_with_deps(dir, grants, StubBlobs::serving(b""), StubProgress::new())
    }

    /// `setup_with_grants` plus caller-chosen blob/progress doubles — the P4
    /// tests observe fetches, progress frames, and cancellation through them.
    fn setup_with_deps(
        dir: &Path,
        grants: ShareGrants,
        blobs: Arc<StubBlobs>,
        progress: Arc<StubProgress>,
    ) -> (RemoteShareServe, ShareRootId, Arc<StubConfinement>) {
        let root = ShareRoot {
            id: ShareRootId(uuid::Uuid::new_v4()),
            path: dir.to_string_lossy().into_owned(),
            label: "docs".to_owned(),
            grants,
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
            blobs,
            progress,
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
            blobs: StubBlobs::serving(b""),
            progress: StubProgress::new(),
        });
        assert_eq!(handler.hello().await, ShareAvailability::Suspended);

        // Locked (store fails to read) — fail-closed.
        let store = StubStore::failing(SharedRootStoreError::NotUnlocked);
        let conf =
            StubConfinement::with(ShareRootId(uuid::Uuid::new_v4()), PathBuf::from("/tmp/x"));
        let handler = RemoteShareServe::new(RemoteShareServeDeps {
            share_store: store,
            confinement: conf,
            blobs: StubBlobs::serving(b""),
            progress: StubProgress::new(),
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
            blobs: StubBlobs::serving(b""),
            progress: StubProgress::new(),
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
            blobs: StubBlobs::serving(b""),
            progress: StubProgress::new(),
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
        assert!(!page.entries[0].is_dir && page.entries[0].size_bytes == 5);
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
            blobs: StubBlobs::serving(b""),
            progress: StubProgress::new(),
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
        assert!(!entry.is_symlink);
        assert_eq!(entry.size_bytes, 10);
        assert!(entry.modified_at_ms > 0, "mtime should be post-epoch");

        // The root itself (empty rel) stats to a directory named after the root dir.
        let root_entry = handler.stat(&peer(), root_id, "").await.unwrap();
        assert!(root_entry.is_dir);
    }

    #[tokio::test]
    async fn stat_missing_path_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = happy_setup(tmp.path());
        // The path is well-formed and authorized, but the file does not exist.
        assert!(matches!(
            handler.stat(&peer(), root_id, "nope.txt").await,
            Err(ShareServeError::NotFound)
        ));
    }

    /// `mkdir` requires the write grant; a read-only root rejects opaquely.
    #[tokio::test]
    async fn mkdir_requires_write_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = happy_setup(tmp.path());
        assert!(matches!(
            handler.mkdir(&peer(), root_id, "newdir").await,
            Err(ShareServeError::NotAuthorized)
        ));
    }

    /// `mkdir` creates the leaf dir through the handle-based verb.
    #[tokio::test]
    async fn mkdir_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());
        handler.mkdir(&peer(), root_id, "newdir").await.unwrap();
        assert!(tmp.path().join("newdir").is_dir());

        // A second mkdir on the same name is a Conflict.
        assert!(matches!(
            handler.mkdir(&peer(), root_id, "newdir").await,
            Err(ShareServeError::Conflict)
        ));
    }

    /// Spec §5.2: rename needs write AND delete — write alone is denied.
    #[tokio::test]
    async fn rename_requires_write_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"x").unwrap();
        let write_only = ShareGrants {
            read: true,
            write: true,
            delete: false,
        };
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), write_only);
        assert!(matches!(
            handler.rename(&peer(), root_id, "a.txt", "b.txt").await,
            Err(ShareServeError::NotAuthorized)
        ));

        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());
        handler
            .rename(&peer(), root_id, "a.txt", "b.txt")
            .await
            .unwrap();
        assert!(tmp.path().join("b.txt").exists());

        // Existing destination is a Conflict.
        std::fs::write(tmp.path().join("a2.txt"), b"x").unwrap();
        std::fs::write(tmp.path().join("b2.txt"), b"y").unwrap();
        assert!(matches!(
            handler.rename(&peer(), root_id, "a2.txt", "b2.txt").await,
            Err(ShareServeError::Conflict)
        ));
    }

    /// `delete` moves the entry into the recycle namespace; `list_trash` sees it,
    /// `restore` brings it back, `empty_trash` clears the rest.
    #[tokio::test]
    async fn delete_restore_and_empty_trash_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("gone.txt"), b"data").unwrap();
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());

        handler.delete(&peer(), root_id, "gone.txt").await.unwrap();
        assert!(!tmp.path().join("gone.txt").exists());

        let page = handler
            .list_trash(&peer(), root_id, None, 10)
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].original_rel, "gone.txt");

        handler
            .restore(&peer(), root_id, &page.entries[0].trash_id, "gone.txt")
            .await
            .unwrap();
        assert_eq!(std::fs::read(tmp.path().join("gone.txt")).unwrap(), b"data");

        // Delete requires the delete grant; restore requires write + delete.
        let read_only = setup_with_grants(tmp.path(), read_only_grants());
        assert!(matches!(
            read_only.0.delete(&peer(), read_only.1, "gone.txt").await,
            Err(ShareServeError::NotAuthorized)
        ));
        assert!(matches!(
            read_only.0.list_trash(&peer(), read_only.1, None, 10).await,
            Err(ShareServeError::NotAuthorized)
        ));
    }

    /// `copy_within` copies a file inside the same root; a conflicting dest is denied.
    #[tokio::test]
    async fn copy_within_copies_and_conflicts() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("src.txt"), b"payload").unwrap();
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());

        handler
            .copy_within(&peer(), root_id, "src.txt", "dup.txt")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("dup.txt")).unwrap(),
            b"payload"
        );

        assert!(matches!(
            handler
                .copy_within(&peer(), root_id, "src.txt", "dup.txt")
                .await,
            Err(ShareServeError::Conflict)
        ));
    }

    /// Upload orchestration: `stage_upload` starts the pull, `commit_upload`
    /// waits for it to settle and lands the bytes; commit tombstones the id
    /// (`StagingNotFound` on re-commit, `TooLate` on a late abort).
    #[tokio::test]
    async fn stage_fetch_commit_and_abort_flow() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dest")).unwrap();
        let blobs = StubBlobs::serving(b"abc");
        let progress = StubProgress::new();
        let (handler, root_id, _conf) =
            setup_with_deps(tmp.path(), full_grants(), blobs.clone(), progress.clone());
        let (transfer, transfer_key) = transfer_id();

        let outcome = handler
            .stage_upload(
                &peer(),
                root_id,
                "dest",
                &[ShareStageEntry {
                    rel: "up.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 3,
                    ticket: Some(BlobTicket::from_bytes(vec![0xab])),
                }],
                transfer,
            )
            .await
            .unwrap();

        // Commit waits for the spawned fetch to settle, then lands the bytes.
        handler
            .commit_upload(&peer(), &[outcome.staging_id.clone()])
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("dest/up.bin")).unwrap(),
            b"abc"
        );

        // Tombstone: a late abort and a repeated commit are both `TooLate` —
        // a reply-lost commit retry learns "already landed" rather than an
        // ambiguous "unknown id".
        assert!(matches!(
            handler
                .commit_upload(&peer(), &[outcome.staging_id.clone()])
                .await,
            Err(ShareServeError::TooLate)
        ));
        assert!(matches!(
            handler
                .abort_upload(&peer(), &[outcome.staging_id.clone()])
                .await,
            Err(ShareServeError::TooLate)
        ));

        // Progress: the session reported a terminal Completed frame under the
        // client's transfer key.
        let frames = progress.frames();
        assert!(
            frames.iter().any(|(id, bytes, status)| id == &transfer_key
                && *bytes == 3
                && *status == OutboundProgressStatus::Completed),
            "expected a Completed frame for {transfer_key}, got {frames:?}"
        );

        // Abort path: stage a second set, then cancel — the session and the
        // staged dir disappear; a repeated abort is a no-op.
        let (abort, _) = transfer_id();
        let outcome = handler
            .stage_upload(
                &peer(),
                root_id,
                "dest",
                &[ShareStageEntry {
                    rel: "scratch.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 1,
                    ticket: Some(BlobTicket::from_bytes(vec![0xcd])),
                }],
                abort,
            )
            .await
            .unwrap();
        handler
            .abort_upload(&peer(), &[outcome.staging_id.clone()])
            .await
            .unwrap();
        assert!(blobs.shutdowns() >= 1);
        handler
            .abort_upload(&peer(), &[outcome.staging_id])
            .await
            .unwrap();
    }

    /// Abort mid-pull: a gated fetch is torn down by `shutdown_inflight_fetch`
    /// and the session reports `Cancelled`.
    #[tokio::test]
    async fn abort_tears_down_inflight_fetch() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dest")).unwrap();
        let blobs = StubBlobs::with(b"zzz", StubBlobBehavior::Gate);
        let progress = StubProgress::new();
        let (handler, root_id, _conf) =
            setup_with_deps(tmp.path(), full_grants(), blobs.clone(), progress.clone());
        let (transfer, transfer_key) = transfer_id();

        let outcome = handler
            .stage_upload(
                &peer(),
                root_id,
                "dest",
                &[ShareStageEntry {
                    rel: "slow.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 3,
                    ticket: Some(BlobTicket::from_bytes(vec![0xee])),
                }],
                transfer,
            )
            .await
            .unwrap();
        // Let the spawned fetch reach its gate.
        tokio::task::yield_now().await;

        handler
            .abort_upload(&peer(), &[outcome.staging_id.clone()])
            .await
            .unwrap();
        assert!(blobs.shutdowns() >= 1);
        let frames = progress.frames();
        assert!(
            frames.iter().any(|(id, _, status)| id == &transfer_key
                && *status
                    == OutboundProgressStatus::Cancelled {
                        reason: FileTransferCancellationReason::RemotePeer,
                    }),
            "expected a Cancelled frame, got {frames:?}"
        );
        // Nothing may land in the destination.
        assert!(!tmp.path().join("dest/slow.bin").exists());
    }

    /// A failed pull makes the set uncommittable: `commit` discards the staged
    /// residue and reports `Io`; the terminal frame is `Failed`.
    #[tokio::test]
    async fn commit_fails_and_discards_on_fetch_failure() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dest")).unwrap();
        let blobs = StubBlobs::with(b"", StubBlobBehavior::Fail);
        let progress = StubProgress::new();
        let (handler, root_id, _conf) =
            setup_with_deps(tmp.path(), full_grants(), blobs, progress.clone());
        let (transfer, transfer_key) = transfer_id();

        let outcome = handler
            .stage_upload(
                &peer(),
                root_id,
                "dest",
                &[ShareStageEntry {
                    rel: "dead.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 9,
                    ticket: Some(BlobTicket::from_bytes(vec![0xdd])),
                }],
                transfer,
            )
            .await
            .unwrap();

        assert!(matches!(
            handler
                .commit_upload(&peer(), &[outcome.staging_id.clone()])
                .await,
            Err(ShareServeError::Io)
        ));
        assert!(!tmp.path().join("dest/dead.bin").exists());
        let frames = progress.frames();
        assert!(
            frames
                .iter()
                .any(|(id, _, status)| id == &transfer_key
                    && *status == OutboundProgressStatus::Failed),
            "expected a Failed frame, got {frames:?}"
        );
    }

    /// A foreign peer's staging id is indistinguishable from an unknown one.
    #[tokio::test]
    async fn foreign_staging_id_is_staging_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dest")).unwrap();
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());
        let (transfer, _) = transfer_id();

        let outcome = handler
            .stage_upload(
                &peer(),
                root_id,
                "dest",
                &[ShareStageEntry {
                    rel: "a.bin".to_owned(),
                    is_dir: false,
                    size_bytes: 0,
                    ticket: Some(BlobTicket::from_bytes(vec![1])),
                }],
                transfer,
            )
            .await
            .unwrap();
        let foreign = DeviceId::new("other-peer");
        assert!(matches!(
            handler
                .commit_upload(&foreign, &[outcome.staging_id.clone()])
                .await,
            Err(ShareServeError::StagingNotFound)
        ));
        assert!(matches!(
            handler
                .abort_upload(&foreign, &[outcome.staging_id.clone()])
                .await,
            Err(ShareServeError::StagingNotFound)
        ));
        // The owner's session survives the foreign probe.
        handler
            .abort_upload(&peer(), &[outcome.staging_id])
            .await
            .unwrap();
    }

    /// A manifest file entry without a ticket is rejected before any staging
    /// space opens.
    #[tokio::test]
    async fn stage_upload_rejects_ticketless_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dest")).unwrap();
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), full_grants());
        let (transfer, _) = transfer_id();
        assert!(matches!(
            handler
                .stage_upload(
                    &peer(),
                    root_id,
                    "dest",
                    &[ShareStageEntry {
                        rel: "n.bin".to_owned(),
                        is_dir: false,
                        size_bytes: 1,
                        ticket: None,
                    }],
                    transfer,
                )
                .await,
            Err(ShareServeError::UnsupportedRequest)
        ));
        assert!(tmp.path().read_dir().unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".uniclipboard-staging-")));
    }

    /// `export` streams the verified fd into a pinned blob and returns its
    /// ticket + announced size.
    #[tokio::test]
    async fn export_publishes_blob_and_returns_ticket() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file.bin"), b"0123456789").unwrap();
        std::fs::create_dir(tmp.path().join("dir")).unwrap();
        let blobs = StubBlobs::serving(b"");
        let (handler, root_id, _conf) = setup_with_deps(
            tmp.path(),
            full_grants(),
            blobs.clone(),
            StubProgress::new(),
        );

        let outcome = handler.export(&peer(), root_id, "file.bin").await.unwrap();
        assert_eq!(outcome.size_bytes, 10);
        assert!(!outcome.ticket.as_bytes().is_empty());
        // The published payload is exactly the checked file's bytes, pinned
        // under a RemoteShareExport lease tag.
        let (reason, bytes) = blobs.last_published().unwrap();
        assert_eq!(bytes, b"0123456789");
        assert!(matches!(reason, TagReason::RemoteShareExport(_)));

        // A directory cannot be exported.
        assert!(matches!(
            handler.export(&peer(), root_id, "dir").await,
            Err(ShareServeError::IsADirectory)
        ));

        // Export needs the read grant.
        let write_only = ShareGrants {
            read: false,
            write: true,
            delete: true,
        };
        let (handler, root_id, _conf) = setup_with_grants(tmp.path(), write_only);
        assert!(matches!(
            handler.export(&peer(), root_id, "file.bin").await,
            Err(ShareServeError::NotAuthorized)
        ));
    }

    /// Redaction: the domain types' `Debug` must never print a file name, a root
    /// label, or a blob ticket (spec §13 I4).
    #[test]
    fn debug_redacts_names_and_labels() {
        let entry = ShareDirectoryEntry {
            name: "secret-file.txt".to_owned(),
            is_dir: false,
            is_symlink: false,
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

        let outcome = ShareExportOutcome {
            ticket: BlobTicket::from_bytes(b"secret-ticket-bytes".to_vec()),
            size_bytes: 1,
        };
        assert!(!format!("{outcome:?}").contains("secret-ticket-bytes"));

        let staged = ShareStageEntry {
            rel: "dir/file.txt".to_owned(),
            is_dir: false,
            size_bytes: 1,
            ticket: Some(BlobTicket::from_bytes(b"ticket-payload".to_vec())),
        };
        let text = format!("{staged:?}");
        assert!(!text.contains("file.txt"));
        assert!(!text.contains("ticket-payload"));
    }
}
