//! Transfer orchestration for the remote-share serve side.
//!
//! `serve_handler` owns authorize-then-confine; this module owns everything
//! after a request is admitted: opening the kernel staging set, pulling each
//! manifest entry's `BlobTicket` into it, aggregating byte progress onto the
//! `OutboundProgressReporterPort` back-channel keyed by the client-chosen
//! `transfer_id`, and turning a verified export fd into a pinned blob +
//! ticket lease.
//!
//! Lifecycle facts (session ownership, commit tombstones, export leases) live
//! in one lock here, so `commit`/`abort` classify `staging_id`s atomically —
//! a committed id can never race back into "in flight".

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Notify, Semaphore};

use uc_core::file_transfer::{
    FileTransferCancellationReason, OutboundProgressReporterPort, OutboundProgressStatus,
};
use uc_core::ids::DeviceId;
use uc_core::ports::blob::{BlobError, BlobProgressSink, BlobTicket, BlobTransferPort, TagReason};
use uc_core::ports::remote_share::{
    ConfinedTarget, ShareConfinementPort, ShareExportOutcome, ShareRootId, ShareServeError,
    ShareStageEntry, ShareStageOutcome, ShareStagedEntry, ShareTransferId,
};

use super::serve_handler::map_confine;

/// Concurrent blob pulls across all open upload sessions. Queued entries
/// re-check `cancelled` after acquiring a permit, so an abort skips work that
/// never started.
const MAX_CONCURRENT_FETCHES: usize = 4;

/// How long an exported blob stays pinned after the control-plane reply.
/// The peer may start its pull lazily; the lease is released on the next
/// `publish_export` sweep once expired.
const EXPORT_LEASE_TTL: Duration = Duration::from_secs(30 * 60);

/// Runtime capabilities shared by the coordinator, its sessions, and the
/// spawned fetch tasks — sessions hold this `Arc` so tasks never reach back
/// into the coordinator's table lock.
struct TransferShared {
    confinement: Arc<dyn ShareConfinementPort>,
    blobs: Arc<dyn BlobTransferPort>,
    progress: Arc<dyn OutboundProgressReporterPort>,
    fetch_permits: Semaphore,
}

/// Mutable progress bookkeeping for one upload session.
struct SessionState {
    /// Last reported cumulative bytes per manifest index (dirs always 0).
    entry_bytes: Vec<u64>,
    /// File entries whose fetch task has not finished yet.
    outstanding: usize,
    /// At least one fetch failed — the set can never commit.
    failed: bool,
    /// `abort_upload` ran — queued entries must not start fetching.
    cancelled: bool,
    /// The terminal progress frame was emitted exactly once.
    terminal_reported: bool,
}

/// A staging set opened by `stage_upload`. The kernel-issued `staging_id`
/// keys the coordinator table; the session records which peer/root/dir it
/// belongs to so `commit`/`abort` re-authorize against recorded facts, never
/// client-supplied context.
pub(crate) struct UploadSession {
    shared: Arc<TransferShared>,
    owner: DeviceId,
    root: ShareRootId,
    dir: ConfinedTarget,
    staged: Vec<ShareStagedEntry>,
    /// Fetch credentials parallel to `staged`; `None` for directory entries.
    tickets: Vec<Option<BlobTicket>>,
    /// `transfer_id` in the UUID-string spelling the progress port expects.
    transfer_key: String,
    /// Declared total of all file-entry sizes (for `total_bytes` reporting).
    total_bytes: u64,
    state: Mutex<SessionState>,
    /// `notify_one` storage semantics: a completion that races a waiter's
    /// state check still leaves the stored permit the next `notified()`
    /// consumes — `wait_settled` cannot miss the last task's signal.
    settle: Notify,
}

impl UploadSession {
    pub(crate) fn root(&self) -> ShareRootId {
        self.root
    }

    pub(crate) fn dir(&self) -> &ConfinedTarget {
        &self.dir
    }

    pub(crate) fn staged(&self) -> &[ShareStagedEntry] {
        &self.staged
    }

    /// Whether the set can no longer commit (fetch failure or abort).
    pub(crate) fn is_uncommittable(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.failed || state.cancelled,
            // discarded-source[lock-poisoned]: `PoisonError`: a poisoned state is
            // fail-closed — treat the set as uncommittable.
            Err(_) => true,
        }
    }

    fn is_cancelled(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.cancelled,
            Err(_) => true,
        }
    }

    /// Wait until every spawned fetch task has finished (success, failure, or
    /// skipped-after-cancel). `Notify::notify_one` stores a permit, so a task
    /// finishing between the state check and `notified()` still wakes the loop
    /// — the last completion can never be missed.
    pub(crate) async fn wait_settled(&self) {
        loop {
            match self.state.lock() {
                Ok(state) if state.outstanding == 0 => return,
                // discarded-source[lock-poisoned]: `PoisonError`: a poisoned
                // state cannot be consulted; stop waiting rather than hang.
                Err(_) => return,
                _ => {}
            }
            self.settle.notified().await;
        }
    }

    /// Fold one adapter progress callback into the session aggregate and
    /// forward it to the uploader. Reporting is best-effort: the port is
    /// infallible by contract and failures never reach the fetch path.
    async fn note_progress(&self, index: usize, bytes_transferred: u64) {
        let sum = match self.state.lock() {
            Ok(mut state) => {
                if let Some(slot) = state.entry_bytes.get_mut(index) {
                    *slot = bytes_transferred;
                }
                state.entry_bytes.iter().sum()
            }
            Err(_) => return,
        };
        self.report(sum, OutboundProgressStatus::InProgress).await;
    }

    /// Record one fetch task's terminal outcome. On failure the whole set is
    /// dead: sibling pulls are shut down so bandwidth is not spent on a set
    /// that can never commit.
    async fn note_entry_done(&self, index: usize, ok: bool) {
        let siblings: Vec<BlobTicket> = match self.state.lock() {
            Ok(mut state) => {
                if ok {
                    if let Some(slot) = state.entry_bytes.get_mut(index) {
                        *slot = self
                            .staged
                            .get(index)
                            .map(|entry| entry.size_bytes)
                            .unwrap_or(*slot);
                    }
                } else {
                    state.failed = true;
                }
                state.outstanding = state.outstanding.saturating_sub(1);
                if state.failed {
                    self.tickets
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != index)
                        .filter_map(|(_, ticket)| ticket.clone())
                        .collect()
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        };
        for ticket in siblings {
            // discarded-source[best-effort-cleanup]: `BlobError`: shutdown is a
            // release-only courtesy; the session is already marked failed.
            let _ = self.shared.blobs.shutdown_inflight_fetch(&ticket).await;
        }
        self.maybe_report_terminal().await;
        self.settle.notify_one();
    }

    /// Mark the set cancelled and emit the terminal frame if it is already
    /// settled (abort of a fully-fetched set waiting on commit).
    async fn mark_cancelled(&self) {
        match self.state.lock() {
            Ok(mut state) => state.cancelled = true,
            Err(_) => return,
        }
        self.maybe_report_terminal().await;
    }

    /// Emit the single terminal progress frame once `outstanding` reaches 0:
    /// `Cancelled` wins over `Failed` — an aborted set is an expected outcome
    /// even if some fetch also failed on the way down.
    async fn maybe_report_terminal(&self) {
        let (sum, status) = match self.state.lock() {
            Ok(mut state) => {
                if state.outstanding > 0 || state.terminal_reported {
                    return;
                }
                state.terminal_reported = true;
                let status = if state.cancelled {
                    OutboundProgressStatus::Cancelled {
                        reason: FileTransferCancellationReason::RemotePeer,
                    }
                } else if state.failed {
                    OutboundProgressStatus::Failed
                } else {
                    OutboundProgressStatus::Completed
                };
                (state.entry_bytes.iter().sum::<u64>(), status)
            }
            Err(_) => return,
        };
        self.report(sum, status).await;
    }

    async fn report(&self, bytes_transferred: u64, status: OutboundProgressStatus) {
        self.shared
            .progress
            .report(
                &self.owner,
                &self.transfer_key,
                bytes_transferred,
                Some(self.total_bytes),
                status,
            )
            .await;
    }
}

/// Forwards one manifest entry's byte progress into its session aggregate.
struct EntryProgressSink {
    session: Arc<UploadSession>,
    index: usize,
}

#[async_trait]
impl BlobProgressSink for EntryProgressSink {
    async fn report(&self, bytes_transferred: u64, _total_bytes: Option<u64>) {
        self.session
            .note_progress(self.index, bytes_transferred)
            .await;
    }
}

/// A pinned blob published for `Export`. The named tag keeps the ciphertext
/// alive past any GC sweep until the lease expires; `publish_export` sweeps
/// expired leases before minting a new one.
struct ExportLease {
    reason: TagReason,
    expires: Instant,
}

/// Sessions + commit tombstones + export leases under one lock, so the
/// `staging_id` lifecycle decision is atomic.
struct TransferTables {
    sessions: HashMap<String, Arc<UploadSession>>,
    /// Ids whose commit already landed — late `abort` answers `TooLate`.
    committed: HashSet<String>,
    exports: HashMap<String, ExportLease>,
}

/// Owns the upload-download mechanics behind `stage_upload` / `commit_upload`
/// / `abort_upload` / `export`. Authorization stays in the serve handler;
/// this coordinator only sees admitted requests.
pub(crate) struct ShareTransferCoordinator {
    shared: Arc<TransferShared>,
    tables: Mutex<TransferTables>,
}

impl ShareTransferCoordinator {
    pub(crate) fn new(
        confinement: Arc<dyn ShareConfinementPort>,
        blobs: Arc<dyn BlobTransferPort>,
        progress: Arc<dyn OutboundProgressReporterPort>,
    ) -> Self {
        Self {
            shared: Arc::new(TransferShared {
                confinement,
                blobs,
                progress,
                fetch_permits: Semaphore::new(MAX_CONCURRENT_FETCHES),
            }),
            tables: Mutex::new(TransferTables {
                sessions: HashMap::new(),
                committed: HashSet::new(),
                exports: HashMap::new(),
            }),
        }
    }

    /// Open a staging set: kernel staging dir, directory entries materialised,
    /// one bounded fetch task per file entry, session registered. Any manifest
    /// rejection discards the whole set (fail-closed, no half-prepared state).
    pub(crate) async fn open_upload(
        &self,
        owner: &DeviceId,
        root: ShareRootId,
        dir: ConfinedTarget,
        entries: Vec<ShareStageEntry>,
        transfer_id: ShareTransferId,
    ) -> Result<ShareStageOutcome, ShareServeError> {
        // Every file entry must carry a fetch credential — a manifest without
        // one is a request shape this build cannot honour.
        if entries.iter().any(|e| !e.is_dir && e.ticket.is_none()) {
            return Err(ShareServeError::UnsupportedRequest);
        }
        let staging_id = self
            .shared
            .confinement
            .create_staging(root)
            .await
            .map_err(map_confine)?;
        let mut staged = Vec::with_capacity(entries.len());
        let mut tickets = Vec::with_capacity(entries.len());
        let mut fetch_paths: Vec<Option<PathBuf>> = Vec::with_capacity(entries.len());
        let mut total_bytes = 0u64;
        for entry in &entries {
            match self
                .shared
                .confinement
                .staging_entry_path(root, &staging_id, &entry.rel, entry.is_dir)
                .await
            {
                Ok(path) => {
                    staged.push(ShareStagedEntry {
                        rel: entry.rel.clone(),
                        is_dir: entry.is_dir,
                        size_bytes: entry.size_bytes,
                    });
                    tickets.push(entry.ticket.clone());
                    fetch_paths.push(if entry.is_dir { None } else { Some(path) });
                    if !entry.is_dir {
                        total_bytes = total_bytes.saturating_add(entry.size_bytes);
                    }
                }
                Err(error) => {
                    // A rejected manifest entry discards the whole staging set.
                    // discarded-source[best-effort-cleanup]: `ConfineError`: the
                    // leftover staging dir is inert and reclaimed by the
                    // registration sweep.
                    let _ = self
                        .shared
                        .confinement
                        .abort_staging(root, &staging_id)
                        .await;
                    return Err(map_confine(error));
                }
            }
        }

        let outstanding = entries.iter().filter(|e| !e.is_dir).count();
        let session = Arc::new(UploadSession {
            shared: Arc::clone(&self.shared),
            owner: owner.clone(),
            root,
            dir,
            staged,
            tickets,
            transfer_key: transfer_id.as_uuid_string(),
            total_bytes,
            state: Mutex::new(SessionState {
                entry_bytes: vec![0; entries.len()],
                outstanding,
                failed: false,
                cancelled: false,
                terminal_reported: false,
            }),
            settle: Notify::new(),
        });
        {
            // discarded-source[lock-poisoned]: `PoisonError`: a poisoned table is
            // a fail-closed refusal; the opened staging dir is discarded.
            let mut tables = self.tables.lock().map_err(|_| ShareServeError::Io)?;
            tables
                .sessions
                .insert(staging_id.clone(), Arc::clone(&session));
        }
        // Zero-file sets are settled at birth; report `Completed` up front so
        // the uploader's task tracker sees a terminal frame even without fetches.
        if outstanding == 0 {
            session.maybe_report_terminal().await;
        }
        for (index, path) in fetch_paths.into_iter().enumerate() {
            let Some(path) = path else { continue };
            tokio::spawn(fetch_entry(Arc::clone(&session), index, path));
        }
        Ok(ShareStageOutcome { staging_id })
    }

    /// Take a session out of the table for the exclusive commit path.
    /// Tombstoned ids are `TooLate`; unknown or foreign ids are
    /// `StagingNotFound` (a foreign id goes back untouched — it is not
    /// probeable and not consumed).
    pub(crate) fn take_upload(
        &self,
        owner: &DeviceId,
        staging_id: &str,
    ) -> Result<Arc<UploadSession>, ShareServeError> {
        // discarded-source[lock-poisoned]: `PoisonError`: a poisoned table is a
        // fail-closed refusal; the guard carries no usable diagnostic.
        let mut tables = self.tables.lock().map_err(|_| ShareServeError::Io)?;
        if tables.committed.contains(staging_id) {
            return Err(ShareServeError::TooLate);
        }
        match tables.sessions.remove(staging_id) {
            Some(session) if session.owner == *owner => Ok(session),
            Some(session) => {
                tables.sessions.insert(staging_id.to_owned(), session);
                Err(ShareServeError::StagingNotFound)
            }
            None => Err(ShareServeError::StagingNotFound),
        }
    }

    /// Put a session back after a retryable failure (denied re-auth or a
    /// failed `commit_staging`). A same-id session wins if one appeared.
    pub(crate) fn restore_upload(&self, staging_id: &str, session: Arc<UploadSession>) {
        if let Ok(mut tables) = self.tables.lock() {
            tables
                .sessions
                .entry(staging_id.to_owned())
                .or_insert(session);
        }
    }

    /// Record a landed commit; subsequent `abort`/`commit` on the id classify
    /// as `TooLate`/`StagingNotFound` respectively.
    pub(crate) fn mark_committed(&self, staging_id: &str) {
        if let Ok(mut tables) = self.tables.lock() {
            tables.committed.insert(staging_id.to_owned());
        }
    }

    /// Discard a staged set. Unknown ids are ignored (abort is idempotent);
    /// tombstoned ids are `TooLate`; foreign ids are `StagingNotFound`.
    /// In-flight fetches are shut down and awaited before the staging dir is
    /// removed, so a platform that locks open files still releases cleanly.
    pub(crate) async fn abort_upload(
        &self,
        owner: &DeviceId,
        staging_id: &str,
    ) -> Result<(), ShareServeError> {
        let session = {
            // The poisoned guard cannot be carried across threads and holds no
            // usable diagnostics; fail-closed as an opaque local error.
            // discarded-source[lock-poisoned]: `PoisonError`: guard carries no usable payload.
            let mut tables = self.tables.lock().map_err(|_| ShareServeError::Io)?;
            if tables.committed.contains(staging_id) {
                return Err(ShareServeError::TooLate);
            }
            match tables.sessions.remove(staging_id) {
                Some(session) if session.owner == *owner => Some(session),
                Some(session) => {
                    tables.sessions.insert(staging_id.to_owned(), session);
                    return Err(ShareServeError::StagingNotFound);
                }
                None => None,
            }
        };
        let Some(session) = session else {
            return Ok(());
        };
        session.mark_cancelled().await;
        for ticket in session.tickets.iter().flatten() {
            // discarded-source[best-effort-cleanup]: `BlobError`: release-only;
            // the session is already cancelled and being torn down regardless.
            let _ = self.shared.blobs.shutdown_inflight_fetch(ticket).await;
        }
        session.wait_settled().await;
        self.shared
            .confinement
            .abort_staging(session.root, staging_id)
            .await
            .map_err(map_confine)
    }

    /// Publish an already-verified export fd and mint its fetch ticket. The
    /// blob is pinned under a per-export lease tag until the lease expires;
    /// expired leases are untagged on every call.
    pub(crate) async fn publish_export(
        &self,
        file: std::fs::File,
        size_bytes: u64,
    ) -> Result<ShareExportOutcome, ShareServeError> {
        self.sweep_exports().await;
        let lease_id = uuid::Uuid::new_v4().to_string();
        let reason = TagReason::RemoteShareExport(lease_id.clone());
        let digest = self
            .shared
            .blobs
            .publish_reader(file, reason.clone())
            .await
            .map_err(map_blob)?;
        let ticket = match self.shared.blobs.issue_ticket(&digest).await {
            Ok(ticket) => ticket,
            Err(error) => {
                // discarded-source[best-effort-cleanup]: `BlobError`: the pinned
                // tag has no client to serve; untagging may itself fail, in
                // which case the tag simply expires unused.
                let _ = self.shared.blobs.untag(reason).await;
                return Err(map_blob(error));
            }
        };
        if let Err(error) = self.insert_lease(
            lease_id,
            ExportLease {
                reason: reason.clone(),
                expires: Instant::now() + EXPORT_LEASE_TTL,
            },
        ) {
            // A poisoned table is fail-closed: the pinned tag is released
            // before the refusal returns (the untag itself is best-effort).
            // discarded-source[best-effort-cleanup]: `BlobError`.
            let _ = self.shared.blobs.untag(reason).await;
            return Err(error);
        }
        Ok(ShareExportOutcome { ticket, size_bytes })
    }

    /// Register one export lease. Kept synchronous so no `MutexGuard` — a
    /// `!Send` type — ever lives across an `.await` in the caller.
    fn insert_lease(&self, lease_id: String, lease: ExportLease) -> Result<(), ShareServeError> {
        // discarded-source[lock-poisoned]: `PoisonError`: a poisoned table is a
        // fail-closed refusal; the guard carries no usable diagnostic.
        let mut tables = self.tables.lock().map_err(|_| ShareServeError::Io)?;
        tables.exports.insert(lease_id, lease);
        Ok(())
    }

    /// Release every expired export lease. Called from `publish_export` so the
    /// pin set stays bounded by live transfers, not by peer behaviour.
    async fn sweep_exports(&self) {
        let expired: Vec<TagReason> = match self.tables.lock() {
            Ok(mut tables) => {
                let now = Instant::now();
                let dead: Vec<String> = tables
                    .exports
                    .iter()
                    .filter(|(_, lease)| lease.expires <= now)
                    .map(|(id, _)| id.clone())
                    .collect();
                dead.into_iter()
                    .filter_map(|id| tables.exports.remove(&id).map(|lease| lease.reason))
                    .collect()
            }
            // discarded-source[lock-poisoned]: `PoisonError`: a poisoned table
            // cannot be swept; the next successful publish retries.
            Err(_) => Vec::new(),
        };
        for reason in expired {
            // discarded-source[best-effort-cleanup]: `BlobError`: an untag that
            // fails leaves a pinned blob that GC declines to reclaim — the
            // failure is adapter-local and already logged there.
            let _ = self.shared.blobs.untag(reason).await;
        }
    }
}

/// One spawned pull: bound by the shared permit pool, cancelled sets exit
/// before touching the network, and the adapter's own progress callbacks feed
/// the session aggregate.
async fn fetch_entry(session: Arc<UploadSession>, index: usize, path: PathBuf) {
    let _permit = match session.shared.fetch_permits.acquire().await {
        Ok(permit) => permit,
        // Semaphore never closes; a closed pool is still fail-closed.
        Err(_) => {
            session.note_entry_done(index, false).await;
            return;
        }
    };
    if session.is_cancelled() {
        session.note_entry_done(index, false).await;
        return;
    }
    let Some(ticket) = session.tickets.get(index).and_then(Clone::clone) else {
        session.note_entry_done(index, false).await;
        return;
    };
    let sink = EntryProgressSink {
        session: Arc::clone(&session),
        index,
    };
    let outcome = session
        .shared
        .blobs
        .fetch_to_path(&ticket, &path, Some(&sink))
        .await;
    session.note_entry_done(index, outcome.is_ok()).await;
}

/// A blob-layer failure collapses into the payload-free wire `Io` code; the
/// adapter keeps the detailed source in its own logs.
fn map_blob(_error: BlobError) -> ShareServeError {
    // discarded-source[business-outcome]: `BlobError`: the wire `DenyCode` is a
    // fixed classification enum with no source slot.
    ShareServeError::Io
}
