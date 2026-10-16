//! remote-share（设备文件共享）操作的执行器：契约输入 → 会话装配上的
//! `RemoteShareClient`（peer 侧）与 `ShareRootsRegistry`（本机清单）动词 →
//! 契约结果。本模块只做 DTO 整形与错误映射——枚举/发布/分片/commit/abort/
//! 导出/收敛的完整流程归 Application 责任人（spec §9.1）。

use std::path::PathBuf;
use std::sync::Arc;

use uc_application::facade::remote_share::{
    ReconcileReport, RemoteShareClient, ShareOutboundError, ShareRootsRegistry,
    ShareTransferCancelOutcome, ShareUploadSource,
};
use uc_core::ids::DeviceId;
use uc_core::ports::remote_share::{
    RemoteShareClientError, ShareAvailability, ShareClientDeny, ShareGrants, ShareRoot,
    ShareRootId, ShareStoreDoc, ShareTransferId, SharedRootStoreError,
};
use uc_observability_contract::{error_source::io_error_kind, uc_error};

use crate::error_codes::{
    PEER_SHARE_CANCELLED_CODE, PEER_SHARE_CONFLICT_CODE, PEER_SHARE_DENIED_CODE,
    PEER_SHARE_FAILED_CODE, PEER_SHARE_INTERRUPTED_CODE, PEER_SHARE_IO_CODE,
    PEER_SHARE_LOCKED_CODE, PEER_SHARE_NOT_FOUND_CODE, PEER_SHARE_QUOTA_CODE,
    PEER_SHARE_RESERVED_NAME_CODE, PEER_SHARE_REVOKED_CODE, PEER_SHARE_ROOT_GONE_CODE,
    PEER_SHARE_SUSPENDED_CODE, PEER_SHARE_TOO_LARGE_CODE, PEER_SHARE_TOO_LATE_CODE,
    PEER_SHARE_TOO_MANY_ENTRIES_CODE, PEER_SHARE_UNAVAILABLE_CODE, PEER_SHARE_UNSUPPORTED_CODE,
    PEER_SHARE_UNSUPPORTED_REQUEST_CODE, REMOTE_SHARE_LOCKED_CODE, REMOTE_SHARE_STATE_FAILED_CODE,
};
use crate::{
    CancelPeerShareTransferInput, DownloadPeerShareInput, EngineError, EngineErrorCategory,
    MutatePeerShareInput, OperationResult, PeerShareAction, PeerShareDirectoryPage,
    PeerShareDownloadSummary, PeerShareEntrySummary, PeerShareListInput, PeerShareMutationOutcome,
    PeerShareRelInput, PeerShareRequest, PeerShareRootSummary, PeerShareState,
    PeerShareTransferCancelOutcome, PeerShareTrashEntrySummary, PeerShareTrashListInput,
    PeerShareTrashPage, PeerShareUploadSummary, RemoteShareReconcileSummary,
    RemoteShareRootSummary, RemoteShareStateSummary, ReplaceRemoteShareRootsInput,
    SetRemoteShareSuspendedInput, UploadPeerShareInput,
};

fn invalid_input() -> EngineError {
    EngineError::new(
        PEER_SHARE_FAILED_CODE,
        EngineErrorCategory::InvalidInput,
        false,
    )
}

fn parse_root_id(raw: &str) -> Result<ShareRootId, EngineError> {
    uuid::Uuid::parse_str(raw)
        .map(|id| ShareRootId::from_wire_bytes(*id.as_bytes()))
        // discarded-source[input-validation]: `uuid::Error`: 语法错误对调用方无额外信息。
        .map_err(|_| invalid_input())
}

fn parse_transfer_id(raw: &str) -> Result<ShareTransferId, EngineError> {
    uuid::Uuid::parse_str(raw)
        .map(|id| ShareTransferId::from_bytes(*id.as_bytes()))
        // discarded-source[input-validation]: `uuid::Error`: 语法错误对调用方无额外信息。
        .map_err(|_| invalid_input())
}

fn peer_id(raw: &str) -> DeviceId {
    DeviceId::new(raw.to_owned())
}

/// §12 的 17 个稳定 deny 码 → §9.1 的数字码块 2101–2117。category 按语义归
/// `NotFound`/`Conflict`/`Unavailable`/`InvalidState`/`Unauthorized`/
/// `Cancelled`；daemon 按数字码表翻译回 API 字符串码。
fn deny_error(deny: ShareClientDeny) -> EngineError {
    let (code, category, retryable) = match deny {
        ShareClientDeny::Locked => (
            PEER_SHARE_LOCKED_CODE,
            EngineErrorCategory::InvalidState,
            false,
        ),
        ShareClientDeny::Unsupported => (
            PEER_SHARE_UNSUPPORTED_CODE,
            EngineErrorCategory::Unavailable,
            false,
        ),
        ShareClientDeny::UnsupportedRequest => (
            PEER_SHARE_UNSUPPORTED_REQUEST_CODE,
            EngineErrorCategory::Internal,
            false,
        ),
        ShareClientDeny::Suspended => (
            PEER_SHARE_SUSPENDED_CODE,
            EngineErrorCategory::InvalidState,
            false,
        ),
        ShareClientDeny::Revoked => (
            PEER_SHARE_REVOKED_CODE,
            EngineErrorCategory::Unauthorized,
            false,
        ),
        ShareClientDeny::Denied => (
            PEER_SHARE_DENIED_CODE,
            EngineErrorCategory::Unauthorized,
            false,
        ),
        ShareClientDeny::ReservedName => (
            PEER_SHARE_RESERVED_NAME_CODE,
            EngineErrorCategory::InvalidInput,
            false,
        ),
        ShareClientDeny::NotFound => (
            PEER_SHARE_NOT_FOUND_CODE,
            EngineErrorCategory::NotFound,
            false,
        ),
        ShareClientDeny::Conflict => (
            PEER_SHARE_CONFLICT_CODE,
            EngineErrorCategory::Conflict,
            false,
        ),
        ShareClientDeny::RootGone => (
            PEER_SHARE_ROOT_GONE_CODE,
            EngineErrorCategory::NotFound,
            false,
        ),
        ShareClientDeny::Quota => (
            PEER_SHARE_QUOTA_CODE,
            EngineErrorCategory::Unavailable,
            false,
        ),
        ShareClientDeny::TooLarge => (
            PEER_SHARE_TOO_LARGE_CODE,
            EngineErrorCategory::InvalidInput,
            false,
        ),
        ShareClientDeny::TooManyEntries => (
            PEER_SHARE_TOO_MANY_ENTRIES_CODE,
            EngineErrorCategory::InvalidInput,
            false,
        ),
        ShareClientDeny::Io => (PEER_SHARE_IO_CODE, EngineErrorCategory::Unavailable, true),
        ShareClientDeny::Cancelled => (
            PEER_SHARE_CANCELLED_CODE,
            EngineErrorCategory::Cancelled,
            false,
        ),
        ShareClientDeny::TooLate => (
            PEER_SHARE_TOO_LATE_CODE,
            EngineErrorCategory::Conflict,
            false,
        ),
        ShareClientDeny::Interrupted => (
            PEER_SHARE_INTERRUPTED_CODE,
            EngineErrorCategory::Unavailable,
            true,
        ),
    };
    EngineError::new(code, category, retryable)
}

/// `Unreachable` 与帧 IO → `Unavailable`（可重试）；`UnexpectedReply` →
/// `Internal`（协议违例不可重试）。
fn map_share_error(error: RemoteShareClientError) -> EngineError {
    match error {
        RemoteShareClientError::Refused(deny) => deny_error(deny),
        RemoteShareClientError::Unreachable | RemoteShareClientError::Io(_) => {
            uc_error!(
                error_kind = "peer_share_request",
                io_error_kind = io_error_kind(&error),
                "remote share request failed"
            );
            EngineError::new(
                PEER_SHARE_UNAVAILABLE_CODE,
                EngineErrorCategory::Unavailable,
                true,
            )
        }
        RemoteShareClientError::UnexpectedReply => {
            uc_error!(
                error_kind = "peer_share_protocol",
                "remote share peer violated the wire contract"
            );
            EngineError::new(PEER_SHARE_FAILED_CODE, EngineErrorCategory::Internal, false)
        }
    }
}

fn map_outbound_error(error: ShareOutboundError) -> EngineError {
    match error {
        ShareOutboundError::Remote(source) => map_share_error(source),
        ShareOutboundError::Enumerate(source) => {
            uc_error!(
                error_kind = "peer_share_local",
                io_error_kind = io_error_kind(&source),
                "remote share local enumeration failed"
            );
            EngineError::new(PEER_SHARE_FAILED_CODE, EngineErrorCategory::Internal, false)
        }
        ShareOutboundError::Blob(source) => {
            uc_error!(
                error_kind = "peer_share_local",
                io_error_kind = io_error_kind(&source),
                "remote share local blob staging failed"
            );
            EngineError::new(PEER_SHARE_FAILED_CODE, EngineErrorCategory::Internal, false)
        }
        ShareOutboundError::Empty => EngineError::new(
            PEER_SHARE_FAILED_CODE,
            EngineErrorCategory::InvalidInput,
            false,
        ),
        ShareOutboundError::Cancelled => EngineError::new(
            PEER_SHARE_CANCELLED_CODE,
            EngineErrorCategory::Cancelled,
            false,
        ),
    }
}

fn map_store_error(error: SharedRootStoreError) -> EngineError {
    let (code, category) = match &error {
        // Space 未解锁不是存储故障：单独成码，daemon 据此译为
        // `423 session_locked` / `GET state` 的 `locked` 形态。
        SharedRootStoreError::NotUnlocked => {
            (REMOTE_SHARE_LOCKED_CODE, EngineErrorCategory::Unavailable)
        }
        _ => (
            REMOTE_SHARE_STATE_FAILED_CODE,
            EngineErrorCategory::Internal,
        ),
    };
    uc_error!(
        error_kind = "remote_share_store",
        io_error_kind = io_error_kind(&error),
        "remote share root store failed"
    );
    EngineError::new(code, category, false)
}

fn reconcile_summary(report: ReconcileReport) -> RemoteShareReconcileSummary {
    RemoteShareReconcileSummary {
        registered: report.registered as u32,
        failed: report.failed as u32,
        unregistered: report.unregistered as u32,
    }
}

// ── 本机共享管理 ─────────────────────────────────────────────────────

/// `QueryRemoteShareState`：清单原文（suspended + 根及本机路径）——本机
/// 持有者的管理面事实，锁定形态由 daemon 结合加密态拼装。
pub async fn execute_query_remote_share_state(
    registry: Arc<ShareRootsRegistry>,
) -> Result<OperationResult, EngineError> {
    let doc = registry.current_doc().await.map_err(map_store_error)?;
    Ok(OperationResult::RemoteShareState(RemoteShareStateSummary {
        suspended: doc.suspended,
        roots: doc
            .roots
            .iter()
            .map(|root| RemoteShareRootSummary {
                id: root.id.0.to_string(),
                path: PathBuf::from(&root.path),
                label: root.label.clone(),
                read: root.grants.read,
                write: root.grants.write,
                delete: root.grants.delete,
                enabled: root.enabled,
            })
            .collect(),
    }))
}

/// `ReplaceRemoteShareRoots`：整表替换根列表（`suspended` 保留现值）。
/// `id` 缺失的条目分配新 id；既有 id 命中旧表同 id 根时沿用其
/// `added_at_ms`，否则取当前时钟。
pub async fn execute_replace_remote_share_roots(
    registry: Arc<ShareRootsRegistry>,
    input: ReplaceRemoteShareRootsInput,
    now_ms: i64,
) -> Result<OperationResult, EngineError> {
    let mut roots = Vec::with_capacity(input.roots.len());
    for entry in input.roots {
        let path = entry
            .path
            .to_str()
            .map(str::to_owned)
            .ok_or_else(invalid_input)?;
        let id = match entry.id.as_deref() {
            Some(raw) => parse_root_id(raw)?,
            None => ShareRootId(uuid::Uuid::new_v4()),
        };
        roots.push((id, entry, path));
    }
    let report = registry
        .update_doc(|doc| {
            doc.roots = roots
                .iter()
                .map(|(id, entry, path)| ShareRoot {
                    id: *id,
                    added_at_ms: doc
                        .roots
                        .iter()
                        .find(|old| old.id == *id)
                        .map(|old| old.added_at_ms)
                        .unwrap_or(now_ms),
                    path: path.clone(),
                    label: entry.label.clone(),
                    grants: ShareGrants {
                        read: entry.read,
                        write: entry.write,
                        delete: entry.delete,
                    },
                    enabled: entry.enabled,
                })
                .collect();
            doc.schema_version = ShareStoreDoc::CURRENT_SCHEMA_VERSION;
        })
        .await
        .map_err(map_store_error)?;
    Ok(OperationResult::RemoteShareReconciled(reconcile_summary(
        report,
    )))
}

/// `SetRemoteShareSuspended`：只翻动总开关，保留根列表与登记表收敛语义。
pub async fn execute_set_remote_share_suspended(
    registry: Arc<ShareRootsRegistry>,
    input: SetRemoteShareSuspendedInput,
) -> Result<OperationResult, EngineError> {
    let suspended = input.suspended;
    let report = registry
        .update_doc(move |doc| doc.suspended = suspended)
        .await
        .map_err(map_store_error)?;
    Ok(OperationResult::RemoteShareReconciled(reconcile_summary(
        report,
    )))
}

// ── peer 侧浏览 ──────────────────────────────────────────────────────

/// `QueryPeerShareState`：对端 `Hello.state` 的稳定枚举。
pub async fn execute_query_peer_share_state(
    client: Arc<RemoteShareClient>,
    input: PeerShareRequest,
) -> Result<OperationResult, EngineError> {
    let state = client
        .hello(&peer_id(&input.peer_id))
        .await
        .map_err(map_share_error)?;
    let state = match state {
        ShareAvailability::Ok => PeerShareState::Ok,
        ShareAvailability::Locked => PeerShareState::Locked,
        ShareAvailability::Unsupported => PeerShareState::Unsupported,
        ShareAvailability::Suspended => PeerShareState::Suspended,
    };
    Ok(OperationResult::PeerShareState(state))
}

/// `ListPeerShareRoots`：对端对本机可见的授权根（不含 holder 本地路径）。
pub async fn execute_list_peer_share_roots(
    client: Arc<RemoteShareClient>,
    input: PeerShareRequest,
) -> Result<OperationResult, EngineError> {
    let roots = client
        .list_roots(&peer_id(&input.peer_id))
        .await
        .map_err(map_share_error)?;
    Ok(OperationResult::PeerShareRoots(
        roots
            .iter()
            .map(|root| PeerShareRootSummary {
                id: root.id.0.to_string(),
                label: root.label.clone(),
                read: root.grants.read,
                write: root.grants.write,
                delete: root.grants.delete,
                enabled: root.enabled,
            })
            .collect(),
    ))
}

/// `ListPeerShareDirectory`：根内 `rel` 目录的一页。
pub async fn execute_list_peer_share_directory(
    client: Arc<RemoteShareClient>,
    input: PeerShareListInput,
) -> Result<OperationResult, EngineError> {
    let page = client
        .list(
            &peer_id(&input.peer_id),
            parse_root_id(&input.root_id)?,
            &input.rel,
            input.after.as_deref(),
            input.limit,
        )
        .await
        .map_err(map_share_error)?;
    Ok(OperationResult::PeerShareDirectory(
        PeerShareDirectoryPage {
            entries: page
                .entries
                .iter()
                .map(|entry| PeerShareEntrySummary {
                    name: entry.name.clone(),
                    is_dir: entry.is_dir,
                    is_symlink: entry.is_symlink,
                    size_bytes: entry.size_bytes,
                    modified_at_ms: entry.modified_at_ms,
                })
                .collect(),
            truncated: page.next_after.is_some(),
            cursor: page.next_after,
        },
    ))
}

/// `StatPeerShareEntry`：单条目元数据。
pub async fn execute_stat_peer_share_entry(
    client: Arc<RemoteShareClient>,
    input: PeerShareRelInput,
) -> Result<OperationResult, EngineError> {
    let entry = client
        .stat(
            &peer_id(&input.peer_id),
            parse_root_id(&input.root_id)?,
            &input.rel,
        )
        .await
        .map_err(map_share_error)?;
    Ok(OperationResult::PeerShareEntry(PeerShareEntrySummary {
        name: entry.name,
        is_dir: entry.is_dir,
        is_symlink: entry.is_symlink,
        size_bytes: entry.size_bytes,
        modified_at_ms: entry.modified_at_ms,
    }))
}

/// `ListPeerShareTrash`：对端根的回收目录分页。
pub async fn execute_list_peer_share_trash(
    client: Arc<RemoteShareClient>,
    input: PeerShareTrashListInput,
) -> Result<OperationResult, EngineError> {
    let page = client
        .list_trash(
            &peer_id(&input.peer_id),
            parse_root_id(&input.root_id)?,
            input.after.as_deref(),
            input.limit,
        )
        .await
        .map_err(map_share_error)?;
    Ok(OperationResult::PeerShareTrash(PeerShareTrashPage {
        entries: page
            .entries
            .iter()
            .map(|entry| PeerShareTrashEntrySummary {
                trash_id: entry.trash_id.clone(),
                original_rel: entry.original_rel.clone(),
                deleted_at_ms: entry.deleted_at_ms,
                is_dir: entry.is_dir,
                size_bytes: entry.size_bytes,
            })
            .collect(),
        truncated: page.next_after.is_some(),
        cursor: page.next_after,
    }))
}

/// `MutatePeerShare`：mk/rename/delete/copy/restore/empty-trash 的派发；
/// `Delete` 回 `trash_id`，其余纯确认。
pub async fn execute_mutate_peer_share(
    client: Arc<RemoteShareClient>,
    input: MutatePeerShareInput,
) -> Result<OperationResult, EngineError> {
    let peer = peer_id(&input.peer_id);
    let root = parse_root_id(&input.root_id)?;
    let outcome = match &input.action {
        PeerShareAction::Mkdir { rel } => client
            .mkdir(&peer, root, rel)
            .await
            .map(|_| PeerShareMutationOutcome::Ack),
        PeerShareAction::Rename { from, to } => client
            .rename(&peer, root, from, to)
            .await
            .map(|_| PeerShareMutationOutcome::Ack),
        PeerShareAction::Delete { rel } => client
            .delete(&peer, root, rel)
            .await
            .map(|trash_id| PeerShareMutationOutcome::Deleted { trash_id }),
        PeerShareAction::CopyWithin { from, to } => client
            .copy_within(&peer, root, from, to)
            .await
            .map(|_| PeerShareMutationOutcome::Ack),
        PeerShareAction::Restore { trash_id, to } => client
            .restore(&peer, root, trash_id, to)
            .await
            .map(|_| PeerShareMutationOutcome::Ack),
        PeerShareAction::EmptyTrash => client
            .empty_trash(&peer, root)
            .await
            .map(|_| PeerShareMutationOutcome::Ack),
    }
    .map_err(map_share_error)?;
    Ok(OperationResult::PeerShareMutated(outcome))
}

// ── 传输 ─────────────────────────────────────────────────────────────

/// `UploadPeerShare`：同步承担完整上传生命周期（枚举 → 发布+签票 → 分片
/// stage → commit → 租约释放），取消经 `CancelPeerShareTransfer` 生效。
/// `sources` 的 handle 即宿主文件系统路径。
pub async fn execute_upload_peer_share(
    client: Arc<RemoteShareClient>,
    input: UploadPeerShareInput,
) -> Result<OperationResult, EngineError> {
    let transfer_id = parse_transfer_id(&input.transfer_id)?;
    let sources: Vec<ShareUploadSource> = input
        .sources
        .iter()
        .map(|handle| ShareUploadSource {
            local: PathBuf::from(handle.as_str()),
        })
        .collect();
    let report = client
        .upload(
            &peer_id(&input.peer_id),
            parse_root_id(&input.root_id)?,
            &input.dest_dir,
            transfer_id,
            &sources,
        )
        .await
        .map_err(map_outbound_error)?;
    Ok(OperationResult::PeerShareUploaded(PeerShareUploadSummary {
        transfer_id: report.transfer_id.as_uuid_string(),
        files: report.files as u64,
        dirs: report.dirs as u64,
        skipped: report.skipped as u64,
        total_bytes: report.total_bytes,
    }))
}

/// `DownloadPeerShare`：同步承担导出票据 → 拉取落盘的生命周期。
pub async fn execute_download_peer_share(
    client: Arc<RemoteShareClient>,
    input: DownloadPeerShareInput,
) -> Result<OperationResult, EngineError> {
    let transfer_id = parse_transfer_id(&input.transfer_id)?;
    let target = PathBuf::from(input.target.as_str());
    let report = client
        .download(
            &peer_id(&input.peer_id),
            parse_root_id(&input.root_id)?,
            &input.rel,
            transfer_id,
            &target,
        )
        .await
        .map_err(map_outbound_error)?;
    Ok(OperationResult::PeerShareDownloaded(
        PeerShareDownloadSummary {
            transfer_id: report.transfer_id.as_uuid_string(),
            size_bytes: report.size_bytes,
        },
    ))
}

/// `CancelPeerShareTransfer`：按 `transfer_id` 寻址在途传输。
pub async fn execute_cancel_peer_share_transfer(
    client: Arc<RemoteShareClient>,
    input: CancelPeerShareTransferInput,
) -> Result<OperationResult, EngineError> {
    let outcome = client
        .cancel_transfer(parse_transfer_id(&input.transfer_id)?)
        .await;
    let outcome = match outcome {
        ShareTransferCancelOutcome::Cancelled => PeerShareTransferCancelOutcome::Cancelled,
        ShareTransferCancelOutcome::NotInflight => PeerShareTransferCancelOutcome::NotInflight,
        ShareTransferCancelOutcome::TooLate => PeerShareTransferCancelOutcome::TooLate,
    };
    Ok(OperationResult::PeerShareTransferCancellation(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytes::Bytes;
    use uc_application::facade::remote_share::RemoteShareClientDeps;
    use uc_core::ports::blob::{
        BlobDigest, BlobError, BlobProgressSink, BlobTicket, BlobTransferPort, TagReason,
    };
    use uc_core::ports::remote_share::{
        ConfineError, ConfinedDirEntry, ConfinedMetadata, ConfinedTarget, ConfinedTrashPage,
        ConflictPolicy, RemoteShareClientPort, ShareConfinementPort, ShareDirectoryEntry,
        ShareDirectoryPage, ShareExportOutcome, ShareRootDescriptor, ShareStageEntry,
        ShareStageOutcome, ShareStagedEntry, ShareTrashEntry, ShareTrashPage, SharedRootStoreError,
        SharedRootStorePort,
    };
    use uc_core::ports::remote_share::{
        RemoteShareClientError as ClientError, ShareClientDeny as Deny,
    };

    type StubFail = fn() -> ClientError;

    fn take<T: Clone>(slot: &Mutex<Result<T, StubFail>>) -> Result<T, ClientError> {
        // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
        match &*slot.lock().expect("slot") {
            Ok(value) => Ok(value.clone()),
            Err(fail) => Err(fail()),
        }
    }

    /// 剧本化 peer 应答桩：Ok 值按克隆回放，Err 以工厂函数重建（错误不可 Clone）。
    /// 未写剧本的动词返回 `UnexpectedReply`（不假成功）；单值动词共用
    /// `unit` 槽，由 `calls` 记录实际动词。
    struct ScriptedShare {
        hello: Mutex<Result<ShareAvailability, StubFail>>,
        roots: Mutex<Result<Vec<ShareRootDescriptor>, StubFail>>,
        page: Mutex<Result<ShareDirectoryPage, StubFail>>,
        entry: Mutex<Result<ShareDirectoryEntry, StubFail>>,
        trash: Mutex<Result<ShareTrashPage, StubFail>>,
        delete_result: Mutex<Result<String, StubFail>>,
        stage: Mutex<Result<ShareStageOutcome, StubFail>>,
        export: Mutex<Result<ShareExportOutcome, StubFail>>,
        unit: Mutex<Result<(), StubFail>>,
        calls: Mutex<Vec<&'static str>>,
    }

    fn unscripted() -> ClientError {
        ClientError::UnexpectedReply
    }

    impl Default for ScriptedShare {
        fn default() -> Self {
            Self {
                hello: Mutex::new(Err(unscripted)),
                roots: Mutex::new(Err(unscripted)),
                page: Mutex::new(Err(unscripted)),
                entry: Mutex::new(Err(unscripted)),
                trash: Mutex::new(Err(unscripted)),
                delete_result: Mutex::new(Err(unscripted)),
                stage: Mutex::new(Err(unscripted)),
                export: Mutex::new(Err(unscripted)),
                unit: Mutex::new(Err(unscripted)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ScriptedShare {
        fn script<T: Clone>(slot: &Mutex<Result<T, StubFail>>, value: Result<T, StubFail>) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            *slot.lock().expect("slot") = value;
        }
        fn called(&self, verb: &'static str) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.calls.lock().expect("calls").push(verb);
        }
        fn calls(&self) -> Vec<&'static str> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.calls.lock().expect("calls").clone()
        }
    }

    #[async_trait]
    impl RemoteShareClientPort for ScriptedShare {
        async fn hello(&self, _peer: &DeviceId) -> Result<ShareAvailability, ClientError> {
            self.called("hello");
            take(&self.hello)
        }
        async fn list_roots(
            &self,
            _peer: &DeviceId,
        ) -> Result<Vec<ShareRootDescriptor>, ClientError> {
            self.called("list_roots");
            take(&self.roots)
        }
        async fn list(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareDirectoryPage, ClientError> {
            self.called("list");
            take(&self.page)
        }
        async fn stat(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareDirectoryEntry, ClientError> {
            self.called("stat");
            take(&self.entry)
        }
        async fn mkdir(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<(), ClientError> {
            self.called("mkdir");
            take(&self.unit)
        }
        async fn rename(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), ClientError> {
            self.called("rename");
            take(&self.unit)
        }
        async fn delete(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<String, ClientError> {
            self.called("delete");
            take(&self.delete_result)
        }
        async fn list_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ShareTrashPage, ClientError> {
            self.called("list_trash");
            take(&self.trash)
        }
        async fn restore(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _trash_id: &str,
            _to: &str,
        ) -> Result<(), ClientError> {
            self.called("restore");
            take(&self.unit)
        }
        async fn empty_trash(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
        ) -> Result<(), ClientError> {
            self.called("empty_trash");
            take(&self.unit)
        }
        async fn copy_within(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _from: &str,
            _to: &str,
        ) -> Result<(), ClientError> {
            self.called("copy_within");
            take(&self.unit)
        }
        async fn stage_upload(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _dir: &str,
            _entries: &[ShareStageEntry],
            _transfer_id: ShareTransferId,
        ) -> Result<ShareStageOutcome, ClientError> {
            self.called("stage_upload");
            take(&self.stage)
        }
        async fn commit_upload(
            &self,
            _peer: &DeviceId,
            _staging_ids: &[String],
        ) -> Result<(), ClientError> {
            self.called("commit_upload");
            take(&self.unit)
        }
        async fn abort_upload(
            &self,
            _peer: &DeviceId,
            _staging_ids: &[String],
        ) -> Result<(), ClientError> {
            self.called("abort_upload");
            take(&self.unit)
        }
        async fn export(
            &self,
            _peer: &DeviceId,
            _root: ShareRootId,
            _rel: &str,
        ) -> Result<ShareExportOutcome, ClientError> {
            self.called("export");
            take(&self.export)
        }
    }

    /// Blob 侧桩：本模块测试不触达 blob 路径，一律内部错误（不假成功）。
    struct FailBlobs;

    fn blob_fail() -> BlobError {
        BlobError::Internal(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "stub",
        )))
    }

    #[async_trait]
    impl BlobTransferPort for FailBlobs {
        async fn publish(&self, _c: Bytes, _r: TagReason) -> Result<BlobDigest, BlobError> {
            Err(blob_fail())
        }
        async fn publish_path(&self, _p: &Path, _r: TagReason) -> Result<BlobDigest, BlobError> {
            Err(blob_fail())
        }
        async fn publish_reader(
            &self,
            _s: std::fs::File,
            _r: TagReason,
        ) -> Result<BlobDigest, BlobError> {
            Err(blob_fail())
        }
        async fn issue_ticket(&self, _d: &BlobDigest) -> Result<BlobTicket, BlobError> {
            Err(blob_fail())
        }
        async fn fetch(
            &self,
            _t: &BlobTicket,
            _p: Option<&dyn BlobProgressSink>,
        ) -> Result<Bytes, BlobError> {
            Err(blob_fail())
        }
        async fn fetch_to_path(
            &self,
            _t: &BlobTicket,
            _p: &Path,
            _s: Option<&dyn BlobProgressSink>,
        ) -> Result<BlobDigest, BlobError> {
            Err(blob_fail())
        }
        async fn shutdown_inflight_fetch(&self, _t: &BlobTicket) -> Result<(), BlobError> {
            Err(blob_fail())
        }
        async fn has(&self, _d: &BlobDigest) -> Result<bool, BlobError> {
            Err(blob_fail())
        }
        async fn tag(&self, _d: &BlobDigest, _r: TagReason) -> Result<(), BlobError> {
            Err(blob_fail())
        }
        async fn untag(&self, _r: TagReason) -> Result<(), BlobError> {
            Err(blob_fail())
        }
        fn digest_of(&self, _t: &BlobTicket) -> Result<BlobDigest, BlobError> {
            Err(blob_fail())
        }
    }

    struct StubStore {
        doc: Mutex<ShareStoreDoc>,
        fail_load: AtomicBool,
        fail_load_io: AtomicBool,
        saves: AtomicUsize,
    }

    #[async_trait]
    impl SharedRootStorePort for StubStore {
        async fn load(&self) -> Result<ShareStoreDoc, SharedRootStoreError> {
            if self.fail_load.load(Ordering::Relaxed) {
                return Err(SharedRootStoreError::NotUnlocked);
            }
            if self.fail_load_io.load(Ordering::Relaxed) {
                return Err(SharedRootStoreError::Io {
                    source: std::io::Error::new(std::io::ErrorKind::Other, "disk gone"),
                });
            }
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            Ok(self.doc.lock().expect("doc").clone())
        }
        async fn save(&self, doc: &ShareStoreDoc) -> Result<(), SharedRootStoreError> {
            self.saves.fetch_add(1, Ordering::Relaxed);
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            *self.doc.lock().expect("doc") = doc.clone();
            Ok(())
        }
    }

    /// 约束桩：登记/撤销记入集合，其余动词固定 `Denied`（本测试不触达）。
    #[derive(Default)]
    struct StubConfinement {
        registered: Mutex<HashSet<ShareRootId>>,
    }

    fn deny<T>() -> Result<T, ConfineError> {
        Err(ConfineError::Denied)
    }

    #[async_trait]
    impl ShareConfinementPort for StubConfinement {
        async fn register_root(&self, root: ShareRootId, _p: &Path) -> Result<(), ConfineError> {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("reg").insert(root);
            Ok(())
        }
        async fn unregister_root(&self, root: ShareRootId) {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("reg").remove(&root);
        }
        async fn is_registered(&self, root: ShareRootId) -> bool {
            // discarded-source[lock-poisoned]: `PoisonError`: test-only stub.
            self.registered.lock().expect("reg").contains(&root)
        }
        async fn resolve(&self, _r: ShareRootId, _c: &str) -> Result<ConfinedTarget, ConfineError> {
            deny()
        }
        async fn resolve_root(&self, _r: ShareRootId) -> Result<ConfinedTarget, ConfineError> {
            deny()
        }
        async fn target_metadata(
            &self,
            _t: &ConfinedTarget,
        ) -> Result<ConfinedMetadata, ConfineError> {
            deny()
        }
        async fn target_child_metadata(
            &self,
            _t: &ConfinedTarget,
            _n: &str,
        ) -> Result<ConfinedMetadata, ConfineError> {
            deny()
        }
        async fn target_read_dir(
            &self,
            _t: &ConfinedTarget,
        ) -> Result<Vec<ConfinedDirEntry>, ConfineError> {
            deny()
        }
        async fn target_open_read(
            &self,
            _t: &ConfinedTarget,
        ) -> Result<std::fs::File, ConfineError> {
            deny()
        }
        async fn target_create_dir(&self, _t: &ConfinedTarget) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_rename(
            &self,
            _f: &ConfinedTarget,
            _t: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_copy_into(
            &self,
            _f: &ConfinedTarget,
            _t: &ConfinedTarget,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn target_move_to_trash(&self, _t: &ConfinedTarget) -> Result<String, ConfineError> {
            deny()
        }
        async fn list_trash(
            &self,
            _r: ShareRootId,
            _a: Option<&str>,
            _l: u32,
        ) -> Result<ConfinedTrashPage, ConfineError> {
            deny()
        }
        async fn restore_from_trash(
            &self,
            _r: ShareRootId,
            _t: &str,
            _to: &ConfinedTarget,
        ) -> Result<String, ConfineError> {
            deny()
        }
        async fn empty_trash(&self, _r: ShareRootId) -> Result<(), ConfineError> {
            deny()
        }
        async fn create_staging(&self, _r: ShareRootId) -> Result<String, ConfineError> {
            deny()
        }
        async fn staging_entry_path(
            &self,
            _r: ShareRootId,
            _s: &str,
            _c: &str,
            _d: bool,
        ) -> Result<PathBuf, ConfineError> {
            deny()
        }
        async fn commit_staging(
            &self,
            _r: ShareRootId,
            _s: &str,
            _d: &ConfinedTarget,
            _e: &[ShareStagedEntry],
            _p: ConflictPolicy,
        ) -> Result<(), ConfineError> {
            deny()
        }
        async fn abort_staging(&self, _r: ShareRootId, _s: &str) -> Result<(), ConfineError> {
            deny()
        }
    }

    fn registry_with(doc: ShareStoreDoc) -> Arc<ShareRootsRegistry> {
        Arc::new(ShareRootsRegistry::new(
            Arc::new(StubStore {
                doc: Mutex::new(doc),
                fail_load: AtomicBool::new(false),
                fail_load_io: AtomicBool::new(false),
                saves: AtomicUsize::new(0),
            }),
            Arc::new(StubConfinement::default()),
        ))
    }

    fn client_with(share: Arc<ScriptedShare>) -> Arc<RemoteShareClient> {
        Arc::new(RemoteShareClient::new(RemoteShareClientDeps {
            client: share,
            blobs: Arc::new(FailBlobs),
            events: None,
        }))
    }

    fn root_id() -> ShareRootId {
        ShareRootId::from_wire_bytes([7; 16])
    }

    fn peer() -> PeerShareRequest {
        PeerShareRequest {
            peer_id: "peer-a".to_owned(),
        }
    }

    // ── 错误映射 ─────────────────────────────────────────────────────

    /// §12 全 17 码 → §9.1 数字块逐条钉死。
    #[test]
    fn deny_codes_cover_all_stable_wire_denies() {
        use EngineErrorCategory as C;
        let table: [(Deny, u32, C, bool); 17] = [
            (Deny::Locked, 2101, C::InvalidState, false),
            (Deny::Unsupported, 2102, C::Unavailable, false),
            (Deny::UnsupportedRequest, 2103, C::Internal, false),
            (Deny::Suspended, 2104, C::InvalidState, false),
            (Deny::Revoked, 2105, C::Unauthorized, false),
            (Deny::Denied, 2106, C::Unauthorized, false),
            (Deny::ReservedName, 2107, C::InvalidInput, false),
            (Deny::NotFound, 2108, C::NotFound, false),
            (Deny::Conflict, 2109, C::Conflict, false),
            (Deny::RootGone, 2110, C::NotFound, false),
            (Deny::Quota, 2111, C::Unavailable, false),
            (Deny::TooLarge, 2112, C::InvalidInput, false),
            (Deny::TooManyEntries, 2113, C::InvalidInput, false),
            (Deny::Io, 2114, C::Unavailable, true),
            (Deny::Cancelled, 2115, C::Cancelled, false),
            (Deny::TooLate, 2116, C::Conflict, false),
            (Deny::Interrupted, 2117, C::Unavailable, true),
        ];
        for (deny, code, category, retryable) in table {
            let error = deny_error(deny);
            assert_eq!(error.code(), code, "{deny:?}");
            assert_eq!(error.category(), category, "{deny:?}");
            assert_eq!(error.is_retryable(), retryable, "{deny:?}");
        }
    }

    #[test]
    fn share_error_maps_transport_classes() {
        let error = map_share_error(ClientError::Unreachable);
        assert_eq!(error.code(), PEER_SHARE_UNAVAILABLE_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Unavailable);
        assert!(error.is_retryable());

        let error = map_share_error(ClientError::UnexpectedReply);
        assert_eq!(error.code(), PEER_SHARE_FAILED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Internal);

        let error = map_share_error(ClientError::Io(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "x",
        ))));
        assert_eq!(error.code(), PEER_SHARE_UNAVAILABLE_CODE);
        assert!(error.is_retryable());
    }

    #[test]
    fn outbound_error_maps_terminal_classes() {
        let error = map_outbound_error(ShareOutboundError::Cancelled);
        assert_eq!(error.code(), PEER_SHARE_CANCELLED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Cancelled);

        let error = map_outbound_error(ShareOutboundError::Empty);
        assert_eq!(error.category(), EngineErrorCategory::InvalidInput);

        let error = map_outbound_error(ShareOutboundError::Remote(ClientError::Refused(
            Deny::NotFound,
        )));
        assert_eq!(error.code(), PEER_SHARE_NOT_FOUND_CODE);
        assert_eq!(error.category(), EngineErrorCategory::NotFound);
    }

    #[test]
    fn malformed_ids_are_invalid_input() {
        assert!(parse_root_id("not-a-uuid").is_err());
        assert!(parse_transfer_id("not-a-uuid").is_err());
        assert!(parse_root_id(&root_id().0.to_string()).is_ok());
        let tid = ShareTransferId::from_bytes([9; 16]);
        assert!(parse_transfer_id(&tid.as_uuid_string()).is_ok());
    }

    // ── 本机共享管理 ─────────────────────────────────────────────────

    #[tokio::test]
    async fn query_state_lists_root_summaries() {
        let mut doc = ShareStoreDoc::default();
        doc.roots.push(ShareRoot {
            id: root_id(),
            added_at_ms: 42,
            path: "/home/u/share".to_owned(),
            label: "shared".to_owned(),
            grants: ShareGrants {
                read: true,
                write: true,
                delete: false,
            },
            enabled: true,
        });
        let result = execute_query_remote_share_state(registry_with(doc))
            .await
            .expect("query state");
        let OperationResult::RemoteShareState(state) = result else {
            panic!("unexpected result shape");
        };
        assert!(!state.suspended);
        assert_eq!(state.roots.len(), 1);
        let root = &state.roots[0];
        assert_eq!(root.id, root_id().0.to_string());
        assert_eq!(root.path, PathBuf::from("/home/u/share"));
        assert_eq!(root.label, "shared");
        assert!(root.read && root.write && !root.delete && root.enabled);
    }

    #[tokio::test]
    async fn query_state_locked_maps_to_locked_code() {
        let store = Arc::new(StubStore {
            doc: Mutex::new(ShareStoreDoc::default()),
            fail_load: AtomicBool::new(true),
            fail_load_io: AtomicBool::new(false),
            saves: AtomicUsize::new(0),
        });
        let registry = Arc::new(ShareRootsRegistry::new(
            store,
            Arc::new(StubConfinement::default()),
        ));
        let error = execute_query_remote_share_state(registry)
            .await
            .expect_err("locked store must surface");
        assert_eq!(error.code(), REMOTE_SHARE_LOCKED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Unavailable);
    }

    #[tokio::test]
    async fn query_state_store_io_maps_to_failed_code() {
        let store = Arc::new(StubStore {
            doc: Mutex::new(ShareStoreDoc::default()),
            fail_load: AtomicBool::new(false),
            fail_load_io: AtomicBool::new(true),
            saves: AtomicUsize::new(0),
        });
        let registry = Arc::new(ShareRootsRegistry::new(
            store,
            Arc::new(StubConfinement::default()),
        ));
        let error = execute_query_remote_share_state(registry)
            .await
            .expect_err("io failure must surface");
        assert_eq!(error.code(), REMOTE_SHARE_STATE_FAILED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Internal);
    }

    #[tokio::test]
    async fn replace_roots_assigns_ids_and_preserves_added_at() {
        let mut doc = ShareStoreDoc::default();
        doc.roots.push(ShareRoot {
            id: root_id(),
            added_at_ms: 100,
            path: "/old".to_owned(),
            label: "old".to_owned(),
            grants: ShareGrants::default(),
            enabled: true,
        });
        let registry = registry_with(doc);
        let kept_id = root_id().0.to_string();
        let result = execute_replace_remote_share_roots(
            registry.clone(),
            ReplaceRemoteShareRootsInput {
                roots: vec![
                    crate::RemoteShareRootInput {
                        id: Some(kept_id.clone()),
                        path: PathBuf::from("/new/path"),
                        label: "kept".to_owned(),
                        read: true,
                        write: false,
                        delete: false,
                        enabled: true,
                    },
                    crate::RemoteShareRootInput {
                        id: None,
                        path: PathBuf::from("/fresh"),
                        label: "fresh".to_owned(),
                        read: true,
                        write: false,
                        delete: false,
                        enabled: false,
                    },
                ],
            },
            999,
        )
        .await
        .expect("replace roots");
        let OperationResult::RemoteShareReconciled(summary) = result else {
            panic!("unexpected result shape");
        };
        // 根 1 enabled → 登记成功；根 2 disabled → 撤销侧（本就未登记，不计数）。
        assert_eq!(summary.registered, 1);
        let doc = registry.current_doc().await.expect("doc");
        assert_eq!(doc.roots.len(), 2);
        let kept = &doc.roots[0];
        assert_eq!(kept.id.0.to_string(), kept_id);
        assert_eq!(kept.added_at_ms, 100, "existing root keeps its added_at_ms");
        assert_eq!(kept.path, "/new/path");
        let fresh = &doc.roots[1];
        assert_eq!(fresh.added_at_ms, 999, "new root takes the clock");
        assert_ne!(fresh.id, kept.id, "missing id gets a fresh uuid");
    }

    #[tokio::test]
    async fn set_suspended_keeps_roots_and_reconciles_registration() {
        let mut doc = ShareStoreDoc::default();
        doc.roots.push(ShareRoot {
            id: root_id(),
            added_at_ms: 1,
            path: "/share".to_owned(),
            label: "s".to_owned(),
            grants: ShareGrants::default(),
            enabled: true,
        });
        let registry = registry_with(doc);
        execute_set_remote_share_suspended(
            registry.clone(),
            SetRemoteShareSuspendedInput { suspended: true },
        )
        .await
        .expect("suspend");
        let doc = registry.current_doc().await.expect("doc");
        assert!(doc.suspended);
        assert_eq!(doc.roots.len(), 1, "suspend keeps the root list");
    }

    // ── peer 侧动词 ──────────────────────────────────────────────────

    #[tokio::test]
    async fn peer_state_maps_availability() {
        let share = Arc::new(ScriptedShare::default());
        ScriptedShare::script(&share.hello, Ok(ShareAvailability::Suspended));
        let result = execute_query_peer_share_state(client_with(share.clone()), peer())
            .await
            .expect("state");
        assert_eq!(
            result,
            OperationResult::PeerShareState(PeerShareState::Suspended)
        );
        assert_eq!(share.calls(), vec!["hello"]);
    }

    #[tokio::test]
    async fn list_roots_surfaces_deny_code() {
        let share = Arc::new(ScriptedShare::default());
        fn refused() -> ClientError {
            ClientError::Refused(Deny::Suspended)
        }
        ScriptedShare::script(&share.roots, Err(refused as StubFail));
        let error = execute_list_peer_share_roots(client_with(share), peer())
            .await
            .expect_err("deny must map");
        assert_eq!(error.code(), PEER_SHARE_SUSPENDED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::InvalidState);
    }

    #[tokio::test]
    async fn list_directory_maps_page_and_cursor() {
        let share = Arc::new(ScriptedShare::default());
        ScriptedShare::script(
            &share.page,
            Ok(ShareDirectoryPage {
                entries: vec![ShareDirectoryEntry {
                    name: "src".to_owned(),
                    is_dir: true,
                    is_symlink: false,
                    size_bytes: 0,
                    modified_at_ms: 7,
                }],
                next_after: Some("src".to_owned()),
            }),
        );
        let result = execute_list_peer_share_directory(
            client_with(share),
            PeerShareListInput {
                peer_id: "peer-a".to_owned(),
                root_id: root_id().0.to_string(),
                rel: String::new(),
                after: None,
                limit: 50,
            },
        )
        .await
        .expect("list");
        let OperationResult::PeerShareDirectory(page) = result else {
            panic!("unexpected result shape");
        };
        assert!(page.truncated);
        assert_eq!(page.cursor.as_deref(), Some("src"));
        assert_eq!(page.entries.len(), 1);
        assert!(page.entries[0].is_dir);
        assert_eq!(page.entries[0].modified_at_ms, 7);
    }

    #[tokio::test]
    async fn list_trash_maps_page() {
        let share = Arc::new(ScriptedShare::default());
        ScriptedShare::script(
            &share.trash,
            Ok(ShareTrashPage {
                entries: vec![ShareTrashEntry {
                    trash_id: "t-1".to_owned(),
                    original_rel: "old/junk.txt".to_owned(),
                    deleted_at_ms: 55,
                    is_dir: false,
                    size_bytes: 12,
                }],
                next_after: None,
            }),
        );
        let result = execute_list_peer_share_trash(
            client_with(share),
            PeerShareTrashListInput {
                peer_id: "peer-a".to_owned(),
                root_id: root_id().0.to_string(),
                after: None,
                limit: 20,
            },
        )
        .await
        .expect("trash page");
        let OperationResult::PeerShareTrash(page) = result else {
            panic!("unexpected result shape");
        };
        assert!(!page.truncated);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].trash_id, "t-1");
        assert_eq!(page.entries[0].deleted_at_ms, 55);
    }

    #[tokio::test]
    async fn mutate_delete_returns_trash_id() {
        let share = Arc::new(ScriptedShare::default());
        ScriptedShare::script(&share.delete_result, Ok("trash-1".to_owned()));
        let result = execute_mutate_peer_share(
            client_with(share.clone()),
            MutatePeerShareInput {
                peer_id: "peer-a".to_owned(),
                root_id: root_id().0.to_string(),
                action: PeerShareAction::Delete {
                    rel: "junk.txt".to_owned(),
                },
            },
        )
        .await
        .expect("delete");
        assert_eq!(
            result,
            OperationResult::PeerShareMutated(PeerShareMutationOutcome::Deleted {
                trash_id: "trash-1".to_owned()
            })
        );
        assert_eq!(share.calls(), vec!["delete"]);
    }

    #[tokio::test]
    async fn mutate_denied_maps_to_unauthorized() {
        let share = Arc::new(ScriptedShare::default());
        fn refused() -> ClientError {
            ClientError::Refused(Deny::Denied)
        }
        ScriptedShare::script(&share.unit, Err(refused as StubFail));
        let error = execute_mutate_peer_share(
            client_with(share.clone()),
            MutatePeerShareInput {
                peer_id: "peer-a".to_owned(),
                root_id: root_id().0.to_string(),
                action: PeerShareAction::Mkdir {
                    rel: "new".to_owned(),
                },
            },
        )
        .await
        .expect_err("deny must map");
        assert_eq!(error.code(), PEER_SHARE_DENIED_CODE);
        assert_eq!(error.category(), EngineErrorCategory::Unauthorized);
        assert_eq!(share.calls(), vec!["mkdir"]);
    }

    #[tokio::test]
    async fn cancel_unknown_transfer_reports_not_inflight() {
        let client = client_with(Arc::new(ScriptedShare::default()));
        let result = execute_cancel_peer_share_transfer(
            client,
            CancelPeerShareTransferInput {
                transfer_id: ShareTransferId::from_bytes([3; 16]).as_uuid_string(),
            },
        )
        .await
        .expect("cancel");
        assert_eq!(
            result,
            OperationResult::PeerShareTransferCancellation(
                PeerShareTransferCancelOutcome::NotInflight
            )
        );
    }

    #[tokio::test]
    async fn upload_rejects_bad_transfer_id_before_touching_peer() {
        let share = Arc::new(ScriptedShare::default());
        let error = execute_upload_peer_share(
            client_with(share.clone()),
            UploadPeerShareInput {
                peer_id: "peer-a".to_owned(),
                root_id: root_id().0.to_string(),
                dest_dir: String::new(),
                transfer_id: "garbage".to_owned(),
                sources: Vec::new(),
            },
        )
        .await
        .expect_err("bad transfer id");
        assert_eq!(error.category(), EngineErrorCategory::InvalidInput);
        assert!(share.calls().is_empty(), "no peer traffic on bad input");
    }
}
