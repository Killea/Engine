//! 线上字节的回归向量。
//!
//! 每个向量固定一个 ALPN 上的一种帧的完整字节。任何编码字节的变化都会让对应
//! 断言失败：这类变化会破坏与已发布版本互通，必须改版本号或 ALPN，而不是改向量。

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uc_core::file_transfer::OutboundProgressStatus;
use uc_core::ports::ClipboardHeader;
use uc_sync_protocol::active_clipboard_pull::{self, PullResponse};
use uc_sync_protocol::active_clipboard_state::{self, ActiveClipboardWireMessage};
use uc_sync_protocol::clipboard;
use uc_sync_protocol::membership_branch_recovery::{self, MembershipBranchRecoveryWireMessage};
use uc_sync_protocol::space_admission::{self, FrameKind, InitialHelloV2, AUTH_FRAME_LIMIT};
use uc_sync_protocol::trace_context::WireTraceContext;
use uc_sync_protocol::transfer_progress::{self, ProgressFrame};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_vector(name: &str, actual: &[u8], expected_hex: &str) {
    assert_eq!(hex(actual), expected_hex, "wire bytes changed: {name}");
}

async fn drain(mut reader: tokio::io::DuplexStream) -> Vec<u8> {
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .await
        .expect("read frame bytes");
    out
}

fn clipboard_header() -> ClipboardHeader {
    ClipboardHeader {
        version: ClipboardHeader::CURRENT_VERSION,
        snapshot_hash: "a".repeat(64),
        captured_at_ms: 1_700_000_000_000,
        origin_device_id: "dev-alpha".to_string(),
        origin_device_name: "Alpha Laptop".to_string(),
        payload_version: 3,
    }
}

#[tokio::test]
async fn clipboard_applied_frame_without_trace_context() {
    let (mut tx, rx) = tokio::io::duplex(64 * 1024);
    clipboard::write_frame(
        &mut tx,
        &clipboard_header(),
        None,
        &Bytes::from_static(b"cipher"),
    )
    .await
    .expect("write");
    drop(tx);
    assert_vector("clipboard-applied/1 frame", &drain(rx).await, "c1000000655543543102406161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616180a0abfef962096465762d616c7068610c416c706861204c6170746f70030000000006636970686572");
}

#[tokio::test]
async fn clipboard_applied_header_with_trace_context() {
    let context = WireTraceContext {
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned(),
    };
    let bytes = clipboard::encode_header(&clipboard_header(), Some(context)).expect("encode");
    assert_vector("clipboard-applied/1 header + trace", &bytes, "5543543102406161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616180a0abfef962096465762d616c7068610c416c706861204c6170746f7003013730302d34626639326633353737623334646136613363653932396430653065343733362d303066303637616130626139303262372d3031");
}

#[tokio::test]
async fn active_clipboard_state_frame() {
    let (mut tx, rx) = tokio::io::duplex(4096);
    active_clipboard_state::write_frame(
        &mut tx,
        &ActiveClipboardWireMessage {
            snapshot_hash: format!("blake3v1:{}", "b".repeat(64)),
            entry_id: "entry-1".to_owned(),
            activated_at_ms: 1_700_000_000_123,
            activated_by: "dev-alpha".to_owned(),
        },
    )
    .await
    .expect("write");
    drop(tx);
    assert_vector("active-clipboard/0 frame", &drain(rx).await, "c3000000630149626c616b653376313a6262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626207656e7472792d31f6a1abfef962096465762d616c706861");
}

#[tokio::test]
async fn active_clipboard_pull_request_and_responses() {
    let (mut tx, rx) = tokio::io::duplex(4096);
    active_clipboard_pull::write_request(&mut tx, "blake3v1:abc")
        .await
        .expect("write");
    drop(tx);
    assert_vector(
        "active-clipboard-pull/0 request",
        &drain(rx).await,
        "c2000c626c616b653376313a616263",
    );

    for (name, response, expected) in [
        (
            "envelope",
            PullResponse::Envelope(vec![1, 2, 3]),
            "0000000003010203",
        ),
        ("not_available", PullResponse::NotAvailable, "01"),
        ("locked", PullResponse::Locked, "02"),
        ("internal", PullResponse::Internal, "03"),
    ] {
        let (mut tx, rx) = tokio::io::duplex(4096);
        active_clipboard_pull::write_response(&mut tx, &response)
            .await
            .expect("write");
        drop(tx);
        let actual = drain(rx).await;
        assert_vector(
            &format!("active-clipboard-pull/0 response {name}"),
            &actual,
            expected,
        );
    }
}

#[tokio::test]
async fn transfer_progress_frames() {
    let transfer_id =
        transfer_progress::transfer_id_to_bytes("11111111-2222-4333-8444-555555555555")
            .expect("uuid");
    let (mut tx, rx) = tokio::io::duplex(256);
    transfer_progress::write_frame(
        &mut tx,
        &ProgressFrame {
            transfer_id_bytes: transfer_id,
            bytes_transferred: 1024,
            total_bytes: Some(4096),
            status: OutboundProgressStatus::InProgress,
        },
    )
    .await
    .expect("write");
    drop(tx);
    assert_vector(
        "transfer-progress/1 in-progress",
        &drain(rx).await,
        "c2111111112222433384445555555555550000000000000400000000000000100001",
    );
}

#[tokio::test]
async fn space_admission_initial_hello_frame() {
    let (mut tx, rx) = tokio::io::duplex(4096);
    space_admission::write_typed(
        &mut tx,
        FrameKind::InitialHello,
        &InitialHelloV2 {
            protocol_version: 2,
            admission_id: [1; 32],
            invitation_id: [2; 32],
            joiner_peer_id: [3; 32],
            attempt_started_at_ms: 1_700_000_000_000,
            attempt_expires_at_ms: 1_700_000_300_000,
            ke1: vec![9, 8, 7],
        },
        AUTH_FRAME_LIMIT,
    )
    .await
    .expect("write");
    drop(tx);
    assert_vector("space-admission/1 initial hello", &drain(rx).await, "554353410101000000710201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030380a0abfef962c0efcffef96203090807");
}

#[test]
fn membership_branch_recovery_messages() {
    let rejected =
        membership_branch_recovery::encode(&MembershipBranchRecoveryWireMessage::rejected())
            .expect("encode");
    assert_vector("membership-branch-recovery/1 rejected", &rejected, "0401");
    let group_info =
        membership_branch_recovery::encode(&MembershipBranchRecoveryWireMessage::group_info(vec![
            1, 2, 3,
        ]))
        .expect("encode");
    assert_vector(
        "membership-branch-recovery/1 group info",
        &group_info,
        "010103010203",
    );
}

// ---- remote-share/1 ----------------------------------------------------------

use uc_sync_protocol::remote_share::{
    self as remote_share, DenyCode, HelloState, ShareReply, ShareRequest, WireDirectoryEntry,
    WireShareGrants, WireShareRoot, WireStageEntry, WireTrashEntry,
};

#[tokio::test]
async fn remote_share_request_frames() {
    for (name, request, expected) in [
        ("hello", ShareRequest::Hello, "5543525301010000000101"),
        ("list_roots", ShareRequest::ListRoots, "5543525301010000000102"),
        (
            "list",
            ShareRequest::List {
                root_id: [7; 16],
                path: "docs/a.txt".to_owned(),
                after: Some("b.txt".to_owned()),
                limit: 50,
            },
            "5543525301010000002403070707070707070707070707070707070a646f63732f612e7478740105622e74787432",
        ),
        (
            "stat",
            ShareRequest::Stat {
                root_id: [7; 16],
                path: "note.txt".to_owned(),
            },
            "5543525301010000001a0407070707070707070707070707070707086e6f74652e747874",
        ),
        (
            "mkdir",
            ShareRequest::Mkdir {
                root_id: [7; 16],
                path: "new/dir".to_owned(),
            },
            "554352530101000000190507070707070707070707070707070707076e65772f646972",
        ),
        (
            "rename",
            ShareRequest::Rename {
                root_id: [7; 16],
                from: "a.txt".to_owned(),
                to: "b.txt".to_owned(),
            },
            "5543525301010000001d060707070707070707070707070707070705612e74787405622e747874",
        ),
        (
            "delete",
            ShareRequest::Delete {
                root_id: [7; 16],
                path: "gone.txt".to_owned(),
            },
            "5543525301010000001a070707070707070707070707070707070708676f6e652e747874",
        ),
        (
            "list_trash",
            ShareRequest::ListTrash {
                root_id: [7; 16],
                after: None,
                limit: 20,
            },
            "5543525301010000001308070707070707070707070707070707070014",
        ),
        (
            "restore",
            ShareRequest::Restore {
                root_id: [7; 16],
                trash_id: "trash-1".to_owned(),
                to: "back/here.txt".to_owned(),
            },
            "5543525301010000002709070707070707070707070707070707070774726173682d310d6261636b2f686572652e747874",
        ),
        (
            "empty_trash",
            ShareRequest::EmptyTrash { root_id: [7; 16] },
            "554352530101000000110a07070707070707070707070707070707",
        ),
        (
            "copy_within",
            ShareRequest::CopyWithin {
                root_id: [7; 16],
                from: "a.txt".to_owned(),
                to: "dup/a.txt".to_owned(),
            },
            "554352530101000000210b0707070707070707070707070707070705612e747874096475702f612e747874",
        ),
        (
            "stage_upload",
            ShareRequest::StageUpload {
                root_id: [7; 16],
                dir: "inbox".to_owned(),
                transfer_id: [9; 16],
                entries: vec![
                    WireStageEntry {
                        rel: "sub".to_owned(),
                        is_dir: true,
                        size_bytes: 0,
                        ticket: Vec::new(),
                    },
                    WireStageEntry {
                        rel: "sub/f.bin".to_owned(),
                        is_dir: false,
                        size_bytes: 1024,
                        ticket: vec![0xaa; 4],
                    },
                ],
            },
            "554352530101000000410c0707070707070707070707070707070705696e626f78090909090909090909090909090909090203737562010000097375622f662e62696e00800804aaaaaaaa",
        ),
        (
            "commit_upload",
            ShareRequest::CommitUpload {
                staging_ids: vec!["st-1".to_owned()],
            },
            "554352530101000000070d010473742d31",
        ),
        (
            "abort_upload",
            ShareRequest::AbortUpload {
                staging_ids: vec!["st-1".to_owned(), "st-2".to_owned()],
            },
            "5543525301010000000c0e020473742d310473742d32",
        ),
        (
            "export",
            ShareRequest::Export {
                root_id: [7; 16],
                path: "out.bin".to_owned(),
            },
            "554352530101000000190f07070707070707070707070707070707076f75742e62696e",
        ),
    ] {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        remote_share::write_request(&mut tx, &request)
            .await
            .expect("write");
        drop(tx);
        assert_vector(&format!("remote-share/1 request {name}"), &drain(rx).await, expected);
    }
}

#[tokio::test]
async fn remote_share_reply_frames() {
    for (name, reply, expected) in [
        (
            "hello",
            ShareReply::Hello {
                state: HelloState::Ok,
            },
            "554352530102000000020100",
        ),
        (
            "roots",
            ShareReply::Roots {
                roots: vec![WireShareRoot {
                    id: [7; 16],
                    label: "Documents".to_owned(),
                    grants: WireShareGrants {
                        read: true,
                        write: true,
                        delete: false,
                    },
                    enabled: true,
                }],
            },
            "5543525301020000002002010707070707070707070707070707070709446f63756d656e747301010001",
        ),
        (
            "entries",
            ShareReply::Entries {
                entries: vec![WireDirectoryEntry {
                    name: "a.txt".to_owned(),
                    is_dir: false,
                    is_symlink: false,
                    size_bytes: 7,
                    modified_at_ms: 1_700_000_000_000,
                }],
                next_after: Some("a.txt".to_owned()),
            },
            "55435253010200000018030105612e74787400000780a0abfef9620105612e747874",
        ),
        (
            "entry",
            ShareReply::Entry {
                entry: WireDirectoryEntry {
                    name: "a.txt".to_owned(),
                    is_dir: false,
                    is_symlink: false,
                    size_bytes: 7,
                    modified_at_ms: 1_700_000_000_000,
                },
            },
            "554352530102000000100405612e74787400000780a0abfef962",
        ),
        ("ack", ShareReply::Ack, "5543525301020000000105"),
        (
            "staged",
            ShareReply::Staged {
                staging_id: "st-1".to_owned(),
            },
            "55435253010200000006060473742d31",
        ),
        (
            "deleted",
            ShareReply::Deleted {
                trash_id: "tr-1".to_owned(),
            },
            "55435253010200000006070474722d31",
        ),
        (
            "trash_entries",
            ShareReply::TrashEntries {
                entries: vec![WireTrashEntry {
                    trash_id: "tr-1".to_owned(),
                    original_path: "old/spot.txt".to_owned(),
                    is_dir: false,
                    size_bytes: 5,
                    deleted_at_ms: 1_700_000_000_000,
                }],
                next_after: None,
            },
            "5543525301020000001d08010474722d310c6f6c642f73706f742e747874000580a0abfef96200",
        ),
        (
            "exported",
            ShareReply::Exported {
                ticket: vec![1, 2, 3],
                size_bytes: 99,
            },
            "55435253010200000006090301020363",
        ),
        (
            "denied",
            ShareReply::Denied {
                code: DenyCode::RootGone,
            },
            "554352530102000000020a09",
        ),
    ] {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        remote_share::write_reply(&mut tx, &reply)
            .await
            .expect("write");
        drop(tx);
        assert_vector(
            &format!("remote-share/1 reply {name}"),
            &drain(rx).await,
            expected,
        );
    }
}

/// An opcode this build does not know must decode to `Unknown`, not fail —
/// spec §15's forward-compat rule.
#[tokio::test]
async fn remote_share_unknown_opcode_decodes_to_unknown() {
    // Frame: magic + version + kind=request + len + body[u32 opcode=999 varint
    // (0xE7 0x07) + ignored payload bytes].
    let frame: &[u8] = b"UCRS\x01\x01\x00\x00\x00\x04\xE7\x07\xAA\xBB";
    let (mut tx, mut rx) = tokio::io::duplex(64);
    tx.write_all(frame).await.expect("feed frame");
    drop(tx);
    match remote_share::read_request(&mut rx).await {
        Ok(ShareRequest::Unknown { opcode }) => assert_eq!(opcode, 999),
        other => panic!("expected Unknown request, got {other:?}"),
    }
}
