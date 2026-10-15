//! Remote-share serve 审计记录：每个变更/传输类入站操作一条封闭记录。
//!
//! 规格 §5.3 的审计要求：每次服务端操作记录对端、操作、根与 `blake3(rel)` 截断值、
//! 结果码。对端身份不走字段值——`peer_context` 把原始 `[u8; 32]` 挂进内存观测
//! 上下文，序列化层为其分配每 run 匿名 `peer_ref`；明文路径与对端身份一样不进
//! 记录，rel 只留 blake3 截断指纹。
//!
//! 高频只读操作（`Hello`/`ListRoots`/`List`/`Stat`/`ListTrash`）不进本记录通道，
//! 由 serve 适配器用模块级 `uc_debug!` 承载——浏览一棵目录树会产生大量 List，
//! 按记录通道计量会把审计信号淹没在浏览噪声里（与本模块 `local_work` 对
//! `WORK_ACTIVE` 门控的同一理由：只有持有业务动作的上下文才值得一条记录）。

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{connection::peer_context, emit_local, record::LocalEvent};

/// 被审计的变更/传输类操作集合：与 wire 上可变远端文件系统的请求一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteShareOp {
    Mkdir,
    Rename,
    Delete,
    Restore,
    EmptyTrash,
    CopyWithin,
    StageUpload,
    CommitUpload,
    AbortUpload,
    Export,
    Unknown,
}

/// 审计记录的结果码：与 wire `DenyCode` 同名（snake_case），独立成枚举使本
/// crate 不依赖线格式定义。`None` 即操作被正常应答。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteShareDeny {
    Locked,
    Unsupported,
    UnsupportedRequest,
    Suspended,
    Revoked,
    Denied,
    ReservedName,
    NotFound,
    Conflict,
    RootGone,
    Quota,
    TooLarge,
    TooManyEntries,
    Io,
    Cancelled,
    TooLate,
    Interrupted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemoteShareEvent {
    op: RemoteShareOp,
    root_id: Option<[u8; 16]>,
    rel_fingerprint: Option<u64>,
    denied: Option<RemoteShareDeny>,
}

impl RemoteShareEvent {
    pub(super) fn name(&self) -> &'static str {
        "remote_share.serve.op"
    }

    /// 结果即应答：策略性拒绝与 `denied` 都是对端可反复触发的预期事件，与
    /// `share gate` 同一档位记 INFO；只有本端 I/O 失败（对端无法制造）记 WARN。
    pub(super) fn level(&self) -> &'static str {
        match self.denied {
            Some(RemoteShareDeny::Io) => "WARN",
            _ => "INFO",
        }
    }

    pub(super) fn fields(&self) -> Map<String, Value> {
        let mut fields = Map::new();
        fields.insert("direction".into(), json!("inbound"));
        fields.insert("op".into(), json!(self.op));
        if let Some(root_id) = self.root_id {
            use std::fmt::Write as _;
            let mut hex = String::with_capacity(32);
            for byte in root_id {
                let _ = write!(hex, "{byte:02x}");
            }
            fields.insert("root_id".into(), json!(hex));
        }
        if let Some(fingerprint) = self.rel_fingerprint {
            fields.insert("rel_fingerprint".into(), json!(fingerprint));
        }
        match self.denied {
            Some(deny) => {
                fields.insert("uc.outcome".into(), json!("denied"));
                fields.insert("error.reason".into(), json!(deny));
            }
            None => {
                fields.insert("uc.outcome".into(), json!("ok"));
            }
        }
        fields
    }
}

/// 为一次已应答的 serve 操作写审计记录。`peer` 是入站连接的原始节点身份，
/// 只在发射瞬间进入内存观测上下文，绝不写入字段值。
#[allow(clippy::too_many_arguments)]
pub fn record_remote_share_op(
    peer: [u8; 32],
    op: RemoteShareOp,
    root_id: Option<[u8; 16]>,
    rel_fingerprint: Option<u64>,
    denied: Option<RemoteShareDeny>,
) {
    emit_local(
        LocalEvent::RemoteShareOp {
            record: RemoteShareEvent {
                op,
                root_id,
                rel_fingerprint,
                denied,
            },
        },
        &peer_context(peer),
    );
}

#[cfg(test)]
mod tests {
    use super::super::decode_local_record;
    use super::*;

    #[test]
    fn remote_share_op_rejects_uncontrolled_fields() {
        let valid = json!({"kind": "remote_share_op", "record": {"op": "mkdir", "root_id": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16], "rel_fingerprint": 42, "denied": "not_found"}});
        let name = "remote_share.serve.op";
        assert!(decode_local_record(name, &valid.to_string(), "INFO").is_some());
        assert!(decode_local_record(name, &valid.to_string(), "WARN").is_none());
        assert!(decode_local_record("peer.inbound.rejected", &valid.to_string(), "INFO").is_none());
        for (field, value) in [
            ("op", json!("PRIVATE")),
            ("root_id", json!("PRIVATE")),
            ("rel_fingerprint", json!("PRIVATE")),
            ("denied", json!("PRIVATE")),
            ("path", json!("/etc/passwd")),
        ] {
            let mut invalid = valid.clone();
            invalid["record"][field] = value;
            assert!(decode_local_record(name, &invalid.to_string(), "INFO").is_none());
        }
    }
}
