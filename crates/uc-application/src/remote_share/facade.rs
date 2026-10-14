//! 设备文件共享的对外门面（ADR-018）。
//!
//! P2 的 serve 适配器通过 [`RemoteShareFacade`] 做 fail-closed 授权判定。判定器本身
//! （`ShareAuthorizer`）保持 `pub(crate)`，外部只经门面消费，符合 ADR-018 的白名单
//! 约束。

use std::sync::Arc;

use uc_core::ids::DeviceId;
use uc_core::ports::remote_share::{ShareOperation, ShareRootId, SharedRootStorePort};

use crate::remote_share::authorizer::{ShareAuthorizer, SharePermit};

/// 构造 [`RemoteShareFacade`] 所需的端口集合。
pub struct RemoteShareFacadeDeps {
    /// 共享根清单的密文存储；未解锁时不可读，判定随之以 fail-closed 返回 `None`。
    pub share_store: Arc<dyn SharedRootStorePort>,
}

/// 设备文件共享门面。线程安全，可放入 `Arc`。
pub struct RemoteShareFacade {
    authorizer: ShareAuthorizer,
}

impl RemoteShareFacade {
    pub fn new(deps: RemoteShareFacadeDeps) -> Self {
        let RemoteShareFacadeDeps { share_store } = deps;
        Self {
            authorizer: ShareAuthorizer::new(share_store),
        }
    }

    /// 判定 `peer` 能否对 `root` 执行 `op`。任何拒绝与任何存储失败都是 `None`。
    ///
    /// 路径约束（`ShareConfinementPort`）不在本门面内：serve 适配器须先把授权判定与
    /// 路径解析两者都成功才放行（规格 §5.2 步骤 3–6 的顺序）。
    #[must_use]
    pub async fn authorize(
        &self,
        peer: &DeviceId,
        root: ShareRootId,
        op: ShareOperation,
    ) -> Option<SharePermit> {
        self.authorizer.authorize(peer, root, op).await
    }
}
