//! 设备文件共享的领域类型与端口。

mod confinement;
mod model;
mod serve;
mod store;

pub use confinement::{
    is_well_formed_relative, ConfineError, ConfinedDirEntry, ConfinedMetadata, ConfinedTarget,
    ConfinedTargetToken, ConfinedTrashEntry, ConfinedTrashPage, ConflictPolicy, RootIdentity,
    ShareConfinementPort, ShareStagedEntry,
};
pub use model::{
    is_reserved_share_component, is_reserved_staging_component, is_reserved_trash_component,
    is_windows_reserved_device_name, normalize_share_component, ShareGrants, ShareOperation,
    ShareRoot, ShareRootId, ShareStoreDoc,
};
pub use serve::{
    RemoteShareServePort, ShareAvailability, ShareDirectoryEntry, ShareDirectoryPage,
    ShareExportOutcome, ShareRootDescriptor, ShareServeError, ShareStageEntry, ShareStageOutcome,
    ShareTransferId, ShareTrashEntry, ShareTrashPage,
};
pub use store::{SharedRootStoreError, SharedRootStorePort};
