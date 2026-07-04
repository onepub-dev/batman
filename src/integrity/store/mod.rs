mod format;
mod hash;
mod manifest;
mod metadata;
mod reader;
mod scan_spool;
mod seen;
mod writer;

pub use metadata::{
    FileMetadata, META_ACL, META_CHANGED, META_CREATED, META_DIRECTORY, META_GROUP, META_KIND_MASK,
    META_OWNER, META_PERMISSIONS, META_SPECIAL, META_SYMLINK, modified_ns,
};
#[cfg(target_os = "linux")]
pub use metadata::{LINUX_APPEND_FL, LINUX_IMMUTABLE_FL, linux_inode_flags};
pub use reader::{BaselineReader, BaselineRecord, LookupResult};
pub use scan_spool::{CurrentScanEntry, CurrentScanReader, CurrentScanSpool};
pub use seen::SeenSet;
pub use writer::{BaselineFinishProgress, BaselineWriter};

pub use manifest::{
    BASELINE_KEY_ENV, BASELINE_MIN_GENERATION_ENV, BASELINE_PRIVATE_KEY_ENV,
    BASELINE_PUBLIC_KEY_ENV, BaselineManifestInfo, BaselineSigningKey, REQUIRE_SIGNED_BASELINE_ENV,
    baseline_signing_key_from_env, ensure_baseline_can_be_signed_if_required,
    ensure_baseline_can_be_signed_if_required_with_private_key,
    ensure_baseline_can_be_signed_if_required_with_public_key, parse_baseline_private_key,
    verify_baseline_manifest, verify_baseline_manifest_with_public_key,
};

pub fn path_key(path: &std::path::Path) -> String {
    format!(
        "{:032x}",
        hash::path_hash(path.to_string_lossy().as_bytes())
    )
}

pub fn path_hash_value(path: &std::path::Path) -> u128 {
    hash::path_hash(path.to_string_lossy().as_bytes())
}
