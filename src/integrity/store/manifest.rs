use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::errors::{BatmanError, BatmanResult};

pub(crate) const RECORD_FILE: &str = "baseline.bfi";
pub(crate) const INDEX_FILE: &str = "baseline.idx";
pub(crate) const MANIFEST_FILE: &str = "baseline.manifest";
pub(crate) const RECORD_TMP: &str = "baseline.bfi.tmp";
pub(crate) const INDEX_TMP: &str = "baseline.idx.tmp";
pub(crate) const MANIFEST_TMP: &str = "baseline.manifest.tmp";
pub(crate) const RECORD_BACKUP: &str = "baseline.bfi.prev";
pub(crate) const INDEX_BACKUP: &str = "baseline.idx.prev";
pub(crate) const MANIFEST_BACKUP: &str = "baseline.manifest.prev";

const FORMAT: &str = "batman-baseline-manifest-v1";
const HASH_BUFFER_SIZE: usize = 1024 * 1024;
pub const BASELINE_KEY_ENV: &str = "BATMAN_BASELINE_KEY";
pub const BASELINE_PRIVATE_KEY_ENV: &str = "BATMAN_BASELINE_PRIVATE_KEY";
pub const BASELINE_PUBLIC_KEY_ENV: &str = "BATMAN_BASELINE_PUBLIC_KEY";
pub const BASELINE_MIN_GENERATION_ENV: &str = "BATMAN_BASELINE_MIN_GENERATION";
pub const REQUIRE_SIGNED_BASELINE_ENV: &str = "BATMAN_REQUIRE_SIGNED_BASELINE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BaselineManifest {
    pub records: u64,
    pub scan_byte_limit: u64,
    pub created_unix_ms: u128,
    pub generation: u64,
    pub config_hash: [u8; 32],
    pub record_hash: [u8; 32],
    pub index_hash: [u8; 32],
    pub signature: Option<ManifestSignature>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaselineManifestInfo {
    pub created_unix_ms: u128,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManifestSignature {
    KeyedBlake3([u8; 32]),
    Ed25519([u8; 64]),
}

#[derive(Clone)]
pub struct BaselineSigningKey {
    seed: [u8; 32],
}

pub(crate) fn write_manifest_tmp(
    db_path: &Path,
    record_path: &Path,
    index_path: &Path,
    records: u64,
    scan_byte_limit: u64,
    config_hash: [u8; 32],
    signing_key: Option<&BaselineSigningKey>,
) -> BatmanResult<()> {
    let previous = read_manifest(&db_path.join(MANIFEST_FILE)).ok();
    let manifest = BaselineManifest {
        records,
        scan_byte_limit,
        created_unix_ms: unix_millis(),
        generation: previous
            .as_ref()
            .map(|manifest| manifest.generation.saturating_add(1))
            .unwrap_or(1),
        config_hash,
        record_hash: file_hash(record_path)?,
        index_hash: file_hash(index_path)?,
        signature: None,
    };
    let signature = manifest_signature(&manifest, signing_key)?;
    let path = db_path.join(MANIFEST_TMP);
    let mut file = File::create(&path)
        .map_err(|error| BatmanError::io(format!("create {}", path.display()), error))?;
    write!(
        file,
        "format: {FORMAT}\nrecords: {}\nscan_byte_limit: {}\ncreated_unix_ms: {}\ngeneration: {}\nconfig_hash: {}\nrecord_hash: {}\nindex_hash: {}\n",
        manifest.records,
        manifest.scan_byte_limit,
        manifest.created_unix_ms,
        manifest.generation,
        hex_hash(&manifest.config_hash),
        hex_hash(&manifest.record_hash),
        hex_hash(&manifest.index_hash),
    )
    .map_err(|error| BatmanError::io(format!("write {}", path.display()), error))?;
    if let Some(signature) = signature {
        writeln!(file, "signature: {}", signature.to_manifest_value())
            .map_err(|error| BatmanError::io(format!("write {}", path.display()), error))?;
    }
    file.sync_all()
        .map_err(|error| BatmanError::io(format!("sync {}", path.display()), error))
}

pub fn verify_baseline_manifest(db_path: &Path) -> BatmanResult<()> {
    verify_baseline_manifest_with_public_key(db_path, None)
}

pub fn verify_baseline_manifest_with_public_key(
    db_path: &Path,
    configured_public_key: Option<&str>,
) -> BatmanResult<()> {
    let manifest = read_manifest(&db_path.join(MANIFEST_FILE))?;
    verify_manifest_values_with_public_key(
        db_path,
        manifest.records,
        manifest.scan_byte_limit,
        manifest.config_hash,
        configured_public_key,
    )
    .map(|_| ())
}

pub fn ensure_baseline_can_be_signed_if_required() -> BatmanResult<()> {
    let private_key = baseline_signing_key_from_env()?;
    ensure_baseline_can_be_signed_if_required_with_private_key(None, private_key.as_ref())
}

pub fn ensure_baseline_can_be_signed_if_required_with_public_key(
    configured_public_key: Option<&str>,
) -> BatmanResult<()> {
    let private_key = baseline_signing_key_from_env()?;
    ensure_baseline_can_be_signed_if_required_with_private_key(
        configured_public_key,
        private_key.as_ref(),
    )
}

pub fn ensure_baseline_can_be_signed_if_required_with_private_key(
    configured_public_key: Option<&str>,
    private_key: Option<&BaselineSigningKey>,
) -> BatmanResult<()> {
    if let Some(public_key) = ed25519_public_key(configured_public_key)? {
        let Some(private_key) = private_key else {
            let required_prefix = if require_signed_baseline() {
                format!("{REQUIRE_SIGNED_BASELINE_ENV} is enabled and ")
            } else {
                String::new()
            };
            return Err(BatmanError::Config(format!(
                "{required_prefix}an Ed25519 baseline public key ({BASELINE_PUBLIC_KEY_ENV} or file_integrity.baseline_public_key) is configured, so {BASELINE_PRIVATE_KEY_ENV} must be set before baselining. {BASELINE_KEY_ENV} cannot create a baseline accepted by the configured Ed25519 public key."
            )));
        };
        if private_key.verifying_key().as_bytes() != public_key.as_bytes() {
            return Err(BatmanError::Config(format!(
                "{BASELINE_PRIVATE_KEY_ENV} does not match the configured baseline public key"
            )));
        }
        return Ok(());
    }
    if !require_signed_baseline() {
        return Ok(());
    }
    if private_key.is_some() || signing_key()?.is_some() {
        return Ok(());
    }
    Err(BatmanError::Config(format!(
        "{REQUIRE_SIGNED_BASELINE_ENV} is enabled, but no baseline signing key is configured. Set {BASELINE_PRIVATE_KEY_ENV} before baselining, or set {BASELINE_KEY_ENV} for legacy symmetric signing."
    )))
}

pub(crate) fn verify_manifest_values_with_public_key(
    db_path: &Path,
    records: u64,
    scan_byte_limit: u64,
    config_hash: [u8; 32],
    configured_public_key: Option<&str>,
) -> BatmanResult<BaselineManifestInfo> {
    let path = db_path.join(MANIFEST_FILE);
    let manifest = read_manifest(&path)?;
    if manifest.records != records {
        return Err(BatmanError::Store(format!(
            "baseline manifest record count mismatch in {}",
            path.display()
        )));
    }
    if manifest.scan_byte_limit != scan_byte_limit {
        return Err(BatmanError::Store(format!(
            "baseline manifest scan byte limit mismatch in {}",
            path.display()
        )));
    }
    if manifest.config_hash != config_hash {
        return Err(BatmanError::Store(format!(
            "baseline manifest config hash mismatch in {}",
            path.display()
        )));
    }
    let record_hash = file_hash(&db_path.join(RECORD_FILE))?;
    if manifest.record_hash != record_hash {
        return Err(BatmanError::Store(format!(
            "baseline record file hash mismatch in {}",
            path.display()
        )));
    }
    let index_hash = file_hash(&db_path.join(INDEX_FILE))?;
    if manifest.index_hash != index_hash {
        return Err(BatmanError::Store(format!(
            "baseline index file hash mismatch in {}",
            path.display()
        )));
    }
    verify_manifest_signature(&manifest, &path, configured_public_key)?;
    Ok(BaselineManifestInfo {
        created_unix_ms: manifest.created_unix_ms,
        generation: manifest.generation,
    })
}

fn read_manifest(path: &Path) -> BatmanResult<BaselineManifest> {
    let content = fs::read_to_string(path)
        .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
    let mut format = None;
    let mut records = None;
    let mut scan_byte_limit = None;
    let mut created_unix_ms = None;
    let mut generation = None;
    let mut config_hash = None;
    let mut record_hash = None;
    let mut index_hash = None;
    let mut signature = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "format" => format = Some(value.to_string()),
            "records" => records = value.parse::<u64>().ok(),
            "scan_byte_limit" => scan_byte_limit = value.parse::<u64>().ok(),
            "created_unix_ms" => created_unix_ms = value.parse::<u128>().ok(),
            "generation" => generation = value.parse::<u64>().ok(),
            "config_hash" => config_hash = parse_hash(value),
            "record_hash" => record_hash = parse_hash(value),
            "index_hash" => index_hash = parse_hash(value),
            "signature" => signature = parse_signature(value),
            _ => {}
        }
    }
    if format.as_deref() != Some(FORMAT) {
        return Err(BatmanError::Store(format!(
            "invalid baseline manifest format in {}",
            path.display()
        )));
    }
    Ok(BaselineManifest {
        records: records.ok_or_else(|| missing_manifest_field(path, "records"))?,
        scan_byte_limit: scan_byte_limit
            .ok_or_else(|| missing_manifest_field(path, "scan_byte_limit"))?,
        created_unix_ms: created_unix_ms
            .ok_or_else(|| missing_manifest_field(path, "created_unix_ms"))?,
        generation: generation.ok_or_else(|| missing_manifest_field(path, "generation"))?,
        config_hash: config_hash.ok_or_else(|| missing_manifest_field(path, "config_hash"))?,
        record_hash: record_hash.ok_or_else(|| missing_manifest_field(path, "record_hash"))?,
        index_hash: index_hash.ok_or_else(|| missing_manifest_field(path, "index_hash"))?,
        signature,
    })
}

fn missing_manifest_field(path: &Path, field: &str) -> BatmanError {
    BatmanError::Store(format!(
        "missing baseline manifest field {field} in {}",
        path.display()
    ))
}

fn file_hash(path: &Path) -> BatmanResult<[u8; 32]> {
    let file = File::open(path)
        .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_SIZE, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    loop {
        let len = reader
            .read(&mut buffer)
            .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
        if len == 0 {
            break;
        }
        hasher.update(&buffer[..len]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn manifest_signature(
    manifest: &BaselineManifest,
    signing_key: Option<&BaselineSigningKey>,
) -> BatmanResult<Option<ManifestSignature>> {
    if let Some(key) = signing_key {
        return Ok(Some(ManifestSignature::Ed25519(
            key.signing_key()
                .sign(&signature_payload(manifest))
                .to_bytes(),
        )));
    }
    Ok(keyed_blake3_signature(manifest)?.map(ManifestSignature::KeyedBlake3))
}

fn keyed_blake3_signature(manifest: &BaselineManifest) -> BatmanResult<Option<[u8; 32]>> {
    let Some(key) = signing_key()? else {
        return Ok(None);
    };
    Ok(Some(
        *blake3::keyed_hash(&key, &signature_payload(manifest)).as_bytes(),
    ))
}

fn verify_manifest_signature(
    manifest: &BaselineManifest,
    path: &Path,
    configured_public_key: Option<&str>,
) -> BatmanResult<()> {
    verify_manifest_signature_with_policy(
        manifest,
        path,
        signing_key()?,
        require_signed_baseline(),
        configured_public_key,
    )
}

fn verify_manifest_signature_with_policy(
    manifest: &BaselineManifest,
    path: &Path,
    key: Option<[u8; 32]>,
    require_signed: bool,
    configured_public_key: Option<&str>,
) -> BatmanResult<()> {
    if let Some(min_generation) = min_generation()?
        && manifest.generation < min_generation
    {
        return Err(BatmanError::Store(format!(
            "baseline manifest generation {} is older than required minimum {} in {}",
            manifest.generation,
            min_generation,
            path.display()
        )));
    }
    if let Some(public_key) = ed25519_public_key(configured_public_key)? {
        return match manifest.signature {
            Some(ManifestSignature::Ed25519(signature)) => {
                let signature = Signature::from_bytes(&signature);
                public_key
                    .verify(&signature_payload(manifest), &signature)
                    .map_err(|_| {
                        BatmanError::Store(format!(
                            "baseline manifest Ed25519 signature mismatch in {}",
                            path.display()
                        ))
                    })
            }
            Some(ManifestSignature::KeyedBlake3(_)) => Err(BatmanError::Store(format!(
                "baseline manifest is not signed with Ed25519 in {}",
                path.display()
            ))),
            None => Err(BatmanError::Store(format!(
                "baseline manifest is unsigned; set {BASELINE_PRIVATE_KEY_ENV} before baselining"
            ))),
        };
    }
    match (&manifest.signature, key, require_signed) {
        (Some(ManifestSignature::KeyedBlake3(signature)), Some(key), _) => {
            let expected = *blake3::keyed_hash(&key, &signature_payload(manifest)).as_bytes();
            if *signature != expected {
                return Err(BatmanError::Store(format!(
                    "baseline manifest signature mismatch in {}",
                    path.display()
                )));
            }
            Ok(())
        }
        (Some(ManifestSignature::KeyedBlake3(_)), None, true) => Err(BatmanError::Store(format!(
            "baseline manifest is signed but {BASELINE_KEY_ENV} is not set"
        ))),
        (Some(ManifestSignature::Ed25519(_)), _, true) => Err(BatmanError::Store(format!(
            "baseline manifest is signed with Ed25519 but {BASELINE_PUBLIC_KEY_ENV} is not set"
        ))),
        (Some(ManifestSignature::Ed25519(_)), _, false) => Ok(()),
        (Some(_), None, false) => Ok(()),
        (None, _, true) => Err(BatmanError::Store(format!(
            "baseline manifest is unsigned; set {BASELINE_PUBLIC_KEY_ENV} or {BASELINE_KEY_ENV}, or disable {REQUIRE_SIGNED_BASELINE_ENV}"
        ))),
        (None, _, false) => Ok(()),
    }
}

fn signature_payload(manifest: &BaselineManifest) -> Vec<u8> {
    format!(
        "format:{FORMAT}\nrecords:{}\nscan_byte_limit:{}\ncreated_unix_ms:{}\ngeneration:{}\nconfig_hash:{}\nrecord_hash:{}\nindex_hash:{}\n",
        manifest.records,
        manifest.scan_byte_limit,
        manifest.created_unix_ms,
        manifest.generation,
        hex_hash(&manifest.config_hash),
        hex_hash(&manifest.record_hash),
        hex_hash(&manifest.index_hash),
    )
    .into_bytes()
}

fn signing_key() -> BatmanResult<Option<[u8; 32]>> {
    let Ok(value) = std::env::var(BASELINE_KEY_ENV) else {
        return Ok(None);
    };
    let value = value.trim();
    parse_hash(value).map(Some).ok_or_else(|| {
        BatmanError::Config(format!(
            "{BASELINE_KEY_ENV} must be a 64-character hex-encoded 32-byte key"
        ))
    })
}

fn require_signed_baseline() -> bool {
    std::env::var(REQUIRE_SIGNED_BASELINE_ENV)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn baseline_signing_key_from_env() -> BatmanResult<Option<BaselineSigningKey>> {
    let Ok(value) = std::env::var(BASELINE_PRIVATE_KEY_ENV) else {
        return Ok(None);
    };
    parse_baseline_private_key(value.trim()).map(Some)
}

pub fn parse_baseline_private_key(value: &str) -> BatmanResult<BaselineSigningKey> {
    let seed = parse_hash(value.trim()).ok_or_else(|| {
        BatmanError::Config(format!(
            "{BASELINE_PRIVATE_KEY_ENV} must be a 64-character hex-encoded 32-byte Ed25519 seed"
        ))
    })?;
    Ok(BaselineSigningKey { seed })
}

fn ed25519_public_key(configured_public_key: Option<&str>) -> BatmanResult<Option<VerifyingKey>> {
    if let Ok(value) = std::env::var(BASELINE_PUBLIC_KEY_ENV) {
        return parse_ed25519_public_key(BASELINE_PUBLIC_KEY_ENV, value.trim());
    }
    let Some(value) = configured_public_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    parse_ed25519_public_key("file_integrity.baseline_public_key", value)
}

fn parse_ed25519_public_key(name: &str, value: &str) -> BatmanResult<Option<VerifyingKey>> {
    let key = parse_hash(value.trim()).ok_or_else(|| {
        BatmanError::Config(format!(
            "{name} must be a 64-character hex-encoded 32-byte Ed25519 public key"
        ))
    })?;
    VerifyingKey::from_bytes(&key)
        .map(Some)
        .map_err(|_| BatmanError::Config(format!("{name} is not a valid Ed25519 public key")))
}

fn min_generation() -> BatmanResult<Option<u64>> {
    let Ok(value) = std::env::var(BASELINE_MIN_GENERATION_ENV) else {
        return Ok(None);
    };
    value.trim().parse::<u64>().map(Some).map_err(|_| {
        BatmanError::Config(format!(
            "{BASELINE_MIN_GENERATION_ENV} must be a positive integer"
        ))
    })
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn hex_hash(hash: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn parse_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut hash = [0_u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(hash)
}

fn parse_signature(value: &str) -> Option<ManifestSignature> {
    if let Some(value) = value.strip_prefix("keyed-blake3:") {
        return parse_hash(value).map(ManifestSignature::KeyedBlake3);
    }
    if let Some(value) = value.strip_prefix("ed25519:") {
        return parse_hex_64(value).map(ManifestSignature::Ed25519);
    }
    parse_hash(value).map(ManifestSignature::KeyedBlake3)
}

fn parse_hex_64(value: &str) -> Option<[u8; 64]> {
    if value.len() != 128 {
        return None;
    }
    let mut bytes = [0_u8; 64];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(bytes)
}

impl BaselineSigningKey {
    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }
}

impl ManifestSignature {
    fn to_manifest_value(&self) -> String {
        match self {
            ManifestSignature::KeyedBlake3(signature) => {
                format!("keyed-blake3:{}", hex_hash(signature))
            }
            ManifestSignature::Ed25519(signature) => format!("ed25519:{}", hex_bytes(signature)),
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};

    use crate::test_support::env_lock;

    use super::{
        BaselineManifest, ManifestSignature, signature_payload,
        verify_manifest_signature_with_policy,
    };

    #[test]
    fn strict_policy_rejects_unsigned_manifest() {
        let _guard = env_lock();
        clear_manifest_env();
        let manifest = manifest(None);
        let error = verify_manifest_signature_with_policy(
            &manifest,
            Path::new("baseline.manifest"),
            None,
            true,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("baseline manifest is unsigned"));
    }

    #[test]
    fn strict_policy_rejects_signed_manifest_without_key() {
        let _guard = env_lock();
        clear_manifest_env();
        let manifest = manifest(Some(ManifestSignature::KeyedBlake3([9; 32])));
        let error = verify_manifest_signature_with_policy(
            &manifest,
            Path::new("baseline.manifest"),
            None,
            true,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("BATMAN_BASELINE_KEY is not set"));
    }

    #[test]
    fn strict_policy_accepts_matching_signature() {
        let _guard = env_lock();
        clear_manifest_env();
        let key = [7; 32];
        let mut manifest = manifest(None);
        manifest.signature = Some(ManifestSignature::KeyedBlake3(
            *blake3::keyed_hash(&key, &signature_payload(&manifest)).as_bytes(),
        ));

        verify_manifest_signature_with_policy(
            &manifest,
            Path::new("baseline.manifest"),
            Some(key),
            true,
            None,
        )
        .unwrap();
    }

    #[test]
    fn strict_policy_rejects_older_than_min_generation() {
        let _guard = env_lock();
        clear_manifest_env();
        unsafe {
            std::env::set_var(super::BASELINE_MIN_GENERATION_ENV, "3");
        }
        let result = verify_manifest_signature_with_policy(
            &manifest(None),
            Path::new("baseline.manifest"),
            None,
            false,
            None,
        );
        unsafe {
            std::env::remove_var(super::BASELINE_MIN_GENERATION_ENV);
        }
        let error = result.unwrap_err().to_string();
        assert!(error.contains("older than required minimum"));
    }

    #[test]
    fn ed25519_signature_is_verified_with_public_key() {
        let _guard = env_lock();
        clear_manifest_env();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let mut manifest = manifest(None);
        manifest.signature = Some(ManifestSignature::Ed25519(
            signing_key.sign(&signature_payload(&manifest)).to_bytes(),
        ));
        unsafe {
            std::env::set_var(
                super::BASELINE_PUBLIC_KEY_ENV,
                super::hex_hash(signing_key.verifying_key().as_bytes()),
            );
        }
        verify_manifest_signature_with_policy(
            &manifest,
            Path::new("baseline.manifest"),
            None,
            true,
            None,
        )
        .unwrap();
        unsafe {
            std::env::remove_var(super::BASELINE_PUBLIC_KEY_ENV);
        }
    }

    #[test]
    fn baseline_signing_preflight_rejects_required_signed_baseline_without_signing_key() {
        let _guard = env_lock();
        clear_manifest_env();
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        unsafe {
            std::env::set_var(super::REQUIRE_SIGNED_BASELINE_ENV, "1");
            std::env::set_var(
                super::BASELINE_PUBLIC_KEY_ENV,
                super::hex_hash(signing_key.verifying_key().as_bytes()),
            );
        }

        let error = super::ensure_baseline_can_be_signed_if_required()
            .unwrap_err()
            .to_string();

        assert!(error.contains("BATMAN_REQUIRE_SIGNED_BASELINE is enabled"));
        assert!(error.contains("BATMAN_BASELINE_PRIVATE_KEY"));
        unsafe {
            std::env::remove_var(super::REQUIRE_SIGNED_BASELINE_ENV);
            std::env::remove_var(super::BASELINE_PUBLIC_KEY_ENV);
        }
    }

    #[test]
    fn baseline_signing_preflight_accepts_required_signed_baseline_with_private_key() {
        let _guard = env_lock();
        clear_manifest_env();
        unsafe {
            std::env::set_var(super::REQUIRE_SIGNED_BASELINE_ENV, "1");
            std::env::set_var(super::BASELINE_PRIVATE_KEY_ENV, super::hex_bytes(&[8; 32]));
        }

        super::ensure_baseline_can_be_signed_if_required().unwrap();

        unsafe {
            std::env::remove_var(super::REQUIRE_SIGNED_BASELINE_ENV);
            std::env::remove_var(super::BASELINE_PRIVATE_KEY_ENV);
        }
    }

    #[test]
    fn baseline_signing_preflight_rejects_public_key_with_only_symmetric_key() {
        let _guard = env_lock();
        clear_manifest_env();
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        unsafe {
            std::env::set_var(super::REQUIRE_SIGNED_BASELINE_ENV, "1");
            std::env::set_var(
                super::BASELINE_PUBLIC_KEY_ENV,
                super::hex_hash(signing_key.verifying_key().as_bytes()),
            );
            std::env::set_var(super::BASELINE_KEY_ENV, super::hex_bytes(&[9; 32]));
        }

        let error = super::ensure_baseline_can_be_signed_if_required()
            .unwrap_err()
            .to_string();

        assert!(error.contains("BATMAN_BASELINE_PUBLIC_KEY"));
        assert!(error.contains("BATMAN_BASELINE_PRIVATE_KEY"));
        assert!(error.contains("BATMAN_BASELINE_KEY cannot create"));
        unsafe {
            std::env::remove_var(super::REQUIRE_SIGNED_BASELINE_ENV);
            std::env::remove_var(super::BASELINE_PUBLIC_KEY_ENV);
            std::env::remove_var(super::BASELINE_KEY_ENV);
        }
    }

    #[test]
    fn baseline_signing_preflight_rejects_mismatched_ed25519_keys() {
        let _guard = env_lock();
        clear_manifest_env();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let other_key = SigningKey::from_bytes(&[12; 32]);
        unsafe {
            std::env::set_var(super::REQUIRE_SIGNED_BASELINE_ENV, "1");
            std::env::set_var(super::BASELINE_PRIVATE_KEY_ENV, super::hex_bytes(&[11; 32]));
            std::env::set_var(
                super::BASELINE_PUBLIC_KEY_ENV,
                super::hex_hash(other_key.verifying_key().as_bytes()),
            );
        }

        let error = super::ensure_baseline_can_be_signed_if_required()
            .unwrap_err()
            .to_string();

        assert_ne!(
            signing_key.verifying_key().as_bytes(),
            other_key.verifying_key().as_bytes()
        );
        assert!(error.contains("does not match"));
        unsafe {
            std::env::remove_var(super::REQUIRE_SIGNED_BASELINE_ENV);
            std::env::remove_var(super::BASELINE_PRIVATE_KEY_ENV);
            std::env::remove_var(super::BASELINE_PUBLIC_KEY_ENV);
        }
    }

    fn clear_manifest_env() {
        unsafe {
            std::env::remove_var(super::BASELINE_KEY_ENV);
            std::env::remove_var(super::BASELINE_PRIVATE_KEY_ENV);
            std::env::remove_var(super::BASELINE_PUBLIC_KEY_ENV);
            std::env::remove_var(super::BASELINE_MIN_GENERATION_ENV);
            std::env::remove_var(super::REQUIRE_SIGNED_BASELINE_ENV);
        }
    }

    fn manifest(signature: Option<ManifestSignature>) -> BaselineManifest {
        BaselineManifest {
            records: 2,
            scan_byte_limit: 0,
            created_unix_ms: 123,
            generation: 2,
            config_hash: [1; 32],
            record_hash: [2; 32],
            index_hash: [3; 32],
            signature,
        }
    }
}
