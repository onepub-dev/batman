use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{BatmanError, BatmanResult};

pub const EXPECTED_CONFIG_HASH_ENV: &str = "BATMAN_EXPECTED_CONFIG_HASH";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustIssue {
    pub path: PathBuf,
    pub message: String,
}

impl TrustIssue {
    fn new(path: &Path, message: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            message: message.into(),
        }
    }
}

pub fn secure_config_path(path: &Path) -> BatmanResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        secure_directory(parent)?;
    }
    secure_file(path)
}

pub fn write_secure_config_atomic(path: &Path, content: &str) -> BatmanResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| BatmanError::io(format!("create {}", parent.display()), error))?;
    secure_directory(parent)?;

    let tmp = temp_config_path(path);
    let write_result = (|| -> BatmanResult<()> {
        let mut file = File::create(&tmp)
            .map_err(|error| BatmanError::io(format!("create {}", tmp.display()), error))?;
        file.write_all(content.as_bytes())
            .map_err(|error| BatmanError::io(format!("write {}", tmp.display()), error))?;
        file.sync_all()
            .map_err(|error| BatmanError::io(format!("sync {}", tmp.display()), error))?;
        secure_file(&tmp)?;
        fs::rename(&tmp, path).map_err(|error| {
            BatmanError::io(
                format!("replace {} with {}", path.display(), tmp.display()),
                error,
            )
        })?;
        secure_file(path)?;
        sync_directory(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

pub fn secure_data_directory(path: &Path) -> BatmanResult<()> {
    secure_directory(path)
}

pub fn secure_data_file(path: &Path) -> BatmanResult<()> {
    secure_file(path)
}

pub fn file_content_hash(path: &Path) -> BatmanResult<[u8; 32]> {
    let bytes = fs::read(path)
        .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub fn hex_hash(hash: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in hash {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub fn expected_config_hash() -> BatmanResult<Option<[u8; 32]>> {
    let Ok(value) = std::env::var(EXPECTED_CONFIG_HASH_ENV) else {
        return Ok(None);
    };
    let value = value.trim();
    let Some(hash) = parse_hex_hash(value) else {
        return Err(BatmanError::Config(format!(
            "{EXPECTED_CONFIG_HASH_ENV} must be a 64-character hex-encoded BLAKE3 config hash"
        )));
    };
    Ok(Some(hash))
}

pub fn verify_expected_config_hash(path: &Path) -> BatmanResult<()> {
    let Some(expected) = expected_config_hash()? else {
        return Ok(());
    };
    let actual = file_content_hash(path)?;
    if actual == expected {
        return Ok(());
    }
    Err(BatmanError::Config(format!(
        "{EXPECTED_CONFIG_HASH_ENV} mismatch for {}; expected {}, actual {}",
        path.display(),
        hex_hash(&expected),
        hex_hash(&actual)
    )))
}

pub fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn config_trust_issues(path: &Path, privileged: bool) -> Vec<TrustIssue> {
    let mut issues = Vec::new();
    check_trusted_file(path, privileged, &mut issues);
    for parent in trust_parents(path) {
        check_trusted_directory(&parent, privileged, &mut issues);
    }
    issues
}

pub fn file_trust_issues(path: &Path, privileged: bool) -> Vec<TrustIssue> {
    let mut issues = Vec::new();
    check_trusted_file(path, privileged, &mut issues);
    for parent in trust_parents(path) {
        check_trusted_directory(&parent, privileged, &mut issues);
    }
    issues
}

pub fn existing_file_trust_issues(path: &Path, privileged: bool) -> Vec<TrustIssue> {
    let mut issues = Vec::new();
    check_existing_trusted_file(path, privileged, &mut issues);
    if path.exists() {
        for parent in trust_parents(path) {
            check_trusted_directory(&parent, privileged, &mut issues);
        }
    }
    issues
}

pub fn data_path_trust_issues(path: &Path, privileged: bool) -> Vec<TrustIssue> {
    let mut issues = Vec::new();
    check_trusted_directory(path, privileged, &mut issues);
    for file in baseline_trust_files(path) {
        check_existing_trusted_file(&file, privileged, &mut issues);
    }
    for parent in trust_parents(path) {
        check_trusted_directory(&parent, privileged, &mut issues);
    }
    issues
}

fn trust_parents(path: &Path) -> Vec<PathBuf> {
    let mut parents = Vec::new();
    let mut current = path.parent();
    while let Some(parent) = current {
        if parent.as_os_str().is_empty() {
            break;
        }
        parents.push(parent.to_path_buf());
        current = parent.parent();
    }
    parents
}

fn temp_config_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "batman.yaml".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    name.push(format!(".tmp.{}.{nanos}", std::process::id()));
    path.with_file_name(name)
}

fn parse_hex_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn check_trusted_file(path: &Path, privileged: bool, issues: &mut Vec<TrustIssue>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            issues.push(TrustIssue::new(path, error.to_string()));
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        issues.push(TrustIssue::new(path, "must not be a symlink"));
        return;
    }
    if !metadata.is_file() {
        issues.push(TrustIssue::new(path, "must be a regular file"));
        return;
    }
    platform_check_trusted_metadata(path, &metadata, privileged, false, issues);
}

fn check_existing_trusted_file(path: &Path, privileged: bool, issues: &mut Vec<TrustIssue>) {
    match fs::symlink_metadata(path) {
        Ok(_) => check_trusted_file(path, privileged, issues),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => issues.push(TrustIssue::new(path, error.to_string())),
    }
}

fn check_trusted_directory(path: &Path, privileged: bool, issues: &mut Vec<TrustIssue>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            issues.push(TrustIssue::new(path, error.to_string()));
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        issues.push(TrustIssue::new(path, "must not be a symlink"));
        return;
    }
    if !metadata.is_dir() {
        issues.push(TrustIssue::new(path, "must be a directory"));
        return;
    }
    platform_check_trusted_metadata(path, &metadata, privileged, true, issues);
}

fn baseline_trust_files(db_path: &Path) -> Vec<PathBuf> {
    [
        "baseline.bfi",
        "baseline.idx",
        "baseline.manifest",
        "baseline.bfi.tmp",
        "baseline.idx.tmp",
        "baseline.manifest.tmp",
        "baseline.bfi.prev",
        "baseline.idx.prev",
        "baseline.manifest.prev",
        "audit.log",
    ]
    .into_iter()
    .map(|name| db_path.join(name))
    .collect()
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> BatmanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| BatmanError::io(format!("set permissions {}", path.display()), error))?;
    chown_root_if_running_as_root(path)
}

#[cfg(unix)]
fn secure_file(path: &Path) -> BatmanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| BatmanError::io(format!("set permissions {}", path.display()), error))?;
    chown_root_if_running_as_root(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> BatmanResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| BatmanError::io(format!("sync {}", path.display()), error))
}

#[cfg(unix)]
fn chown_root_if_running_as_root(path: &Path) -> BatmanResult<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_bytes = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        BatmanError::Config(format!(
            "path contains NUL byte: {} ({error})",
            path.display()
        ))
    })?;
    let rc = unsafe { libc::chown(path_bytes.as_ptr(), 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(BatmanError::io(
            format!("chown root:root {}", path.display()),
            std::io::Error::last_os_error(),
        ))
    }
}

#[cfg(unix)]
fn platform_check_trusted_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    privileged: bool,
    _directory: bool,
    issues: &mut Vec<TrustIssue>,
) {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode() & 0o777;
    if mode & 0o022 != 0 {
        issues.push(TrustIssue::new(
            path,
            format!("must not be group/world writable (mode {mode:o})"),
        ));
    }
    if privileged && metadata.uid() != 0 {
        issues.push(TrustIssue::new(path, "must be owned by root"));
    }
}

#[cfg(windows)]
fn secure_directory(path: &Path) -> BatmanResult<()> {
    secure_windows_acl(path)
}

#[cfg(windows)]
fn secure_file(path: &Path) -> BatmanResult<()> {
    secure_windows_acl(path)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> BatmanResult<()> {
    Ok(())
}

#[cfg(windows)]
fn secure_windows_acl(path: &Path) -> BatmanResult<()> {
    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:F")
        .arg("*S-1-5-18:F")
        .arg("/remove:g")
        .arg("*S-1-1-0")
        .arg("*S-1-5-11")
        .arg("*S-1-5-32-545")
        .status()
        .map_err(|error| BatmanError::io(format!("run icacls {}", path.display()), error))?;
    if status.success() {
        Ok(())
    } else {
        Err(BatmanError::Config(format!(
            "icacls failed while securing {}",
            path.display()
        )))
    }
}

#[cfg(windows)]
fn platform_check_trusted_metadata(
    path: &Path,
    _metadata: &fs::Metadata,
    _privileged: bool,
    _directory: bool,
    issues: &mut Vec<TrustIssue>,
) {
    if !windows_acl_is_admin_only(path) {
        issues.push(TrustIssue::new(
            path,
            "ACL should restrict writes to Administrators and SYSTEM",
        ));
    }
}

#[cfg(windows)]
fn windows_acl_is_admin_only(_path: &Path) -> bool {
    windows_acl_has_no_broad_writers(_path).unwrap_or(false)
}

#[cfg(windows)]
fn windows_acl_has_no_broad_writers(path: &Path) -> Option<bool> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{addr_of, null_mut};

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, PSID,
        WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_WRITE,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const WRITE_LIKE_ACCESS: u32 = GENERIC_ALL
        | GENERIC_WRITE
        | FILE_ALL_ACCESS
        | FILE_GENERIC_WRITE
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER;

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let mut dacl: *mut ACL = null_mut();
    let mut security_descriptor = null_mut();

    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut security_descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let _guard = LocalSecurityDescriptor(security_descriptor);
    if dacl.is_null() {
        return Some(false);
    }

    let broad_sids = [
        well_known_sid(WinWorldSid)?,
        well_known_sid(WinAuthenticatedUserSid)?,
        well_known_sid(WinBuiltinUsersSid)?,
    ];
    let mut info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return None;
    }

    for index in 0..info.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return None;
        }
        let ace = ace as *const ACCESS_ALLOWED_ACE;
        let header = unsafe { (*ace).Header };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let mask = unsafe { (*ace).Mask };
        if mask & WRITE_LIKE_ACCESS == 0 {
            continue;
        }
        let sid = unsafe { addr_of!((*ace).SidStart) as PSID };
        if broad_sids
            .iter()
            .any(|broad_sid| unsafe { EqualSid(sid, broad_sid.as_psid()) != 0 })
        {
            return Some(false);
        }
    }
    Some(true)
}

#[cfg(windows)]
struct LocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct OwnedSid(Vec<u8>);

#[cfg(windows)]
impl OwnedSid {
    fn as_psid(&self) -> windows_sys::Win32::Security::PSID {
        self.0.as_ptr() as windows_sys::Win32::Security::PSID
    }
}

#[cfg(windows)]
fn well_known_sid(kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE) -> Option<OwnedSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};

    let mut bytes = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    let ok = unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            bytes.as_mut_ptr() as windows_sys::Win32::Security::PSID,
            &mut len,
        )
    };
    if ok == 0 {
        return None;
    }
    bytes.truncate(len as usize);
    Some(OwnedSid(bytes))
}

#[cfg(not(any(unix, windows)))]
fn secure_directory(_path: &Path) -> BatmanResult<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_file(_path: &Path) -> BatmanResult<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn platform_check_trusted_metadata(
    _path: &Path,
    _metadata: &fs::Metadata,
    _privileged: bool,
    _directory: bool,
    _issues: &mut Vec<TrustIssue>,
) {
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use crate::test_support::env_lock;

    use super::{
        EXPECTED_CONFIG_HASH_ENV, expected_config_hash, file_content_hash, hex_hash,
        verify_expected_config_hash,
    };
    #[cfg(unix)]
    use super::{
        config_trust_issues, data_path_trust_issues, existing_file_trust_issues,
        secure_config_path, write_secure_config_atomic,
    };

    #[test]
    fn expected_config_hash_validates_active_config() {
        let _guard = env_lock();
        let root = unique_dir("batman-security-config-pin");
        fs::create_dir_all(&root).unwrap();
        let config = root.join("batman.yaml");
        fs::write(&config, "file_integrity:\n  scan_paths: []\n").unwrap();
        let hash = file_content_hash(&config).unwrap();
        unsafe {
            std::env::set_var(EXPECTED_CONFIG_HASH_ENV, hex_hash(&hash));
        }

        assert_eq!(expected_config_hash().unwrap(), Some(hash));
        verify_expected_config_hash(&config).unwrap();

        fs::write(&config, "file_integrity:\n  scan_paths:\n    - /\n").unwrap();
        let error = verify_expected_config_hash(&config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("BATMAN_EXPECTED_CONFIG_HASH mismatch"));

        unsafe {
            std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expected_config_hash_rejects_invalid_hex() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var(EXPECTED_CONFIG_HASH_ENV, "not-a-hash");
        }

        let error = expected_config_hash().unwrap_err().to_string();
        assert!(error.contains("64-character hex-encoded"));

        unsafe {
            std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
        }
    }

    #[cfg(unix)]
    #[test]
    fn secure_config_path_sets_private_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-security");
        let dir = root.join("etc").join("batman");
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("batman.yaml");
        fs::write(&config, "file_integrity:\n  scan_paths: []\n").unwrap();

        secure_config_path(&config).unwrap();

        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_config_write_replaces_content_and_keeps_private_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-security-atomic");
        let config = root.join("etc").join("batman").join("batman.yaml");

        write_secure_config_atomic(&config, "file_integrity:\n  scan_paths: []\n").unwrap();
        write_secure_config_atomic(&config, "file_integrity:\n  scan_paths:\n    - /\n").unwrap();

        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            "file_integrity:\n  scan_paths:\n    - /\n"
        );
        assert_eq!(
            fs::metadata(config.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let leftovers = fs::read_dir(config.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_trust_rejects_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-security-world");
        fs::create_dir_all(&root).unwrap();
        let config = root.join("batman.yaml");
        fs::write(&config, "file_integrity:\n  scan_paths: []\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();

        let issues = config_trust_issues(&config, false);

        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("group/world writable"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_path_trust_rejects_world_writable_database_directory() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-data-security-world");
        let db = root.join("db");
        fs::create_dir_all(&db).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o777)).unwrap();

        let issues = data_path_trust_issues(&db, false);

        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("group/world writable"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_path_trust_allows_missing_baseline_files() {
        let root = unique_dir("batman-data-security-empty");
        let db = root.join("db");
        fs::create_dir_all(&db).unwrap();

        let issues = data_path_trust_issues(&db, false);

        assert!(!issues.iter().any(|issue| {
            issue
                .path
                .file_name()
                .is_some_and(|name| name == "baseline.bfi")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_path_trust_rejects_world_writable_baseline_files() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-data-security-file-world");
        let db = root.join("db");
        fs::create_dir_all(&db).unwrap();
        let record = db.join("baseline.bfi");
        fs::write(&record, "baseline").unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o666)).unwrap();

        let issues = data_path_trust_issues(&db, false);

        assert!(issues.iter().any(|issue| {
            issue.path == record && issue.message.contains("group/world writable")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_path_trust_rejects_world_writable_baseline_temp_files() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-data-security-tmp-world");
        let db = root.join("db");
        fs::create_dir_all(&db).unwrap();
        let tmp = db.join("baseline.idx.tmp");
        fs::write(&tmp, "partial index").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o666)).unwrap();

        let issues = data_path_trust_issues(&db, false);

        assert!(
            issues
                .iter()
                .any(|issue| issue.path == tmp && issue.message.contains("group/world writable"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn data_path_trust_rejects_world_writable_audit_log() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-data-security-audit-world");
        let db = root.join("db");
        fs::create_dir_all(&db).unwrap();
        let audit = db.join("audit.log");
        fs::write(&audit, "audit").unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o666)).unwrap();

        let issues = data_path_trust_issues(&db, false);

        assert!(issues.iter().any(|issue| {
            issue.path == audit && issue.message.contains("group/world writable")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_trust_rejects_world_writable_scheduler_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_dir("batman-security-scheduler-world");
        fs::create_dir_all(&root).unwrap();
        let service = root.join("batman-scan.service");
        fs::write(&service, "[Service]\nExecStart=/usr/bin/batman scan\n").unwrap();
        fs::set_permissions(&service, fs::Permissions::from_mode(0o666)).unwrap();

        let issues = existing_file_trust_issues(&service, false);

        assert!(issues.iter().any(|issue| {
            issue.path == service && issue.message.contains("group/world writable")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
