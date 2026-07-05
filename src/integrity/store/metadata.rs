use std::fs::Metadata;
use std::path::Path;
use std::time::UNIX_EPOCH;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_XATTR_VALUE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub flags: u32,
    pub size: u64,
    pub permissions: u64,
    pub owner: u64,
    pub group: u64,
    pub modified_ns: i128,
    pub created_ns: i128,
    pub changed_ns: i128,
    pub acl_hash: [u8; 32],
}

pub const META_PERMISSIONS: u32 = 1 << 0;
pub const META_OWNER: u32 = 1 << 1;
pub const META_GROUP: u32 = 1 << 2;
pub const META_CREATED: u32 = 1 << 3;
pub const META_CHANGED: u32 = 1 << 4;
pub const META_ACL: u32 = 1 << 5;
pub const META_DIRECTORY: u32 = 1 << 6;
pub const META_SYMLINK: u32 = 1 << 7;
pub const META_SPECIAL: u32 = 1 << 8;
pub const META_KIND_MASK: u32 = META_DIRECTORY | META_SYMLINK | META_SPECIAL;

impl FileMetadata {
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self::from_path_and_metadata(None, metadata)
    }

    pub fn from_path_metadata(path: &Path, metadata: &Metadata) -> Self {
        Self::from_path_and_metadata(Some(path), metadata)
    }

    fn from_path_and_metadata(path: Option<&Path>, metadata: &Metadata) -> Self {
        let (mut flags, permissions, owner, group, changed_ns) = platform_metadata(metadata);
        if metadata.is_dir() {
            flags |= META_DIRECTORY;
        } else if metadata.file_type().is_symlink() {
            flags |= META_SYMLINK;
        } else if !metadata.is_file() {
            flags |= META_SPECIAL;
        }

        let created_ns = metadata
            .created()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| {
                flags |= META_CREATED;
                duration.as_nanos() as i128
            })
            .unwrap_or(0);

        let acl_hash = platform_acl_hash(path, metadata);
        if acl_hash.is_some() {
            flags |= META_ACL;
        }

        Self {
            flags,
            size: metadata.len(),
            permissions,
            owner,
            group,
            modified_ns: modified_ns(metadata),
            created_ns,
            changed_ns,
            acl_hash: acl_hash.unwrap_or([0; 32]),
        }
    }
}

#[cfg(unix)]
fn platform_metadata(metadata: &Metadata) -> (u32, u64, u64, u64, i128) {
    use std::os::unix::fs::MetadataExt;

    (
        META_PERMISSIONS | META_OWNER | META_GROUP | META_CHANGED,
        metadata.mode() as u64,
        metadata.uid() as u64,
        metadata.gid() as u64,
        i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
    )
}

#[cfg(target_os = "linux")]
fn platform_acl_hash(path: Option<&Path>, metadata: &Metadata) -> Option<[u8; 32]> {
    linux_acl_metadata_hash(path, metadata)
}

#[cfg(target_os = "macos")]
fn platform_acl_hash(path: Option<&Path>, metadata: &Metadata) -> Option<[u8; 32]> {
    unix_acl_metadata_hash(path, metadata, b"batman:macos-acl-metadata-v1")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn platform_acl_hash(_path: Option<&Path>, metadata: &Metadata) -> Option<[u8; 32]> {
    Some(unix_file_identity_hash(
        metadata,
        b"batman:unix-acl-metadata-v1",
    ))
}

#[cfg(target_os = "linux")]
fn linux_acl_metadata_hash(path: Option<&Path>, metadata: &Metadata) -> Option<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"batman:linux-acl-metadata-v1");
    hash_unix_file_identity(metadata, &mut hasher);

    if let Some(path) = path {
        match linux_inode_flags(path) {
            Ok(Some(flags)) => {
                hasher.update(b"inode-flags");
                hasher.update(&flags.to_le_bytes());
            }
            Ok(None) => {}
            Err(error) => {
                hasher.update(b"inode-flags-error");
                hasher.update(&i64::from(error.raw_os_error().unwrap_or(-1)).to_le_bytes());
                hasher.update(format!("{:?}", error.kind()).as_bytes());
            }
        }

        match list_xattrs_no_follow(path) {
            Ok(names) => {
                if names.is_empty() {
                    hasher.update(b"xattrs-empty");
                } else {
                    hash_xattrs(path, names, &mut hasher);
                }
            }
            Err(error) => {
                hash_xattr_collection_error("list", &error, &mut hasher);
            }
        }
    }

    Some(*hasher.finalize().as_bytes())
}

#[cfg(target_os = "macos")]
fn unix_acl_metadata_hash(
    path: Option<&Path>,
    metadata: &Metadata,
    domain: &[u8],
) -> Option<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_unix_file_identity(metadata, &mut hasher);
    let Some(path) = path else {
        return Some(*hasher.finalize().as_bytes());
    };
    match list_xattrs_no_follow(path) {
        Ok(names) => {
            if names.is_empty() {
                hasher.update(b"xattrs-empty");
            } else {
                hash_xattrs(path, names, &mut hasher);
            }
        }
        Err(error) => {
            hash_xattr_collection_error("list", &error, &mut hasher);
        }
    }
    Some(*hasher.finalize().as_bytes())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn unix_file_identity_hash(metadata: &Metadata, domain: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_unix_file_identity(metadata, &mut hasher);
    *hasher.finalize().as_bytes()
}

#[cfg(unix)]
fn hash_unix_file_identity(metadata: &Metadata, hasher: &mut blake3::Hasher) {
    use std::os::unix::fs::MetadataExt;

    hasher.update(b"unix-file-identity");
    hasher.update(&metadata.dev().to_le_bytes());
    hasher.update(&metadata.ino().to_le_bytes());
    if !metadata.is_dir() {
        hasher.update(b"nlink");
        hasher.update(&metadata.nlink().to_le_bytes());
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn hash_xattrs(path: &Path, names: Vec<Vec<u8>>, hasher: &mut blake3::Hasher) {
    hasher.update(b"xattrs");
    for name in names {
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(&name);
        match get_xattr_no_follow(path, &name) {
            Ok(value) => {
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(&value);
            }
            Err(error) => {
                hasher.update(b"batman:xattr-value-error");
                hasher.update(&u64::MAX.to_le_bytes());
                hasher.update(&i64::from(error.raw_os_error().unwrap_or(-1)).to_le_bytes());
                hasher.update(format!("{:?}", error.kind()).as_bytes());
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
fn xattr_collection_error_hash(phase: &str, error: &std::io::Error) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_xattr_collection_error(phase, error, &mut hasher);
    *hasher.finalize().as_bytes()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn hash_xattr_collection_error(phase: &str, error: &std::io::Error, hasher: &mut blake3::Hasher) {
    hasher.update(b"batman:xattr-collection-error-v1");
    hasher.update(phase.as_bytes());
    hasher.update(&i64::from(error.raw_os_error().unwrap_or(-1)).to_le_bytes());
    hasher.update(format!("{:?}", error.kind()).as_bytes());
}

#[cfg(target_os = "linux")]
pub const LINUX_IMMUTABLE_FL: u32 = 0x0000_0010;
#[cfg(target_os = "linux")]
pub const LINUX_APPEND_FL: u32 = 0x0000_0020;

#[cfg(target_os = "linux")]
pub fn linux_inode_flags(path: &Path) -> std::io::Result<Option<u32>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(error) => return Err(error),
    };

    let mut flags: libc::c_long = 0;
    let result = unsafe { libc::ioctl(file.as_raw_fd(), fs_ioc_getflags(), &mut flags) };
    if result == 0 {
        return Ok(Some(flags as u32));
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EINVAL) => Ok(None),
        _ => Err(error),
    }
}

#[cfg(target_os = "linux")]
const fn fs_ioc_getflags() -> libc::c_ulong {
    ior(b'f' as u32, 1, std::mem::size_of::<libc::c_long>())
}

#[cfg(target_os = "linux")]
const fn ior(kind: u32, number: u32, size: usize) -> libc::c_ulong {
    ioc(IOC_READ, kind, number, size)
}

#[cfg(target_os = "linux")]
const fn ioc(direction: u32, kind: u32, number: u32, size: usize) -> libc::c_ulong {
    ((direction as libc::c_ulong) << IOC_DIRSHIFT)
        | ((kind as libc::c_ulong) << IOC_TYPESHIFT)
        | ((number as libc::c_ulong) << IOC_NRSHIFT)
        | ((size as libc::c_ulong) << IOC_SIZESHIFT)
}

#[cfg(target_os = "linux")]
const IOC_NRBITS: u32 = 8;
#[cfg(target_os = "linux")]
const IOC_TYPEBITS: u32 = 8;
#[cfg(target_os = "linux")]
const IOC_SIZEBITS: u32 = 14;
#[cfg(target_os = "linux")]
const IOC_NRSHIFT: u32 = 0;
#[cfg(target_os = "linux")]
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
#[cfg(target_os = "linux")]
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
#[cfg(target_os = "linux")]
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
#[cfg(target_os = "linux")]
const IOC_READ: u32 = 2;

#[cfg(target_os = "linux")]
fn list_xattrs_no_follow(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid_xattr_input)?;
    let len = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if len <= 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0_u8; len as usize];
    let len = unsafe { libc::llistxattr(path.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(split_xattr_names(&buffer[..len as usize]))
}

#[cfg(target_os = "linux")]
fn get_xattr_no_follow(path: &Path, name: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid_xattr_input)?;
    let name = CString::new(name).map_err(invalid_xattr_input)?;
    let len = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize > MAX_XATTR_VALUE_BYTES {
        return Ok(format!("batman:xattr-too-large:{len}").into_bytes());
    }
    let mut buffer = vec![0_u8; len as usize];
    let len = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

#[cfg(target_os = "macos")]
fn list_xattrs_no_follow(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid_xattr_input)?;
    let len =
        unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0, libc::XATTR_NOFOLLOW) };
    if len <= 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0_u8; len as usize];
    let len = unsafe {
        libc::listxattr(
            path.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(split_xattr_names(&buffer[..len as usize]))
}

#[cfg(target_os = "macos")]
fn get_xattr_no_follow(path: &Path, name: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid_xattr_input)?;
    let name = CString::new(name).map_err(invalid_xattr_input)?;
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize > MAX_XATTR_VALUE_BYTES {
        return Ok(format!("batman:xattr-too-large:{len}").into_bytes());
    }
    let mut buffer = vec![0_u8; len as usize];
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn split_xattr_names(buffer: &[u8]) -> Vec<Vec<u8>> {
    let mut names = buffer
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_vec())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invalid_xattr_input(error: std::ffi::NulError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
}

#[cfg(windows)]
fn platform_metadata(metadata: &Metadata) -> (u32, u64, u64, u64, i128) {
    use std::os::windows::fs::MetadataExt;

    (META_PERMISSIONS, metadata.file_attributes() as u64, 0, 0, 0)
}

#[cfg(windows)]
fn platform_acl_hash(path: Option<&Path>, _metadata: &Metadata) -> Option<[u8; 32]> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null_mut, slice_from_raw_parts};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let path = path?;
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide_path.push(0);

    let security_info =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();

    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            security_info,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 || security_descriptor.is_null() {
        return None;
    }

    let mut sddl: *mut u16 = null_mut();
    let mut sddl_len = 0_u32;
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            1,
            security_info,
            &mut sddl,
            &mut sddl_len,
        )
    };

    let hash = if converted != 0 && !sddl.is_null() {
        let bytes = unsafe {
            let wide = &*slice_from_raw_parts(sddl, sddl_len as usize);
            std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2)
        };
        Some(*blake3::hash(bytes).as_bytes())
    } else {
        None
    };

    if !sddl.is_null() {
        unsafe {
            LocalFree(sddl.cast::<c_void>());
        }
    }
    unsafe {
        LocalFree(security_descriptor.cast::<c_void>());
    }

    hash
}

#[cfg(not(any(unix, windows)))]
fn platform_metadata(metadata: &Metadata) -> (u32, u64, u64, u64, i128) {
    (
        META_PERMISSIONS,
        u64::from(metadata.permissions().readonly()),
        0,
        0,
        0,
    )
}

#[cfg(not(any(unix, windows)))]
fn platform_acl_hash(_path: Option<&Path>, _metadata: &Metadata) -> Option<[u8; 32]> {
    None
}

pub fn modified_ns(metadata: &Metadata) -> i128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{FileMetadata, META_ACL};

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fs_ioc_getflags_constant_matches_header_value() {
        if std::mem::size_of::<libc::c_long>() == 8 {
            assert_eq!(super::fs_ioc_getflags(), 0x8008_6601);
        } else {
            assert_eq!(super::fs_ioc_getflags(), 0x8004_6601);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_inode_flags_are_included_in_acl_hash_when_supported() {
        let root = unique_dir("batman-inode-flags");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file.txt");
        fs::write(&path, "content").unwrap();

        if super::linux_inode_flags(&path).unwrap().is_none() {
            fs::remove_dir_all(root).unwrap();
            return;
        }

        let metadata = fs::symlink_metadata(&path).unwrap();
        let file = FileMetadata::from_path_metadata(&path, &metadata);
        assert!(file.flags & META_ACL != 0);
        assert_ne!(file.acl_hash, [0; 32]);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn xattr_collection_errors_have_stable_distinct_hashes() {
        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let missing = std::io::Error::from_raw_os_error(libc::ENOENT);

        let first = super::xattr_collection_error_hash("list", &denied);
        let repeated = super::xattr_collection_error_hash("list", &denied);
        let different_phase = super::xattr_collection_error_hash("value", &denied);
        let different_error = super::xattr_collection_error_hash("list", &missing);

        assert_eq!(first, repeated);
        assert_ne!(first, different_phase);
        assert_ne!(first, different_error);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_xattrs_are_included_in_acl_hash() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = unique_dir("batman-xattr");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file.txt");
        fs::write(&path, "content").unwrap();

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new("user.batman.test").unwrap();
        let value = b"one";
        let status = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if status != 0 {
            fs::remove_dir_all(root).unwrap();
            return;
        }

        let metadata = fs::symlink_metadata(&path).unwrap();
        let first = FileMetadata::from_path_metadata(&path, &metadata);
        assert!(first.flags & META_ACL != 0);

        let value = b"two";
        let status = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        assert_eq!(status, 0);
        let second = FileMetadata::from_path_metadata(&path, &metadata);
        assert_ne!(first.acl_hash, second.acl_hash);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_hard_link_count_is_included_for_files() {
        let root = unique_dir("batman-hardlink-metadata");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file.txt");
        let link = root.join("linked.txt");
        fs::write(&path, "content").unwrap();

        let before_metadata = fs::symlink_metadata(&path).unwrap();
        let before = FileMetadata::from_path_metadata(&path, &before_metadata);
        fs::hard_link(&path, &link).unwrap();
        let after_metadata = fs::symlink_metadata(&path).unwrap();
        let after = FileMetadata::from_path_metadata(&path, &after_metadata);

        assert!(before.flags & META_ACL != 0);
        assert!(after.flags & META_ACL != 0);
        assert_ne!(before.acl_hash, after.acl_hash);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_directory_child_churn_does_not_change_identity_hash() {
        let root = unique_dir("batman-directory-metadata");
        let dir = root.join("watched");
        fs::create_dir_all(&dir).unwrap();

        let before_metadata = fs::symlink_metadata(&dir).unwrap();
        let before = FileMetadata::from_path_metadata(&dir, &before_metadata);
        fs::write(dir.join("child.txt"), "content").unwrap();
        let after_metadata = fs::symlink_metadata(&dir).unwrap();
        let after = FileMetadata::from_path_metadata(&dir, &after_metadata);

        assert!(before.flags & META_ACL != 0);
        assert!(after.flags & META_ACL != 0);
        assert_eq!(before.acl_hash, after.acl_hash);

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
