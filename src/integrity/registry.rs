use crate::config::FileIntegrityConfig;
use crate::errors::BatmanResult;
use crate::integrity::parallel_scanner::ScannedFile;
#[cfg(windows)]
use crate::integrity::store::{FileMetadata, META_SPECIAL};

#[cfg(not(windows))]
pub fn scan_registry_paths<F>(_config: &FileIntegrityConfig, _on_entry: F) -> BatmanResult<()>
where
    F: FnMut(ScannedFile) -> BatmanResult<()>,
{
    Ok(())
}

#[cfg(windows)]
pub fn scan_registry_paths<F>(config: &FileIntegrityConfig, mut on_entry: F) -> BatmanResult<()>
where
    F: FnMut(ScannedFile) -> BatmanResult<()>,
{
    for path in &config.registry_paths {
        windows_registry::scan_path(path, &mut on_entry)?;
    }
    Ok(())
}

#[cfg(windows)]
mod windows_registry {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW,
        RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    };

    use super::*;
    use crate::errors::{BatmanError, BatmanResult};

    const DEFAULT_NAME: &str = "(default)";
    const MAX_ENUM_NAME_CHARS: usize = 16 * 1024;
    const HUNDRED_NS_PER_SECOND: i128 = 10_000_000;
    const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;

    pub fn scan_path<F>(path: &str, on_entry: &mut F) -> BatmanResult<()>
    where
        F: FnMut(ScannedFile) -> BatmanResult<()>,
    {
        let Some(root) = RegistryRoot::parse(path) else {
            return Err(BatmanError::Config(format!(
                "invalid registry path {path}; expected HKLM\\Software style path"
            )));
        };
        let mut stack = vec![root.subkey.clone()];
        while let Some(subkey) = stack.pop() {
            let key = match open_key(root.handle, &subkey) {
                Ok(key) => key,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(error) => {
                    return Err(BatmanError::io(
                        format!("open registry key {}", root.path_for(&subkey)),
                        error,
                    ));
                }
            };
            let info = match query_info(key.raw) {
                Ok(info) => info,
                Err(error) => {
                    return Err(BatmanError::io(
                        format!("query registry key {}", root.path_for(&subkey)),
                        error,
                    ));
                }
            };
            emit_key(root.alias, &subkey, &info, on_entry)?;
            enumerate_values(root.alias, &subkey, key.raw, info.values, on_entry)?;
            for child in enumerate_subkeys(key.raw, info.subkeys).map_err(|error| {
                BatmanError::io(
                    format!("enumerate registry key {}", root.path_for(&subkey)),
                    error,
                )
            })? {
                let child_path = join_subkey(&subkey, &child);
                stack.push(child_path);
            }
        }
        Ok(())
    }

    struct RegistryRoot<'a> {
        alias: &'static str,
        handle: HKEY,
        subkey: String,
        _source: &'a str,
    }

    impl RegistryRoot<'_> {
        fn parse(path: &str) -> Option<RegistryRoot<'_>> {
            let trimmed = path
                .trim()
                .strip_prefix("registry://")
                .unwrap_or(path.trim());
            let normalized = trimmed.replace('/', "\\");
            let (root, subkey) = normalized
                .split_once('\\')
                .map_or((normalized.as_str(), ""), |(root, subkey)| (root, subkey));
            let (alias, handle) = match root.to_ascii_uppercase().as_str() {
                "HKLM" | "HKEY_LOCAL_MACHINE" => ("HKLM", HKEY_LOCAL_MACHINE),
                "HKCU" | "HKEY_CURRENT_USER" => ("HKCU", HKEY_CURRENT_USER),
                "HKCR" | "HKEY_CLASSES_ROOT" => ("HKCR", HKEY_CLASSES_ROOT),
                "HKU" | "HKEY_USERS" => ("HKU", HKEY_USERS),
                "HKCC" | "HKEY_CURRENT_CONFIG" => ("HKCC", HKEY_CURRENT_CONFIG),
                _ => return None,
            };
            Some(RegistryRoot {
                alias,
                handle,
                subkey: subkey.trim_matches('\\').to_string(),
                _source: path,
            })
        }

        fn path_for(&self, subkey: &str) -> String {
            registry_key_path(self.alias, subkey)
        }
    }

    struct OwnedKey {
        raw: HKEY,
    }

    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.raw);
            }
        }
    }

    struct KeyInfo {
        subkeys: u32,
        values: u32,
        modified_ns: i128,
    }

    fn open_key(root: HKEY, subkey: &str) -> io::Result<OwnedKey> {
        let mut opened = null_mut();
        let wide = wide(subkey);
        let status = unsafe {
            RegOpenKeyExW(
                root,
                wide.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut opened,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(OwnedKey { raw: opened })
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    fn query_info(key: HKEY) -> io::Result<KeyInfo> {
        let mut subkeys = 0_u32;
        let mut values = 0_u32;
        let mut last_write = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let status = unsafe {
            RegQueryInfoKeyW(
                key,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut subkeys,
                null_mut(),
                null_mut(),
                &mut values,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut last_write,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(KeyInfo {
                subkeys,
                values,
                modified_ns: filetime_to_unix_ns(last_write),
            })
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    fn emit_key<F>(root: &str, subkey: &str, info: &KeyInfo, on_entry: &mut F) -> BatmanResult<()>
    where
        F: FnMut(ScannedFile) -> BatmanResult<()>,
    {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"batman-registry-key-v1");
        hasher.update(&info.subkeys.to_le_bytes());
        hasher.update(&info.values.to_le_bytes());
        hasher.update(&info.modified_ns.to_le_bytes());
        emit_record(
            registry_key_path(root, subkey),
            *hasher.finalize().as_bytes(),
            0,
            info.modified_ns,
            on_entry,
        )
    }

    fn enumerate_values<F>(
        root: &str,
        subkey: &str,
        key: HKEY,
        values: u32,
        on_entry: &mut F,
    ) -> BatmanResult<()>
    where
        F: FnMut(ScannedFile) -> BatmanResult<()>,
    {
        for index in 0..values {
            let Some(value) = enum_value(key, index).map_err(|error| {
                BatmanError::io(format!("enumerate registry value {subkey}"), error)
            })?
            else {
                break;
            };
            let path = registry_value_path(root, subkey, &value.name);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"batman-registry-value-v1");
            hasher.update(&value.kind.to_le_bytes());
            hasher.update(&(value.data.len() as u64).to_le_bytes());
            hasher.update(&value.data);
            emit_record(
                path,
                *hasher.finalize().as_bytes(),
                value.data.len() as u64,
                0,
                on_entry,
            )?;
        }
        Ok(())
    }

    fn enum_value(key: HKEY, index: u32) -> io::Result<Option<RegistryValue>> {
        let mut name = vec![0_u16; MAX_ENUM_NAME_CHARS];
        let mut name_len = name.len() as u32;
        let mut kind: REG_VALUE_TYPE = 0;
        let mut data_len = 0_u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut kind,
                null_mut(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut data = vec![0_u8; data_len as usize];
        name_len = name.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        name.truncate(name_len as usize);
        data.truncate(data_len as usize);
        Ok(Some(RegistryValue {
            name: if name.is_empty() {
                DEFAULT_NAME.to_string()
            } else {
                String::from_utf16_lossy(&name)
            },
            kind,
            data,
        }))
    }

    fn enumerate_subkeys(key: HKEY, subkeys: u32) -> io::Result<Vec<String>> {
        let mut output = Vec::with_capacity(subkeys.min(256) as usize);
        for index in 0..subkeys {
            let mut name = vec![0_u16; MAX_ENUM_NAME_CHARS];
            let mut name_len = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            name.truncate(name_len as usize);
            output.push(String::from_utf16_lossy(&name));
        }
        Ok(output)
    }

    struct RegistryValue {
        name: String,
        kind: REG_VALUE_TYPE,
        data: Vec<u8>,
    }

    fn emit_record<F>(
        path: String,
        checksum: [u8; 32],
        size: u64,
        modified_ns: i128,
        on_entry: &mut F,
    ) -> BatmanResult<()>
    where
        F: FnMut(ScannedFile) -> BatmanResult<()>,
    {
        on_entry(ScannedFile {
            path: PathBuf::from(path),
            checksum,
            size,
            processed_bytes: size,
            modified_ns,
            metadata: FileMetadata {
                flags: META_SPECIAL,
                size,
                permissions: 0,
                owner: 0,
                group: 0,
                modified_ns,
                created_ns: 0,
                changed_ns: 0,
                acl_hash: [0; 32],
            },
        })
    }

    fn registry_key_path(root: &str, subkey: &str) -> String {
        if subkey.is_empty() {
            format!("registry://{root}")
        } else {
            format!("registry://{root}/{}", subkey.replace('\\', "/"))
        }
    }

    fn registry_value_path(root: &str, subkey: &str, value: &str) -> String {
        format!(
            "{}#{}",
            registry_key_path(root, subkey),
            escape_value_name(value)
        )
    }

    fn escape_value_name(value: &str) -> String {
        value.replace('#', "%23").replace('/', "%2F")
    }

    fn join_subkey(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_string()
        } else {
            format!("{parent}\\{child}")
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn filetime_to_unix_ns(filetime: FILETIME) -> i128 {
        let ticks = ((filetime.dwHighDateTime as u64) << 32) | u64::from(filetime.dwLowDateTime);
        let seconds = i128::from(ticks / HUNDRED_NS_PER_SECOND as u64) - WINDOWS_TO_UNIX_SECONDS;
        let nanos = i128::from(ticks % HUNDRED_NS_PER_SECOND as u64) * 100;
        seconds * 1_000_000_000 + nanos
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::FileIntegrityConfig;

    use super::scan_registry_paths;

    #[test]
    #[cfg(not(windows))]
    fn registry_paths_are_ignored_on_non_windows() {
        let config = FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 64 * 1024,
            baseline_public_key: None,
            db_path: PathBuf::from("/tmp/batman-db"),
            scan_paths: Vec::new(),
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: vec!["HKLM\\Software".to_string()],
            settings_dir: PathBuf::from("/tmp/batman"),
        };
        let mut records = 0;
        scan_registry_paths(&config, |_| {
            records += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(records, 0);
    }
}
