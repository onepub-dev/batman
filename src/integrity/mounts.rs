use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::FileIntegrityConfig;

#[derive(Clone, Debug, Default)]
pub struct MountTable {
    mounts: Vec<MountInfo>,
    by_mountpoint: HashMap<PathBuf, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountScanRisk {
    pub mountpoint: PathBuf,
    pub fs_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfo {
    mountpoint: PathBuf,
    fs_type: String,
}

impl MountTable {
    pub fn current() -> Self {
        current_mount_table()
    }

    pub fn path_is_on_excluded_fs(&self, config: &FileIntegrityConfig, path: &Path) -> bool {
        self.fs_type_for_path(path)
            .map(|fs_type| config.is_filesystem_excluded(fs_type))
            .unwrap_or(false)
    }

    pub fn mountpoint_is_excluded(&self, config: &FileIntegrityConfig, path: &Path) -> bool {
        self.by_mountpoint
            .get(path)
            .map(|fs_type| config.is_filesystem_excluded(fs_type))
            .unwrap_or(false)
    }

    pub fn risky_included_mountpoints(&self, config: &FileIntegrityConfig) -> Vec<MountScanRisk> {
        self.mounts
            .iter()
            .filter(|mount| mount_reachable_from_scan_paths(config, &mount.mountpoint))
            .filter(|mount| high_overhead_filesystem(&mount.fs_type))
            .filter(|mount| !config.is_excluded(&mount.mountpoint))
            .filter(|mount| !config.is_filesystem_excluded(&mount.fs_type))
            .map(|mount| MountScanRisk {
                mountpoint: mount.mountpoint.clone(),
                fs_type: mount.fs_type.clone(),
            })
            .collect()
    }

    pub fn fs_type_for_path(&self, path: &Path) -> Option<&str> {
        self.mounts
            .iter()
            .find(|mount| path.starts_with(&mount.mountpoint))
            .map(|mount| mount.fs_type.as_str())
    }

    #[cfg(any(target_os = "linux", test))]
    fn from_mountinfo(content: &str) -> Self {
        let mut mounts = content
            .lines()
            .filter_map(parse_mountinfo_line)
            .collect::<Vec<_>>();
        mounts.sort_by(|left, right| {
            right
                .mountpoint
                .components()
                .count()
                .cmp(&left.mountpoint.components().count())
        });
        let by_mountpoint = mounts
            .iter()
            .map(|mount| (mount.mountpoint.clone(), mount.fs_type.clone()))
            .collect();
        Self {
            mounts,
            by_mountpoint,
        }
    }
}

fn mount_reachable_from_scan_paths(config: &FileIntegrityConfig, mountpoint: &Path) -> bool {
    config
        .scan_paths
        .iter()
        .any(|scan_path| mountpoint.starts_with(scan_path) || scan_path.starts_with(mountpoint))
}

fn high_overhead_filesystem(fs_type: &str) -> bool {
    matches!(
        fs_type,
        "autofs"
            | "bpf"
            | "cgroup"
            | "cgroup2"
            | "configfs"
            | "debugfs"
            | "devpts"
            | "devtmpfs"
            | "efivarfs"
            | "fuse.gvfsd-fuse"
            | "fuse.portal"
            | "mqueue"
            | "proc"
            | "pstore"
            | "securityfs"
            | "squashfs"
            | "sysfs"
            | "tracefs"
    )
}

#[cfg(target_os = "linux")]
fn current_mount_table() -> MountTable {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|content| MountTable::from_mountinfo(&content))
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn current_mount_table() -> MountTable {
    MountTable::default()
}

#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo_line(line: &str) -> Option<MountInfo> {
    let (mount_fields, fs_fields) = line.split_once(" - ")?;
    let mountpoint = mount_fields.split_whitespace().nth(4)?;
    let fs_type = fs_fields.split_whitespace().next()?;
    Some(MountInfo {
        mountpoint: PathBuf::from(decode_mount_field(mountpoint)),
        fs_type: fs_type.to_string(),
    })
}

#[cfg(any(target_os = "linux", test))]
fn decode_mount_field(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let octal = [chars.next(), chars.next(), chars.next()];
        if let [Some(first), Some(second), Some(third)] = octal
            && let Ok(byte) = u8::from_str_radix(&format!("{first}{second}{third}"), 8)
        {
            decoded.push(byte as char);
            continue;
        }

        decoded.push('\\');
        for ch in octal.into_iter().flatten() {
            decoded.push(ch);
        }
    }
    decoded
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{MountTable, decode_mount_field};

    #[test]
    fn decodes_mountinfo_octal_escapes() {
        assert_eq!(decode_mount_field("/media/My\\040Disk"), "/media/My Disk");
        assert_eq!(
            decode_mount_field("/path/with\\134slash"),
            "/path/with\\slash"
        );
    }

    #[test]
    fn selects_most_specific_mountpoint() {
        let table = MountTable::from_mountinfo(
            "24 20 0:22 / / rw - ext4 /dev/root rw\n\
             25 24 7:1 / /snap/app/1 ro - squashfs /dev/loop1 ro\n\
             26 24 0:23 / /run rw - tmpfs tmpfs rw\n",
        );

        assert_eq!(
            table.fs_type_for_path(Path::new("/etc/passwd")),
            Some("ext4")
        );
        assert_eq!(
            table.fs_type_for_path(Path::new("/snap/app/1/bin/tool")),
            Some("squashfs")
        );
        assert_eq!(
            table.fs_type_for_path(Path::new("/run/lock")),
            Some("tmpfs")
        );
    }

    #[test]
    fn exact_mountpoint_checks_do_not_scan_prefixes() {
        let table = MountTable::from_mountinfo(
            "24 20 0:22 / / rw - ext4 /dev/root rw\n\
             25 24 7:1 / /snap/app/1 ro - squashfs /dev/loop1 ro\n",
        );

        let mut config = crate::config::FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 64 * 1024,
            baseline_public_key: None,
            db_path: "/tmp/batman-db".into(),
            scan_paths: Vec::new(),
            exclusions: Vec::new(),
            excluded_filesystems: vec!["squashfs".to_string()],
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: "/tmp".into(),
        };

        assert!(table.mountpoint_is_excluded(&config, Path::new("/snap/app/1")));
        assert!(!table.mountpoint_is_excluded(&config, Path::new("/snap/app/1/bin")));
        assert!(table.path_is_on_excluded_fs(&config, Path::new("/snap/app/1/bin")));

        config.excluded_filesystems.clear();
        assert!(!table.mountpoint_is_excluded(&config, Path::new("/snap/app/1")));
    }

    #[test]
    fn reports_high_overhead_mountpoints_that_config_would_scan() {
        let table = MountTable::from_mountinfo(
            "24 20 0:22 / / rw - ext4 /dev/root rw\n\
             25 24 7:1 / /snap/app/1 ro - squashfs /dev/loop1 ro\n\
             26 24 0:23 / /run rw - tmpfs tmpfs rw\n",
        );
        let mut config = crate::config::FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: 1,
            scan_buffer_size: 64 * 1024,
            baseline_public_key: None,
            db_path: "/tmp/batman-db".into(),
            scan_paths: vec!["/".into()],
            exclusions: Vec::new(),
            excluded_filesystems: Vec::new(),
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: "/tmp".into(),
        };

        let risks = table.risky_included_mountpoints(&config);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].mountpoint, Path::new("/snap/app/1"));
        assert_eq!(risks[0].fs_type, "squashfs");

        config.excluded_filesystems = vec!["squashfs".to_string()];
        assert!(table.risky_included_mountpoints(&config).is_empty());

        config.excluded_filesystems.clear();
        config.exclusions = vec!["/snap".into()];
        assert!(table.risky_included_mountpoints(&config).is_empty());
    }
}
