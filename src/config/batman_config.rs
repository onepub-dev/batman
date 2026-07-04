use std::path::{Path, PathBuf};

use crate::config::local_settings::expand_home;
use crate::config::simple_yaml::SimpleYaml;
use crate::errors::{BatmanError, BatmanResult};

const DEFAULT_BASELINE_DIR: &str = "baseline";

#[derive(Clone, Debug)]
pub struct BatmanConfig {
    pub file_integrity: FileIntegrityConfig,
    pub email: EmailConfig,
}

#[derive(Clone, Debug)]
pub struct FileIntegrityConfig {
    pub scan_byte_limit: u64,
    pub scan_threads: usize,
    pub scan_buffer_size: usize,
    pub baseline_public_key: Option<String>,
    pub db_path: PathBuf,
    pub scan_paths: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub excluded_filesystems: Vec<String>,
    pub metadata_directories: Vec<PathBuf>,
    pub metadata_only: Vec<PathBuf>,
    pub registry_paths: Vec<String>,
    pub settings_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct EmailConfig {
    pub send_on_fail: bool,
    pub send_on_success: bool,
    pub server_host: String,
    pub server_port: u16,
    pub from_address: String,
    pub fail_to_address: String,
    pub success_to_address: String,
}

impl BatmanConfig {
    pub fn load(config_path: &Path, settings_dir: &Path) -> BatmanResult<Self> {
        if !config_path.exists() {
            return Err(BatmanError::Config(format!(
                "config file {} does not exist; run 'batman install' first",
                config_path.display()
            )));
        }

        let yaml = SimpleYaml::load(config_path)?;
        let db_path = yaml
            .scalar("db_path")
            .or_else(|| yaml.scalar("file_integrity.db_path"))
            .map(|value| expand_home(Path::new(value)))
            .unwrap_or_else(|| settings_dir.join(DEFAULT_BASELINE_DIR));

        let metadata_rules = yaml.list("file_integrity.metadata_only");
        let (metadata_directories, metadata_only) = parse_metadata_only_rules(metadata_rules);

        let file_integrity = FileIntegrityConfig {
            scan_byte_limit: yaml.usize("file_integrity.scan_byte_limit", 0) as u64,
            scan_threads: yaml
                .usize("file_integrity.scan_threads", default_scan_threads())
                .max(1),
            scan_buffer_size: yaml
                .usize(
                    "file_integrity.scan_buffer_size",
                    default_scan_buffer_size(),
                )
                .max(4 * 1024),
            baseline_public_key: yaml
                .scalar("file_integrity.baseline_public_key")
                .or_else(|| yaml.scalar("baseline_public_key"))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            db_path,
            scan_paths: yaml
                .list("file_integrity.scan_paths")
                .into_iter()
                .map(|path| expand_home(Path::new(&path)))
                .collect(),
            exclusions: yaml
                .list("file_integrity.exclusions")
                .into_iter()
                .map(|path| expand_home(Path::new(&path)))
                .collect(),
            excluded_filesystems: if yaml.has_list("file_integrity.excluded_filesystems") {
                yaml.list("file_integrity.excluded_filesystems")
            } else {
                default_excluded_filesystems()
            },
            metadata_directories,
            metadata_only,
            registry_paths: yaml.list("file_integrity.registry_paths"),
            settings_dir: settings_dir.to_path_buf(),
        };

        let email = EmailConfig {
            send_on_fail: yaml.bool("send_email_on_fail", false),
            send_on_success: yaml.bool(
                "send_email_on_success",
                yaml.bool("report_on_success", false),
            ),
            server_host: yaml
                .scalar("email_server_host")
                .unwrap_or("localhost")
                .to_string(),
            server_port: yaml.usize("email_server_port", 25) as u16,
            from_address: yaml.scalar("email_from_address").unwrap_or("").to_string(),
            fail_to_address: yaml
                .scalar("email_fail_to_address")
                .or_else(|| yaml.scalar("report_to"))
                .unwrap_or("")
                .to_string(),
            success_to_address: yaml
                .scalar("email_success_to_address")
                .unwrap_or("")
                .to_string(),
        };

        Ok(Self {
            file_integrity,
            email,
        })
    }
}

fn default_scan_threads() -> usize {
    default_max_scan_threads()
}

pub fn default_max_scan_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_sub(2)
        .clamp(1, 4)
}

fn default_scan_buffer_size() -> usize {
    64 * 1024
}

fn default_excluded_filesystems() -> Vec<String> {
    if cfg!(target_os = "linux") {
        [
            "autofs",
            "bpf",
            "cgroup",
            "cgroup2",
            "configfs",
            "debugfs",
            "devpts",
            "devtmpfs",
            "efivarfs",
            "fuse.gvfsd-fuse",
            "fuse.portal",
            "mqueue",
            "proc",
            "pstore",
            "securityfs",
            "squashfs",
            "sysfs",
            "tracefs",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    }
}

impl FileIntegrityConfig {
    pub fn is_excluded(&self, path: &Path) -> bool {
        path.starts_with(&self.db_path)
            || self
                .exclusions
                .iter()
                .any(|exclusion| path.starts_with(exclusion))
    }

    pub fn is_metadata_only(&self, path: &Path) -> bool {
        self.is_metadata_directory(path)
            || self
                .metadata_only
                .iter()
                .any(|metadata_only| path.starts_with(metadata_only))
    }

    pub fn is_metadata_directory(&self, path: &Path) -> bool {
        self.metadata_directories
            .iter()
            .any(|metadata_directory| path == metadata_directory)
    }

    pub fn is_filesystem_excluded(&self, fs_type: &str) -> bool {
        self.excluded_filesystems
            .iter()
            .any(|excluded| excluded == fs_type)
    }
}

fn parse_metadata_only_rules(values: Vec<String>) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut metadata_directories = Vec::new();
    let mut metadata_only = Vec::new();

    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Some(path) = strip_recursive_suffix(value) {
            metadata_only.push(expand_home(Path::new(path)));
        } else if let Some(path) = strip_directory_suffix(value) {
            metadata_directories.push(expand_home(Path::new(path)));
        } else {
            metadata_only.push(expand_home(Path::new(value)));
        }
    }

    (metadata_directories, metadata_only)
}

fn strip_recursive_suffix(value: &str) -> Option<&str> {
    value
        .strip_suffix("/*")
        .or_else(|| value.strip_suffix("\\*"))
        .filter(|path| !path.is_empty())
}

fn strip_directory_suffix(value: &str) -> Option<&str> {
    if value == "/" || is_windows_drive_root(value) {
        return Some(value);
    }
    value
        .strip_suffix('/')
        .or_else(|| value.strip_suffix('\\'))
        .filter(|path| !path.is_empty())
}

fn is_windows_drive_root(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 3
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
        && bytes[0].is_ascii_alphabetic()
}
