#![allow(clippy::items_after_test_module)]

use std::env;
use std::path::{Path, PathBuf};

use crate::errors::{BatmanError, BatmanResult};
use crate::system::is_privileged;

#[derive(Clone, Debug)]
pub struct LocalSettings {
    pub config_path: PathBuf,
    pub config_path_source: String,
    pub default_db_path: PathBuf,
    pub system_config_path: PathBuf,
    pub user_config_path: PathBuf,
}

impl LocalSettings {
    pub fn load(config_path_override: Option<&Path>) -> BatmanResult<Self> {
        let defaults = DefaultPaths::new()?;
        if let Some(config_path) = config_path_override {
            return Ok(Self::explicit(
                expand_home(config_path),
                "--config",
                defaults,
            ));
        }
        if let Some(config_path) = env_config_path("BATMAN_CONFIG") {
            return Ok(Self::explicit(config_path, "BATMAN_CONFIG", defaults));
        }

        for candidate in defaults.existing_candidates() {
            if candidate.path.exists() {
                return Ok(Self {
                    config_path: candidate.path,
                    config_path_source: candidate.source,
                    default_db_path: candidate.default_db_path,
                    system_config_path: defaults.system_config_path,
                    user_config_path: defaults.user_config_path,
                });
            }
        }

        let (config_path, source, default_db_path) = if is_privileged() {
            (
                defaults.system_config_path.clone(),
                "default system location".to_string(),
                defaults.system_db_path.clone(),
            )
        } else {
            (
                defaults.user_config_path.clone(),
                "default user location".to_string(),
                defaults.user_db_path.clone(),
            )
        };

        Ok(Self {
            config_path,
            config_path_source: source,
            default_db_path,
            system_config_path: defaults.system_config_path,
            user_config_path: defaults.user_config_path,
        })
    }

    pub fn for_config_path(config_path: PathBuf) -> Self {
        let config_dir = config_parent_or_current(&config_path);
        Self {
            config_path,
            config_path_source: "test fixture".to_string(),
            default_db_path: config_dir.join("baseline"),
            system_config_path: PathBuf::from("/etc/batman/batman.yaml"),
            user_config_path: config_dir.join("batman.yaml"),
        }
    }

    fn explicit(config_path: PathBuf, source: impl Into<String>, defaults: DefaultPaths) -> Self {
        let config_dir = config_parent_or_current(&config_path);
        Self {
            config_path,
            config_path_source: source.into(),
            default_db_path: config_dir.join("baseline"),
            system_config_path: defaults.system_config_path,
            user_config_path: defaults.user_config_path,
        }
    }

    pub fn settings_dir(&self) -> PathBuf {
        config_parent_or_current(&self.config_path)
    }
}

fn config_parent_or_current(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

struct DefaultPaths {
    system_config_path: PathBuf,
    system_db_path: PathBuf,
    user_config_path: PathBuf,
    user_db_path: PathBuf,
}

struct Candidate {
    path: PathBuf,
    source: String,
    default_db_path: PathBuf,
}

impl DefaultPaths {
    fn new() -> BatmanResult<Self> {
        let user_home = user_home_dir()?;
        Ok(Self {
            system_config_path: system_config_dir().join("batman.yaml"),
            system_db_path: system_data_dir().join("baseline"),
            user_config_path: user_config_dir(&user_home).join("batman.yaml"),
            user_db_path: user_data_dir(&user_home).join("baseline"),
        })
    }

    fn existing_candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        if is_privileged() {
            candidates.push(Candidate {
                path: self.system_config_path.clone(),
                source: "default system location".to_string(),
                default_db_path: self.system_db_path.clone(),
            });
        }
        candidates.push(Candidate {
            path: self.user_config_path.clone(),
            source: "default user location".to_string(),
            default_db_path: self.user_db_path.clone(),
        });
        if !is_privileged() {
            candidates.push(Candidate {
                path: self.system_config_path.clone(),
                source: "default system location".to_string(),
                default_db_path: self.system_db_path.clone(),
            });
        }
        candidates
    }
}

fn env_config_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(|value| expand_home(Path::new(&value)))
}

pub fn user_home_dir() -> BatmanResult<PathBuf> {
    sudo_home_dir()
        .or_else(home_from_environment)
        .ok_or_else(|| BatmanError::Config("unable to determine user home directory".to_string()))
}

fn home_from_environment() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(unix)]
fn sudo_home_dir() -> Option<PathBuf> {
    if !is_privileged() {
        return None;
    }
    let user = env::var("SUDO_USER").ok()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    home_from_passwd(&user)
}

#[cfg(not(unix))]
fn sudo_home_dir() -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn home_from_passwd(user: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        if name != user {
            return None;
        }
        let _password = fields.next()?;
        let _uid = fields.next()?;
        let _gid = fields.next()?;
        let _gecos = fields.next()?;
        fields.next().map(PathBuf::from)
    })
}

pub fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return user_home_dir().unwrap_or_else(|_| PathBuf::from("~"));
    }
    if let Some(rest) = text.strip_prefix("~/") {
        return user_home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|_| path.to_path_buf());
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::LocalSettings;

    #[test]
    fn bare_relative_config_path_uses_current_directory_as_settings_dir() {
        let settings = LocalSettings::for_config_path(PathBuf::from("batman.yaml"));

        assert_eq!(settings.settings_dir(), PathBuf::from("."));
        assert_eq!(settings.default_db_path, PathBuf::from("./baseline"));
    }
}

#[cfg(target_os = "windows")]
fn system_config_dir() -> PathBuf {
    env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Batman")
}

#[cfg(target_os = "windows")]
fn system_data_dir() -> PathBuf {
    system_config_dir()
}

#[cfg(target_os = "macos")]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/Batman")
}

#[cfg(target_os = "macos")]
fn system_data_dir() -> PathBuf {
    system_config_dir()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc/batman")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/batman")
}

#[cfg(target_os = "windows")]
fn user_config_dir(home: &Path) -> PathBuf {
    env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData").join("Roaming"))
        .join("Batman")
}

#[cfg(target_os = "windows")]
fn user_data_dir(home: &Path) -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData").join("Local"))
        .join("Batman")
}

#[cfg(target_os = "macos")]
fn user_config_dir(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Batman")
}

#[cfg(target_os = "macos")]
fn user_data_dir(home: &Path) -> PathBuf {
    user_config_dir(home)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn user_config_dir(home: &Path) -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("batman")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn user_data_dir(home: &Path) -> PathBuf {
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local").join("share"))
        .join("batman")
}
