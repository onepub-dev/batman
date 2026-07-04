mod batman_config;
pub mod local_settings;
mod simple_yaml;

pub use batman_config::{BatmanConfig, EmailConfig, FileIntegrityConfig, default_max_scan_threads};
pub use local_settings::LocalSettings;
