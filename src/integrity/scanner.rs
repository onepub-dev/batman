use std::fs;
use std::path::Path;

use crate::config::FileIntegrityConfig;
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::checksum::processed_byte_count;

#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    pub directories: u64,
    pub files: u64,
    pub bytes: u64,
    pub processed_bytes: u64,
    pub failed: u64,
}

pub fn scan_files<F>(config: &FileIntegrityConfig, mut on_file: F) -> BatmanResult<ScanStats>
where
    F: FnMut(&Path, &fs::Metadata, &mut ScanStats) -> BatmanResult<()>,
{
    let mut stats = ScanStats::default();
    for path in &config.scan_paths {
        if !path.exists() {
            stats.failed += 1;
            continue;
        }
        visit(path, config, &mut stats, &mut on_file)?;
    }
    Ok(stats)
}

fn visit<F>(
    path: &Path,
    config: &FileIntegrityConfig,
    stats: &mut ScanStats,
    on_file: &mut F,
) -> BatmanResult<()>
where
    F: FnMut(&Path, &fs::Metadata, &mut ScanStats) -> BatmanResult<()>,
{
    if config.is_excluded(path) {
        return Ok(());
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            stats.failed += 1;
            return Ok(());
        }
        Err(error) => return Err(BatmanError::io(format!("stat {}", path.display()), error)),
    };

    if metadata.is_file() {
        stats.files += 1;
        stats.bytes += metadata.len();
        stats.processed_bytes += processed_byte_count(metadata.len(), config.scan_byte_limit);
        on_file(path, &metadata, stats)?;
        return Ok(());
    }

    if metadata.is_dir() {
        stats.directories += 1;
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                stats.failed += 1;
                return Ok(());
            }
            Err(error) => return Err(BatmanError::io(format!("read {}", path.display()), error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| BatmanError::io("read directory entry", error))?;
            visit(&entry.path(), config, stats, on_file)?;
        }
    }

    Ok(())
}
