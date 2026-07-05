use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::audit::append_event;
use crate::cli::AcceptOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path};
use crate::config::{BatmanConfig, FileIntegrityConfig};
use crate::errors::BatmanResult;
use crate::integrity::scan_checksums;
use crate::integrity::store::{BaselineReader, BaselineRecord, BaselineWriter, path_hash_value};
use crate::output::{Output, ProgressMeter, Style, format_count};
use crate::system::{is_privileged, required_privilege_description};

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: AcceptOptions,
) -> BatmanResult<u8> {
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "Error: You must run with {} to accept integrity changes",
            required_privilege_description()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_config(context, output)? {
        return Ok(1);
    }

    let config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    if !ensure_trusted_data_path(context, output, &config.file_integrity.db_path)? {
        return Ok(1);
    }
    let mut reader = BaselineReader::open_with_public_key(
        &config.file_integrity.db_path,
        config.file_integrity.baseline_public_key.as_deref(),
    )?;
    let config_hash = reader.config_hash();
    if reader.scan_byte_limit() != config.file_integrity.scan_byte_limit {
        output.error(format!(
            "Refusing accept: baseline scan_byte_limit is {} but config is {}. Run a new baseline first.",
            reader.scan_byte_limit(),
            config.file_integrity.scan_byte_limit
        ))?;
        return Ok(1);
    }

    let scope = options.path;
    let canonical_scope = normalise_scope(&scope);
    let accepted_records = scan_scope(&config.file_integrity, &scope, context, output)?;
    let signing_key = super::signing::baseline_signing_key_for_write(
        config.file_integrity.baseline_public_key.as_deref(),
        output,
    )?;
    let mut writer = BaselineWriter::create_with_config_hash_and_signing_key(
        &config.file_integrity.db_path,
        config.file_integrity.scan_byte_limit,
        config_hash,
        signing_key,
    )?;
    let mut preserved = 0_u64;
    let mut removed = 0_u64;

    for ordinal in 0..reader.record_count() {
        let record = reader.record_at(ordinal)?;
        if in_scope(&record.path, &scope, &canonical_scope) {
            removed += 1;
            continue;
        }
        writer.add_file_with_metadata(&record.path, record.checksum, record.metadata)?;
        preserved += 1;
    }

    let added = accepted_records.len() as u64;
    for record in accepted_records.into_values() {
        writer.add_file_with_metadata(&record.path, record.checksum, record.metadata)?;
    }
    let total = writer.finish()?;

    output.line(
        Style::Success,
        format!(
            "Accepted {}. Preserved: {} Removed: {} Accepted: {} Records: {}",
            scope.display(),
            format_count(preserved),
            format_count(removed),
            format_count(added),
            format_count(total)
        ),
    )?;
    append_event(
        &config.file_integrity.db_path,
        "accept",
        &[
            ("scope", scope.display().to_string()),
            ("preserved", preserved.to_string()),
            ("removed", removed.to_string()),
            ("accepted", added.to_string()),
            ("records", total.to_string()),
        ],
    )?;
    Ok(0)
}

fn scan_scope(
    config: &FileIntegrityConfig,
    scope: &Path,
    context: &CommandContext,
    output: &mut Output,
) -> BatmanResult<HashMap<PathBuf, BaselineRecord>> {
    if !scope.exists() {
        return Ok(HashMap::new());
    }

    let mut scan_config = config.clone();
    scan_config.scan_paths = vec![scope.to_path_buf()];
    let mut records = HashMap::new();
    let mut progress = ProgressMeter::new();
    scan_checksums(&scan_config, |file, stats| {
        records.insert(
            file.path.clone(),
            BaselineRecord {
                path_hash: path_hash_value(&file.path),
                path: file.path.clone(),
                checksum: file.checksum,
                metadata: file.metadata,
            },
        );
        if !context.global.quiet && stats.files % 100 == 0 {
            let snapshot = progress.snapshot(stats.files, stats.processed_bytes, 0, 0);
            output.progress_path(Style::Plain, "Accepting", stats.files, snapshot, &file.path)?;
        }
        Ok(())
    })?;
    Ok(records)
}

fn normalise_scope(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn in_scope(path: &Path, scope: &Path, canonical_scope: &Path) -> bool {
    path == scope
        || path.starts_with(scope)
        || path == canonical_scope
        || path.starts_with(canonical_scope)
        || comparable_path(path).starts_with(comparable_path(scope))
        || comparable_path(path).starts_with(comparable_path(canonical_scope))
}

fn comparable_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        path.strip_prefix("/private")
            .map(|stripped| Path::new("/").join(stripped))
            .unwrap_or_else(|_| path.to_path_buf())
    }
    #[cfg(not(target_os = "macos"))]
    {
        path.to_path_buf()
    }
}
