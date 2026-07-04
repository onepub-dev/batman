use crate::audit::append_event;
use crate::cli::BaselineOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path, install};
use crate::config::BatmanConfig;
use crate::errors::{BatmanError, BatmanResult};
use crate::integrity::scan_checksums;
use crate::integrity::store::{BaselineFinishProgress, BaselineWriter};
use crate::output::{
    Output, ProgressMeter, Style, format_bytes, format_count, notify_integrity_result,
};
use crate::security::file_content_hash;
use crate::system::{is_privileged, required_privilege_description};

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: BaselineOptions,
) -> BatmanResult<u8> {
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "You must run with {} to create a baseline",
            required_privilege_description()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_config(context, output)? {
        return Ok(1);
    }

    if install::ensure_rule_file(context, output)? != 0 {
        return Ok(1);
    }

    let config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    if config.file_integrity.scan_paths.is_empty() {
        output.error(format!(
            "There were no scan paths in {}. Add at least one scan path and try again",
            context.local_settings.config_path.display()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_data_path(context, output, &config.file_integrity.db_path)? {
        return Ok(1);
    }
    let signing_key = if options.unsigned {
        if super::signing::signed_baseline_required() {
            output
                .error("Refusing --unsigned because BATMAN_REQUIRE_SIGNED_BASELINE is enabled.")?;
            output.line(
                Style::Plain,
                "Run 'batman keygen' if signing keys have not been created yet, then rerun 'batman baseline' and enter the private key when prompted.",
            )?;
            return Ok(1);
        }
        output.line(
            Style::Warn,
            "Creating an unsigned baseline by request. Scans configured to verify signed baselines will reject it.",
        )?;
        None
    } else {
        super::signing::baseline_signing_key_for_write(
            config.file_integrity.baseline_public_key.as_deref(),
            output,
        )?
    };

    let mut writer = BaselineWriter::create_with_config_hash_and_signing_key(
        &config.file_integrity.db_path,
        config.file_integrity.scan_byte_limit,
        file_content_hash(&context.local_settings.config_path)?,
        signing_key,
    )?;
    let scan_config = config.file_integrity.clone();
    let mut progress = ProgressMeter::new();
    let stats = scan_checksums(&scan_config, |file, stats| {
        writer.add_file_with_metadata(&file.path, file.checksum, file.metadata)?;
        if !context.global.quiet && stats.files % 100 == 0 {
            let (db_chunks, db_bytes) = if context.global.verbose {
                writer.progress_counters()
            } else {
                (0, 0)
            };
            let snapshot =
                progress.snapshot(stats.files, stats.processed_bytes, db_chunks, db_bytes);
            if context.global.progress {
                output.progress_count(
                    Style::Plain,
                    "Processed",
                    stats.directories,
                    stats.files,
                    snapshot,
                )?;
            } else {
                output.progress_path(
                    Style::Plain,
                    "Calculating Hashes",
                    stats.files,
                    snapshot,
                    &file.path,
                )?;
            }
        }
        Ok(())
    })?;
    let records = if context.global.quiet {
        writer.finish()?
    } else {
        writer.finish_with_progress(|progress| {
            output.progress(Style::Plain, format_baseline_finish_progress(progress))
        })?
    };

    if stats.failed > 0 {
        output.line(
            Style::Warn,
            format!(
                "File Integrity Baseline completed with errors. Directories: {} Files: {} Bytes: {} Failed: {}",
                format_count(stats.directories),
                format_count(stats.files),
                format_bytes(stats.bytes),
                format_count(stats.failed)
            ),
        )?;
    } else {
        output.line(
            Style::Success,
            format!(
                "File Integrity Baseline complete. Records: {} Directories: {} Files: {} Bytes: {}",
                format_count(records),
                format_count(stats.directories),
                format_count(stats.files),
                format_bytes(stats.bytes),
            ),
        )?;
    }
    append_event(
        &config.file_integrity.db_path,
        "baseline",
        &[
            (
                "config_path",
                context.local_settings.config_path.display().to_string(),
            ),
            ("records", records.to_string()),
            ("directories", stats.directories.to_string()),
            ("files", stats.files.to_string()),
            ("bytes", stats.bytes.to_string()),
            ("failed", stats.failed.to_string()),
        ],
    )?;
    notify_integrity_result(
        &config.email,
        output,
        "File Integrity Baseline",
        stats.failed == 0,
        &stats,
        stats.failed,
        &[],
    )?;
    if stats.failed == 0 { Ok(0) } else { Ok(1) }
}

fn format_baseline_finish_progress(progress: BaselineFinishProgress) -> String {
    match progress {
        BaselineFinishProgress::Preparing { records } => format!(
            "Finalising Baseline: preparing sorted records ({})",
            format_count(records)
        ),
        BaselineFinishProgress::Writing { written, records } => format!(
            "Finalising Baseline: writing records {}/{}",
            format_count(written),
            format_count(records)
        ),
        BaselineFinishProgress::Syncing { records } => format!(
            "Finalising Baseline: syncing records ({})",
            format_count(records)
        ),
        BaselineFinishProgress::Replacing { records } => format!(
            "Finalising Baseline: replacing baseline files ({})",
            format_count(records)
        ),
    }
}

pub fn ensure_rule_file(context: &CommandContext) -> BatmanResult<()> {
    if context.local_settings.config_path.exists() {
        Ok(())
    } else {
        Err(BatmanError::Config(format!(
            "You must run 'batman install' first. Missing {}",
            context.local_settings.config_path.display()
        )))
    }
}
