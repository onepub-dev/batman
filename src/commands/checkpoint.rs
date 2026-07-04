use std::fmt::Write;
use std::path::Path;

use crate::cli::CheckpointOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path};
use crate::config::BatmanConfig;
use crate::errors::BatmanResult;
use crate::integrity::store::BaselineReader;
use crate::output::{Output, Style, format_count};
use crate::security::file_content_hash;
use time::OffsetDateTime;

const MANIFEST_FILE: &str = "baseline.manifest";

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: CheckpointOptions,
) -> BatmanResult<u8> {
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

    let reader = BaselineReader::open_with_public_key(
        &config.file_integrity.db_path,
        config.file_integrity.baseline_public_key.as_deref(),
    )?;
    let manifest_path = config.file_integrity.db_path.join(MANIFEST_FILE);
    let manifest_hash = hex_hash(&file_content_hash(&manifest_path)?);
    let config_hash = hex_hash(&reader.config_hash());
    let manifest_info = reader.manifest_info();

    if options.json {
        output.line(
            Style::Plain,
            checkpoint_json(
                &manifest_path,
                reader.record_count(),
                manifest_info.generation,
                manifest_info.created_unix_ms,
                &manifest_hash,
                &config_hash,
            ),
        )?;
    } else {
        output.line(Style::Info, "Batman Baseline Checkpoint")?;
        output.line(
            Style::Plain,
            format!("Records: {}", format_count(reader.record_count())),
        )?;
        output.line(
            Style::Plain,
            format!("Generation: {}", manifest_info.generation),
        )?;
        output.line(
            Style::Plain,
            format!(
                "Created: {}",
                format_unix_ms_utc(manifest_info.created_unix_ms)
            ),
        )?;
        output.line(
            Style::Plain,
            format!("Manifest: {}", manifest_path.display()),
        )?;
        output.line(Style::Plain, format!("Manifest hash: {manifest_hash}"))?;
        output.line(Style::Plain, format!("Config hash: {config_hash}"))?;
        output.line(
            Style::Success,
            format!(
                "BATMAN_BASELINE_MIN_GENERATION={}",
                manifest_info.generation
            ),
        )?;
    }
    Ok(0)
}

fn checkpoint_json(
    manifest_path: &Path,
    records: u64,
    generation: u64,
    created_unix_ms: u128,
    manifest_hash: &str,
    config_hash: &str,
) -> String {
    format!(
        "{{\"format\":\"batman-baseline-checkpoint-v1\",\"records\":{records},\"generation\":{generation},\"created_unix_ms\":{created_unix_ms},\"created_utc\":\"{}\",\"manifest_path\":\"{}\",\"manifest_hash\":\"{}\",\"config_hash\":\"{}\",\"min_generation_env\":\"BATMAN_BASELINE_MIN_GENERATION={generation}\"}}",
        json_escape(&format_unix_ms_utc(created_unix_ms)),
        json_escape(&manifest_path.display().to_string()),
        json_escape(manifest_hash),
        json_escape(config_hash)
    )
}

fn format_unix_ms_utc(value: u128) -> String {
    let Ok(seconds) = i64::try_from(value / 1_000) else {
        return format!("{value}ms since epoch");
    };
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return format!("{value}ms since epoch");
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

fn hex_hash(hash: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in hash {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{checkpoint_json, json_escape};

    #[test]
    fn checkpoint_json_contains_external_generation_hint() {
        let json = checkpoint_json(
            "/var/lib/batman/baseline.manifest".as_ref(),
            42,
            7,
            1_700_000_000_000,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        assert!(json.contains("\"format\":\"batman-baseline-checkpoint-v1\""));
        assert!(json.contains("\"records\":42"));
        assert!(json.contains("\"generation\":7"));
        assert!(json.contains("BATMAN_BASELINE_MIN_GENERATION=7"));
    }

    #[test]
    fn json_escape_handles_control_characters_and_quotes() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n".to_string());
    }
}
