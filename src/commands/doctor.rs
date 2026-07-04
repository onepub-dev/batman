use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::audit::{
    AUDIT_SINK_REQUIRED_ENV, AUDIT_SYSLOG_ENV, AUDIT_TCP_ENV, audit_path, verify_audit_log,
};
use crate::cli::DoctorOptions;
use crate::commands::CommandContext;
use crate::config::{BatmanConfig, default_max_scan_threads};
use crate::errors::BatmanResult;
use crate::integrity::mounts::MountTable;
use crate::integrity::store::{
    BASELINE_KEY_ENV, BASELINE_MIN_GENERATION_ENV, BASELINE_PRIVATE_KEY_ENV,
    BASELINE_PUBLIC_KEY_ENV, BaselineReader, REQUIRE_SIGNED_BASELINE_ENV,
};
use crate::logscan::LogAuditConfig;
use crate::output::{Output, Style, format_bytes, format_count};
use crate::security::{
    EXPECTED_CONFIG_HASH_ENV, config_trust_issues, data_path_trust_issues, env_flag_enabled,
    existing_file_trust_issues, expected_config_hash, file_content_hash, file_trust_issues,
    hex_hash,
};
use crate::system::is_privileged;
use time::OffsetDateTime;

const STRICT_CONFIG_ENV: &str = "BATMAN_STRICT_CONFIG";

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: DoctorOptions,
) -> BatmanResult<u8> {
    let mut strict_failures = 0_usize;
    let production_mode = options.strict || options.production;
    output.line(Style::Info, "Batman Doctor")?;
    output.line(Style::Plain, "")?;

    section(output, "Runtime")?;
    field(output, "Version", env!("CARGO_PKG_VERSION"))?;
    let executable = std::env::current_exe();
    match &executable {
        Ok(path) => {
            field(output, "Executable", path.display().to_string())?;
            strict_failures += report_trust_issues(
                output,
                "Executable trust",
                file_trust_issues(path, is_privileged()),
            )?;
        }
        Err(error) => {
            strict_failures += 1;
            field_with_style(
                output,
                Style::Warn,
                "Executable",
                format!("unavailable: {error}"),
            )?;
        }
    }
    field(output, "Privileged", yes_no(is_privileged()))?;
    strict_failures += report_scheduler_artifact_trust(output, context)?;
    if production_mode {
        strict_failures += report_scheduler_artifact_policy(output, context)?;
    }

    output.line(Style::Plain, "")?;
    section(output, "Settings")?;
    field(
        output,
        "Active config file",
        describe_rule_file(
            &context.local_settings.config_path,
            &context.local_settings.config_path_source,
        ),
    )?;
    strict_failures += report_trust_issues(
        output,
        "Config trust",
        config_trust_issues(&context.local_settings.config_path, is_privileged()),
    )?;
    strict_failures += report_expected_config_pin(output, &context.local_settings.config_path)?;
    if is_privileged() && context.local_settings.config_path_source == "default user location" {
        field_with_style(
            output,
            Style::Warn,
            "Config trust",
            "privileged run is using the user default config",
        )?;
        strict_failures += 1;
    }
    rule_file_search(output, context)?;
    output.line(Style::Plain, "")?;
    section(output, "File Integrity")?;
    match BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    ) {
        Ok(config) => {
            let file_integrity = &config.file_integrity;
            field(
                output,
                "Database path",
                describe_path(&file_integrity.db_path),
            )?;
            strict_failures += report_trust_issues(
                output,
                "Database trust",
                data_path_trust_issues(&file_integrity.db_path, is_privileged()),
            )?;
            field(
                output,
                "Record file",
                describe_path(&file_integrity.db_path.join("baseline.bfi")),
            )?;
            field(
                output,
                "Index file",
                describe_path(&file_integrity.db_path.join("baseline.idx")),
            )?;
            field(
                output,
                "Manifest file",
                describe_path(&file_integrity.db_path.join("baseline.manifest")),
            )?;
            match BaselineReader::open_with_public_key(
                &file_integrity.db_path,
                file_integrity.baseline_public_key.as_deref(),
            ) {
                Ok(reader) => {
                    field(output, "Baseline integrity", "ok")?;
                    field(
                        output,
                        "Baseline records",
                        format_count(reader.record_count()),
                    )?;
                    let manifest_info = reader.manifest_info();
                    field(
                        output,
                        "Baseline generation",
                        manifest_info.generation.to_string(),
                    )?;
                    field(
                        output,
                        "Baseline created",
                        format_unix_ms_utc(manifest_info.created_unix_ms),
                    )?;
                    field(
                        output,
                        "Scan byte limit",
                        if reader.scan_byte_limit() == 0 {
                            "whole file".to_string()
                        } else {
                            format_bytes(reader.scan_byte_limit())
                        },
                    )?;
                    strict_failures += report_config_drift(
                        output,
                        reader.config_hash(),
                        &context.local_settings.config_path,
                    )?;
                }
                Err(error) => {
                    strict_failures += 1;
                    if file_integrity.db_path.join("baseline.bfi").exists()
                        || file_integrity.db_path.join("baseline.idx").exists()
                    {
                        field_with_style(
                            output,
                            Style::Warn,
                            "Baseline integrity",
                            error.to_string(),
                        )?;
                    } else {
                        field(output, "Baseline", "missing - run 'batman baseline'")?;
                    }
                }
            }
            let audit_path = audit_path(&file_integrity.db_path);
            match verify_audit_log(&audit_path) {
                Ok(verification) => {
                    field(output, "Audit log", describe_path(&audit_path))?;
                    field(output, "Audit chain", "ok")?;
                    field(output, "Audit events", format_count(verification.events))?;
                }
                Err(error) => {
                    strict_failures += 1;
                    field(output, "Audit log", describe_path(&audit_path))?;
                    field_with_style(output, Style::Warn, "Audit chain", error.to_string())?;
                }
            }
            field(
                output,
                "Available CPUs",
                std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1)
                    .to_string(),
            )?;
            field(
                output,
                "Default max scan workers",
                default_max_scan_threads().to_string(),
            )?;
            field(
                output,
                "Configured scan workers",
                file_integrity.scan_threads.to_string(),
            )?;
            field(
                output,
                "Expected process threads",
                format!("{} including main thread", file_integrity.scan_threads + 1),
            )?;
            field(
                output,
                "Scan paths",
                file_integrity.scan_paths.len().to_string(),
            )?;
            for path in &file_integrity.scan_paths {
                field(output, "  path", describe_path(path))?;
            }
            field(
                output,
                "Exclusions",
                file_integrity.exclusions.len().to_string(),
            )?;
            field(
                output,
                "Metadata only",
                (file_integrity.metadata_only.len() + file_integrity.metadata_directories.len())
                    .to_string(),
            )?;
            field(
                output,
                "Excluded filesystems",
                file_integrity.excluded_filesystems.len().to_string(),
            )?;
            let risky_mounts = MountTable::current().risky_included_mountpoints(file_integrity);
            if !risky_mounts.is_empty() {
                field_with_style(
                    output,
                    Style::Warn,
                    "Scan risk",
                    format!(
                        "{} high-overhead mountpoints included",
                        format_count(risky_mounts.len() as u64)
                    ),
                )?;
                for risk in risky_mounts.iter().take(5) {
                    field_with_style(
                        output,
                        Style::Warn,
                        "  mount",
                        format!("{} ({})", risk.mountpoint.display(), risk.fs_type),
                    )?;
                }
                if risky_mounts.len() > 5 {
                    field_with_style(
                        output,
                        Style::Warn,
                        "  mount",
                        format!("... {} more", format_count((risky_mounts.len() - 5) as u64)),
                    )?;
                }
            }
            strict_failures += report_policy_warnings(output, file_integrity)?;
            strict_failures += report_self_monitoring_warnings(output, context, file_integrity)?;
            report_linux_file_flag_advisories(
                output,
                &context.local_settings.config_path,
                &file_integrity.db_path,
            )?;

            output.line(Style::Plain, "")?;
            section(output, "Log Scanning")?;
            match LogAuditConfig::load(&context.local_settings.config_path) {
                Ok(log_config) => {
                    field(output, "Sources", log_config.sources.len().to_string())?;
                    field(output, "Rules", log_config.rules.len().to_string())?;
                }
                Err(error) => field(output, "Config", error.to_string())?,
            }
        }
        Err(error) => {
            strict_failures += 1;
            field(output, "Config", error.to_string())?;
        }
    }

    if production_mode && strict_failures > 0 {
        output.line(
            Style::Warn,
            format!("Production doctor failed with {strict_failures} issue(s)"),
        )?;
        Ok(1)
    } else {
        Ok(0)
    }
}

fn section(output: &mut Output, name: &str) -> BatmanResult<()> {
    output.line(Style::Success, name)
}

fn field(output: &mut Output, label: &str, value: impl AsRef<str>) -> BatmanResult<()> {
    field_with_style(output, Style::Plain, label, value)
}

fn field_with_style(
    output: &mut Output,
    style: Style,
    label: &str,
    value: impl AsRef<str>,
) -> BatmanResult<()> {
    output.line(style, format!("{label:<20}: {}", value.as_ref()))
}

fn report_trust_issues(
    output: &mut Output,
    label: &str,
    issues: Vec<crate::security::TrustIssue>,
) -> BatmanResult<usize> {
    if issues.is_empty() {
        field(output, label, "ok")?;
        return Ok(0);
    }
    field_with_style(
        output,
        Style::Warn,
        label,
        format!("{} issue(s)", issues.len()),
    )?;
    for issue in issues.iter().take(5) {
        field_with_style(
            output,
            Style::Warn,
            "  issue",
            format!("{}: {}", issue.path.display(), issue.message),
        )?;
    }
    if issues.len() > 5 {
        field_with_style(
            output,
            Style::Warn,
            "  issue",
            format!("... {} more", issues.len() - 5),
        )?;
    }
    Ok(issues.len())
}

fn report_policy_warnings(
    output: &mut Output,
    config: &crate::config::FileIntegrityConfig,
) -> BatmanResult<usize> {
    let warnings = policy_warnings(config);
    if warnings.is_empty() {
        field(output, "Policy lint", "ok")?;
        return Ok(0);
    }
    let count = warnings.len();
    field_with_style(
        output,
        Style::Warn,
        "Policy lint",
        format!("{} warning(s)", count),
    )?;
    for warning in warnings {
        field_with_style(output, Style::Warn, "  warning", warning)?;
    }
    Ok(count)
}

fn report_self_monitoring_warnings(
    output: &mut Output,
    context: &CommandContext,
    config: &crate::config::FileIntegrityConfig,
) -> BatmanResult<usize> {
    let mut warnings = Vec::new();
    let config_path = &context.local_settings.config_path;
    let active_config_metadata_only = config.is_metadata_only(config_path);
    warnings.extend(content_monitoring_warnings(
        config,
        config_path,
        "active config",
    ));
    if active_config_metadata_only
        && !warnings
            .iter()
            .any(|warning| warning.starts_with("active config "))
    {
        warnings.push(format!(
            "active config {} is metadata-only; production self-monitoring requires content hashing",
            config_path.display()
        ));
    }

    match std::env::current_exe() {
        Ok(executable) => {
            warnings.extend(content_monitoring_warnings(
                config,
                &executable,
                "executable",
            ));
        }
        Err(error) => warnings.push(format!("unable to resolve executable path: {error}")),
    }

    if warnings.is_empty() {
        field(output, "Self monitoring", "ok")?;
        return Ok(0);
    }

    let count = warnings.len();
    field_with_style(
        output,
        Style::Warn,
        "Self monitoring",
        format!("{} warning(s)", count),
    )?;
    for warning in warnings {
        field_with_style(output, Style::Warn, "  warning", warning)?;
    }
    Ok(count)
}

fn report_scheduler_artifact_trust(
    output: &mut Output,
    context: &CommandContext,
) -> BatmanResult<usize> {
    let artifacts = existing_scheduler_artifacts(context);
    if artifacts.is_empty() {
        field(
            output,
            "Scheduler trust",
            "no known Batman scheduler artifacts found",
        )?;
        return Ok(0);
    }

    let mut issues = Vec::new();
    for artifact in &artifacts {
        issues.extend(existing_file_trust_issues(artifact, is_privileged()));
    }
    if issues.is_empty() {
        field(
            output,
            "Scheduler trust",
            format!("ok ({} artifact(s))", artifacts.len()),
        )?;
        return Ok(0);
    }

    field_with_style(
        output,
        Style::Warn,
        "Scheduler trust",
        format!("{} issue(s)", issues.len()),
    )?;
    for issue in issues.iter().take(5) {
        field_with_style(
            output,
            Style::Warn,
            "  issue",
            format!("{}: {}", issue.path.display(), issue.message),
        )?;
    }
    if issues.len() > 5 {
        field_with_style(
            output,
            Style::Warn,
            "  issue",
            format!("... {} more", issues.len() - 5),
        )?;
    }
    Ok(issues.len())
}

fn existing_scheduler_artifacts(context: &CommandContext) -> Vec<PathBuf> {
    scheduler_artifact_candidates(context)
        .into_iter()
        .filter(|path| path.exists())
        .collect()
}

fn report_scheduler_artifact_policy(
    output: &mut Output,
    context: &CommandContext,
) -> BatmanResult<usize> {
    let artifacts = existing_scheduler_artifacts(context)
        .into_iter()
        .filter(|path| scheduler_artifact_runs_scan(path))
        .collect::<Vec<_>>();
    if artifacts.is_empty() {
        field(output, "Scheduler policy", "no scan runner artifact found")?;
        return Ok(0);
    }

    let mut warnings = Vec::new();
    let config_path = context.local_settings.config_path.display().to_string();
    let expected_config_env = file_content_hash(&context.local_settings.config_path)
        .map(|hash| format!("{EXPECTED_CONFIG_HASH_ENV}={}", hex_hash(&hash)))
        .ok();
    for artifact in &artifacts {
        let content = match fs::read_to_string(artifact) {
            Ok(content) => content,
            Err(error) => {
                warnings.push(format!("{} could not be read: {error}", artifact.display()));
                continue;
            }
        };
        if !content.contains(&config_path) {
            warnings.push(format!(
                "{} does not reference active config {}",
                artifact.display(),
                config_path
            ));
        }
        if scheduler_artifact_should_carry_env(artifact, &content) {
            for (name, value) in [
                (REQUIRE_SIGNED_BASELINE_ENV, "1"),
                (STRICT_CONFIG_ENV, "1"),
                (AUDIT_SINK_REQUIRED_ENV, "1"),
            ] {
                if !content.contains(&format!("{name}={value}")) {
                    warnings.push(format!(
                        "{} is missing {name}={value}; regenerate with --production-scheduler or add scheduler env",
                        artifact.display()
                    ));
                }
            }
            match &expected_config_env {
                Some(expected) if !content.contains(expected) => {
                    warnings.push(format!(
                        "{} is missing {expected}; regenerate with --production-scheduler or add scheduler env",
                        artifact.display()
                    ));
                }
                None if !content.contains(EXPECTED_CONFIG_HASH_ENV) => {
                    warnings.push(format!(
                        "{} is missing {EXPECTED_CONFIG_HASH_ENV}; regenerate with --production-scheduler or add scheduler env",
                        artifact.display()
                    ));
                }
                _ => {}
            }
        }
    }

    if warnings.is_empty() {
        field(
            output,
            "Scheduler policy",
            format!("ok ({} artifact(s))", artifacts.len()),
        )?;
        return Ok(0);
    }

    field_with_style(
        output,
        Style::Warn,
        "Scheduler policy",
        format!("{} warning(s)", warnings.len()),
    )?;
    for warning in warnings.iter().take(5) {
        field_with_style(output, Style::Warn, "  warning", warning)?;
    }
    if warnings.len() > 5 {
        field_with_style(
            output,
            Style::Warn,
            "  warning",
            format!("... {} more", warnings.len() - 5),
        )?;
    }
    Ok(warnings.len())
}

fn scheduler_artifact_runs_scan(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "batman-scan.service"
                    | "com.noojee.batman.scan.plist"
                    | "batman-scan.xml"
                    | "batman-scan.cmd"
            )
        })
}

fn scheduler_artifact_should_carry_env(path: &Path, content: &str) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    match name {
        "batman-scan.xml" => !content.contains("batman-scan.cmd"),
        "batman-scan.service" | "com.noojee.batman.scan.plist" | "batman-scan.cmd" => true,
        _ => false,
    }
}

fn scheduler_artifact_candidates(context: &CommandContext) -> Vec<PathBuf> {
    let mut candidates = BTreeSet::new();
    let settings_dir = context.local_settings.settings_dir();
    for name in [
        "batman-scan.service",
        "batman-scan.timer",
        "com.noojee.batman.scan.plist",
        "batman-scan.xml",
        "batman-scan.cmd",
    ] {
        candidates.insert(settings_dir.join(name));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        candidates.insert(PathBuf::from("/etc/systemd/system/batman-scan.service"));
        candidates.insert(PathBuf::from("/etc/systemd/system/batman-scan.timer"));
    }

    #[cfg(target_os = "macos")]
    {
        candidates.insert(PathBuf::from(
            "/Library/LaunchDaemons/com.noojee.batman.scan.plist",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let batman_dir = program_data.join("Batman");
        candidates.insert(batman_dir.join("batman-scan.xml"));
        candidates.insert(batman_dir.join("batman-scan.cmd"));
    }

    candidates.into_iter().collect()
}

fn report_config_drift(
    output: &mut Output,
    baseline_config_hash: [u8; 32],
    config_path: &Path,
) -> BatmanResult<usize> {
    if baseline_config_hash == [0; 32] {
        field_with_style(
            output,
            Style::Warn,
            "Config drift",
            "baseline does not record a config hash",
        )?;
        return Ok(1);
    }

    let current_config_hash = file_content_hash(config_path)?;
    if current_config_hash == baseline_config_hash {
        field(output, "Config drift", "ok")?;
        return Ok(0);
    }

    field_with_style(
        output,
        Style::Warn,
        "Config drift",
        "active config differs from baseline",
    )?;
    Ok(1)
}

fn report_expected_config_pin(output: &mut Output, config_path: &Path) -> BatmanResult<usize> {
    let expected = match expected_config_hash() {
        Ok(Some(expected)) => expected,
        Ok(None) => {
            field(output, "Config pin", "not set")?;
            return Ok(0);
        }
        Err(error) => {
            field_with_style(output, Style::Warn, "Config pin", error.to_string())?;
            return Ok(1);
        }
    };
    let actual = match file_content_hash(config_path) {
        Ok(actual) => actual,
        Err(error) => {
            field_with_style(output, Style::Warn, "Config pin", error.to_string())?;
            return Ok(1);
        }
    };
    if actual == expected {
        field(output, "Config pin", "ok")?;
        return Ok(0);
    }
    field_with_style(
        output,
        Style::Warn,
        "Config pin",
        format!(
            "mismatch expected {} actual {}",
            hex_hash(&expected),
            hex_hash(&actual)
        ),
    )?;
    Ok(1)
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

#[cfg(target_os = "linux")]
fn report_linux_file_flag_advisories(
    output: &mut Output,
    config_path: &Path,
    db_path: &Path,
) -> BatmanResult<()> {
    let mut advisories = Vec::new();
    collect_linux_flag_advisory(
        &mut advisories,
        config_path,
        "config",
        crate::integrity::store::LINUX_IMMUTABLE_FL,
        "immutable",
    );
    for name in ["baseline.bfi", "baseline.idx", "baseline.manifest"] {
        collect_linux_flag_advisory(
            &mut advisories,
            &db_path.join(name),
            name,
            crate::integrity::store::LINUX_IMMUTABLE_FL,
            "immutable",
        );
    }
    collect_linux_flag_advisory(
        &mut advisories,
        &audit_path(db_path),
        "audit.log",
        crate::integrity::store::LINUX_APPEND_FL,
        "append-only",
    );

    if advisories.is_empty() {
        field(output, "Linux file flags", "ok or unsupported")?;
        return Ok(());
    }

    field_with_style(
        output,
        Style::Warn,
        "Linux file flags",
        format!("{} advisory item(s)", advisories.len()),
    )?;
    for advisory in advisories.iter().take(5) {
        field_with_style(output, Style::Warn, "  advisory", advisory)?;
    }
    if advisories.len() > 5 {
        field_with_style(
            output,
            Style::Warn,
            "  advisory",
            format!("... {} more", advisories.len() - 5),
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn report_linux_file_flag_advisories(
    _output: &mut Output,
    _config_path: &Path,
    _db_path: &Path,
) -> BatmanResult<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_linux_flag_advisory(
    advisories: &mut Vec<String>,
    path: &Path,
    label: &str,
    required_flag: u32,
    flag_name: &str,
) {
    if !path.exists() {
        return;
    }
    match crate::integrity::store::linux_inode_flags(path) {
        Ok(Some(flags)) if flags & required_flag == 0 => advisories.push(format!(
            "{label} {} is not {flag_name}; consider chattr {} after approved baseline changes",
            path.display(),
            if flag_name == "append-only" {
                "+a"
            } else {
                "+i"
            }
        )),
        Ok(Some(_)) | Ok(None) => {}
        Err(error) => advisories.push(format!(
            "{label} {} file flags could not be checked: {error}",
            path.display()
        )),
    }
}

fn content_monitoring_warnings(
    config: &crate::config::FileIntegrityConfig,
    path: &Path,
    label: &str,
) -> Vec<String> {
    if !path_is_monitored(config, path) {
        return vec![format!(
            "{label} {} is not covered by file_integrity.scan_paths",
            path.display()
        )];
    }
    if metadata_only_matches(config, path) {
        return vec![format!(
            "{label} {} is metadata-only; production self-monitoring requires content hashing",
            path.display()
        )];
    }
    Vec::new()
}

fn metadata_only_matches(config: &crate::config::FileIntegrityConfig, path: &Path) -> bool {
    config.is_metadata_directory(path)
        || config
            .metadata_only
            .iter()
            .any(|metadata_only| path_matches_rule(path, metadata_only))
}

fn path_matches_rule(path: &Path, rule: &Path) -> bool {
    path == rule
        || path.starts_with(rule)
        || normalized_path_text(path) == normalized_path_text(rule)
}

fn normalized_path_text(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn path_is_monitored(config: &crate::config::FileIntegrityConfig, path: &Path) -> bool {
    let monitored = config
        .scan_paths
        .iter()
        .any(|scan_path| path == scan_path || path.starts_with(scan_path));
    monitored && !config.is_excluded(path)
}

fn policy_warnings(config: &crate::config::FileIntegrityConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.scan_paths.is_empty() {
        warnings.push("no scan paths configured".to_string());
    }
    if config.scan_byte_limit > 0 {
        warnings.push(format!(
            "scan_byte_limit is {}; whole-file hashing is stronger",
            format_bytes(config.scan_byte_limit)
        ));
    }
    if cfg!(target_os = "linux") && config.excluded_filesystems.is_empty() {
        warnings
            .push("excluded_filesystems is empty; virtual filesystems may be scanned".to_string());
    }
    if config.scan_threads > default_max_scan_threads() {
        warnings.push(format!(
            "scan_threads {} exceeds default worker cap {}; this may starve the host",
            config.scan_threads,
            default_max_scan_threads()
        ));
    }
    for scan_path in &config.scan_paths {
        if scan_path == &config.db_path || scan_path.starts_with(&config.db_path) {
            warnings.push(format!(
                "scan path {} is inside db_path {}; the baseline database is always excluded and should not be configured as a scan root",
                scan_path.display(),
                config.db_path.display()
            ));
        }
    }
    let ed25519_public_env = std::env::var(BASELINE_PUBLIC_KEY_ENV).is_ok();
    let ed25519_public_config = config.baseline_public_key.is_some();
    let ed25519_public = ed25519_public_env || ed25519_public_config;
    let ed25519_private = std::env::var(BASELINE_PRIVATE_KEY_ENV).is_ok();
    let symmetric_key = std::env::var(BASELINE_KEY_ENV).is_ok();
    if !env_flag_enabled(REQUIRE_SIGNED_BASELINE_ENV) {
        warnings.push(format!(
            "{REQUIRE_SIGNED_BASELINE_ENV} is not enabled; production scans should strictly reject unsigned or unverifiable baselines"
        ));
    } else if !ed25519_public && !symmetric_key {
        warnings.push(format!(
            "{BASELINE_PUBLIC_KEY_ENV}, file_integrity.baseline_public_key, or {BASELINE_KEY_ENV} is not set; signed baselines cannot be verified by this process"
        ));
    }
    if ed25519_public && symmetric_key && !ed25519_private {
        warnings.push(format!(
            "{BASELINE_PUBLIC_KEY_ENV} is set with {BASELINE_KEY_ENV} but {BASELINE_PRIVATE_KEY_ENV} is not set; baselining would create a symmetric signature rejected by the configured Ed25519 public key"
        ));
    } else if symmetric_key && !ed25519_public {
        warnings.push(format!(
            "{BASELINE_KEY_ENV} uses symmetric signing; prefer {BASELINE_PRIVATE_KEY_ENV} for baselining and {BASELINE_PUBLIC_KEY_ENV} for production scans"
        ));
    }
    if ed25519_private {
        warnings.push(format!(
            "{BASELINE_PRIVATE_KEY_ENV} is set in this process; production scan hosts should normally keep only {BASELINE_PUBLIC_KEY_ENV} or file_integrity.baseline_public_key"
        ));
    }
    if std::env::var(BASELINE_MIN_GENERATION_ENV).is_err() {
        warnings.push(format!(
            "{BASELINE_MIN_GENERATION_ENV} is not set; signed old baselines are not rejected by generation"
        ));
    }
    if std::env::var(AUDIT_TCP_ENV).is_err() && !env_flag_enabled(AUDIT_SYSLOG_ENV) {
        warnings.push(format!(
            "no off-host audit sink is configured; set {AUDIT_TCP_ENV} or {AUDIT_SYSLOG_ENV}"
        ));
    }
    if !env_flag_enabled(AUDIT_SINK_REQUIRED_ENV) {
        warnings.push(format!(
            "{AUDIT_SINK_REQUIRED_ENV} is not enabled; scheduled scans will continue if audit forwarding fails"
        ));
    }
    if !config_drift_aborts_scans() {
        warnings.push(
            "BATMAN_STRICT_CONFIG is not enabled; config drift will be reported as a finding instead of aborting scheduled scans"
                .to_string(),
        );
    }
    if std::env::var(EXPECTED_CONFIG_HASH_ENV).is_err() {
        warnings.push(format!(
            "{EXPECTED_CONFIG_HASH_ENV} is not set; production scans are not pinned to an externally supplied config hash"
        ));
    }
    for exclusion in &config.exclusions {
        if is_root_path(exclusion) {
            warnings.push(format!(
                "exclusion {} removes an entire scan root",
                exclusion.display()
            ));
        }
    }
    for path in config
        .metadata_only
        .iter()
        .chain(config.metadata_directories.iter())
    {
        if is_root_path(path) {
            warnings.push(format!(
                "metadata_only {} disables content hashing broadly",
                path.display()
            ));
        }
    }
    warnings
}

fn is_root_path(path: &Path) -> bool {
    path.parent().is_none()
        || path == Path::new("/")
        || path
            .to_string_lossy()
            .as_bytes()
            .get(1..3)
            .is_some_and(|suffix| suffix == b":/" || suffix == b":\\")
}

fn config_drift_aborts_scans() -> bool {
    env_flag_enabled(STRICT_CONFIG_ENV) || env_flag_enabled(REQUIRE_SIGNED_BASELINE_ENV)
}

fn rule_file_search(context_output: &mut Output, context: &CommandContext) -> BatmanResult<()> {
    let mut wrote_header = false;
    for (label, path) in [
        (
            "  system default",
            &context.local_settings.system_config_path,
        ),
        ("  user default", &context.local_settings.user_config_path),
    ] {
        if path == &context.local_settings.config_path {
            continue;
        }
        if !wrote_header {
            context_output.line(Style::Plain, "Config file search:")?;
            wrote_header = true;
        }
        field(context_output, label, describe_path(path))?;
    }
    Ok(())
}

fn describe_path(path: &std::path::Path) -> String {
    let status = path_status(path);
    format!("{} ({status})", path.display())
}

fn path_status(path: &std::path::Path) -> String {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => "directory exists",
        Ok(_) => "file exists",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing",
        Err(error) => return error.to_string(),
    }
    .to_string()
}

fn describe_rule_file(path: &std::path::Path, source: &str) -> String {
    format!("{} ({}, {source})", path.display(), path_status(path))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::FileIntegrityConfig;
    use crate::security::EXPECTED_CONFIG_HASH_ENV;
    use crate::test_support::env_lock;

    use super::{STRICT_CONFIG_ENV, policy_warnings};

    #[test]
    fn policy_lint_warns_when_signed_baselines_are_not_required() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "0");
            std::env::remove_var("BATMAN_BASELINE_KEY");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
            std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
            std::env::remove_var(STRICT_CONFIG_ENV);
        }

        let warnings = policy_warnings(&minimal_config());

        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_REQUIRE_SIGNED_BASELINE is not enabled")),
            "{warnings:?}"
        );
    }

    #[test]
    fn policy_lint_accepts_signed_baseline_environment() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "1");
            std::env::set_var(
                "BATMAN_BASELINE_PUBLIC_KEY",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            );
            std::env::set_var("BATMAN_BASELINE_MIN_GENERATION", "1");
            std::env::set_var(EXPECTED_CONFIG_HASH_ENV, "abc");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_BASELINE_KEY");
            std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
            std::env::remove_var("BATMAN_STRICT_CONFIG");
        }

        let warnings = policy_warnings(&minimal_config());

        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_REQUIRE_SIGNED_BASELINE")),
            "{warnings:?}"
        );
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_BASELINE_KEY")),
            "{warnings:?}"
        );
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_BASELINE_MIN_GENERATION")),
            "{warnings:?}"
        );
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_STRICT_CONFIG")),
            "{warnings:?}"
        );
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_EXPECTED_CONFIG_HASH")),
            "{warnings:?}"
        );
        unsafe {
            std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
            std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
        }
    }

    #[test]
    fn policy_lint_accepts_explicit_strict_config_drift_handling() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "0");
            std::env::set_var(STRICT_CONFIG_ENV, "1");
            std::env::remove_var("BATMAN_BASELINE_KEY");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
            std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
        }

        let warnings = policy_warnings(&minimal_config());

        assert!(
            !warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_STRICT_CONFIG")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("BATMAN_REQUIRE_SIGNED_BASELINE")),
            "{warnings:?}"
        );
        unsafe {
            std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
            std::env::remove_var(STRICT_CONFIG_ENV);
        }
    }

    #[test]
    fn policy_lint_warns_when_database_directory_is_scan_root() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "1");
            std::env::set_var(
                "BATMAN_BASELINE_PUBLIC_KEY",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            );
            std::env::set_var("BATMAN_BASELINE_MIN_GENERATION", "1");
            std::env::set_var("BATMAN_AUDIT_TCP", "127.0.0.1:9");
            std::env::set_var("BATMAN_AUDIT_SINK_REQUIRED", "1");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_BASELINE_KEY");
            std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
            std::env::remove_var("BATMAN_STRICT_CONFIG");
        }
        let mut config = minimal_config();
        config.scan_paths = vec![config.db_path.clone()];

        let warnings = policy_warnings(&config);

        assert!(
            warnings.iter().any(|warning| warning.contains(
                "the baseline database is always excluded and should not be configured as a scan root"
            )),
            "{warnings:?}"
        );
        unsafe {
            std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        }
    }

    #[test]
    fn policy_lint_warns_when_public_key_is_mixed_with_symmetric_signing_key() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("BATMAN_REQUIRE_SIGNED_BASELINE", "1");
            std::env::set_var(
                "BATMAN_BASELINE_PUBLIC_KEY",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            );
            std::env::set_var(
                "BATMAN_BASELINE_KEY",
                "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f",
            );
            std::env::set_var("BATMAN_BASELINE_MIN_GENERATION", "1");
            std::env::set_var("BATMAN_AUDIT_TCP", "127.0.0.1:9");
            std::env::set_var("BATMAN_AUDIT_SINK_REQUIRED", "1");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
            std::env::remove_var("BATMAN_STRICT_CONFIG");
        }

        let warnings = policy_warnings(&minimal_config());

        assert!(
            warnings.iter().any(|warning| {
                warning.contains("BATMAN_BASELINE_PUBLIC_KEY is set with BATMAN_BASELINE_KEY")
            }),
            "{warnings:?}"
        );
        unsafe {
            std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
            std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
            std::env::remove_var("BATMAN_BASELINE_KEY");
            std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
            std::env::remove_var("BATMAN_AUDIT_TCP");
            std::env::remove_var("BATMAN_AUDIT_SYSLOG");
            std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        }
    }

    fn minimal_config() -> FileIntegrityConfig {
        FileIntegrityConfig {
            scan_byte_limit: 0,
            scan_threads: crate::config::default_max_scan_threads(),
            scan_buffer_size: 64 * 1024,
            baseline_public_key: None,
            db_path: PathBuf::from("/var/lib/batman"),
            scan_paths: vec![PathBuf::from("/")],
            exclusions: Vec::new(),
            excluded_filesystems: vec!["proc".to_string()],
            metadata_directories: Vec::new(),
            metadata_only: Vec::new(),
            registry_paths: Vec::new(),
            settings_dir: PathBuf::from("/etc/batman"),
        }
    }
}
