use crate::cli::LogOptions;
use crate::commands::{CommandContext, ensure_trusted_config};
use crate::config::BatmanConfig;
use crate::errors::{BatmanError, BatmanResult};
use crate::logscan::{LogAuditConfig, LogSource, SourceKind, scan_log_source};
use crate::output::{Output, Style, notify_log_result};
use crate::system::{is_privileged, required_privilege_description};

pub fn run(context: &CommandContext, output: &mut Output, options: LogOptions) -> BatmanResult<u8> {
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "Error: You must run with {} to run a log scan",
            required_privilege_description()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_config(context, output)? {
        return Ok(1);
    }

    let batman_config = BatmanConfig::load(
        &context.local_settings.config_path,
        &context.local_settings.settings_dir(),
    )?;
    let log_config = LogAuditConfig::load(&context.local_settings.config_path)?;

    if options.selector.is_some() || options.path.is_some() {
        let Some(source) = selected_source(output, &log_config, options)? else {
            return Ok(1);
        };
        return scan_source(output, &batman_config, &log_config, &source);
    }

    for source in &log_config.sources {
        if source.exists() {
            scan_source(output, &batman_config, &log_config, source)?;
        }
    }
    Ok(0)
}

fn selected_source(
    output: &mut Output,
    config: &LogAuditConfig,
    options: LogOptions,
) -> BatmanResult<Option<LogSource>> {
    let Some(selector) = options.selector else {
        let Some(path) = options.path else {
            return Err(BatmanError::Usage(
                "logs requires SOURCE_OR_RULE_OR_PATH when selecting a single source".to_string(),
            ));
        };
        return selected_path_source(output, config, path);
    };

    if let Some(path) = options.path {
        if !path.exists() {
            output.error(format!("The path {} does not exist.", path.display()))?;
            return Ok(None);
        }
        if let Some(source) = config.find_source(&selector) {
            let mut source = source.clone();
            source.override_source = Some(path);
            return Ok(Some(source));
        }
        if config.find_rule(&selector).is_some() {
            return Ok(Some(virtual_file_source(selector, path)));
        }
        output.error(format!(
            "No log_source or rule with the name \"{selector}\" exists"
        ))?;
        return Ok(None);
    }

    let selector_path = std::path::PathBuf::from(&selector);
    if selector_path.exists() {
        return selected_path_source(output, config, selector_path);
    }
    if config.find_rule(&selector).is_some() {
        output.error(format!(
            "Rule \"{selector}\" requires a path; use `batman logs {selector} PATH`"
        ))?;
        return Ok(None);
    }

    let Some(source) = config.find_source(&selector) else {
        output.error(format!("A log_source with name {selector} was not found"))?;
        return Ok(None);
    };
    if !source.exists() {
        output.error(format!("A log_source with name {selector} was not found"))?;
        return Ok(None);
    }
    Ok(Some(source.clone()))
}

fn selected_path_source(
    output: &mut Output,
    config: &LogAuditConfig,
    path: std::path::PathBuf,
) -> BatmanResult<Option<LogSource>> {
    if !path.exists() {
        output.error(format!("The path {} does not exist.", path.display()))?;
        return Ok(None);
    }
    let file_sources = config
        .sources
        .iter()
        .filter(|source| source.kind == SourceKind::File)
        .collect::<Vec<_>>();
    if file_sources.len() != 1 {
        output.error(
            "The path is ambiguous; pass SOURCE PATH or RULE PATH so Batman knows which rules to use",
        )?;
        return Ok(None);
    }
    let mut source = file_sources[0].clone();
    source.override_source = Some(path);
    Ok(Some(source))
}

fn virtual_file_source(rule: String, path: std::path::PathBuf) -> LogSource {
    LogSource {
        kind: SourceKind::File,
        name: "Virtual".to_string(),
        description: "Virtual".to_string(),
        top: 1000,
        rule_names: vec![rule],
        path: Some(path),
        container: None,
        since: None,
        args: None,
        trim_prefix: None,
        reset: None,
        group_by: None,
        report_to: None,
        override_source: None,
    }
}

fn scan_source(
    output: &mut Output,
    batman_config: &BatmanConfig,
    log_config: &LogAuditConfig,
    source: &LogSource,
) -> BatmanResult<u8> {
    output.line(
        Style::Info,
        format!(
            "Processing LogSource: {} : source {}",
            source.description,
            source.source_label()
        ),
    )?;
    let summary = scan_log_source(log_config, source)?;
    output.line(
        Style::Plain,
        format!(
            "Checked {} log lines, matched: {}",
            summary.line_count, summary.match_count
        ),
    )?;
    if summary.match_count == 0 {
        output.line(Style::Success, "No problems found.")?;
    } else {
        output.error(format!("Found {} problems.", summary.match_count))?;
        output.line(Style::Plain, &summary.report)?;
    }
    notify_log_result(&batman_config.email, output, source, &summary)?;
    Ok(0)
}
