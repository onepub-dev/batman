use crate::cli::GlobalOptions;
use crate::config::LocalSettings;
use crate::errors::BatmanResult;
use crate::output::{Output, Style};
use std::path::Path;

use crate::security::{config_trust_issues, data_path_trust_issues, verify_expected_config_hash};
use crate::system::is_privileged;

pub mod accept;
pub mod baseline;
pub mod checkpoint;
pub mod cron;
pub mod doctor;
pub mod harden;
pub mod install;
pub mod keygen;
pub mod logs;
pub mod review;
pub mod scan;
mod signing;

pub struct CommandContext {
    pub global: GlobalOptions,
    pub local_settings: LocalSettings,
}

pub fn ensure_trusted_config(context: &CommandContext, output: &mut Output) -> BatmanResult<bool> {
    if let Err(error) = verify_expected_config_hash(&context.local_settings.config_path) {
        output.error(error.to_string())?;
        return Ok(false);
    }
    if context.global.insecure || !is_privileged() {
        return Ok(true);
    }
    if context.local_settings.config_path_source == "default user location" {
        output.error(format!(
            "Refusing to use user config {} while running privileged. Run 'batman install' from an elevated shell or pass a trusted --config path.",
            context.local_settings.config_path.display()
        ))?;
        return Ok(false);
    }
    let issues = config_trust_issues(&context.local_settings.config_path, true);
    if issues.is_empty() {
        return Ok(true);
    }
    output.error(format!(
        "Refusing untrusted config {}",
        context.local_settings.config_path.display()
    ))?;
    for issue in issues.iter().take(5) {
        output.line(
            Style::Warn,
            format!("  {}: {}", issue.path.display(), issue.message),
        )?;
    }
    if issues.len() > 5 {
        output.line(
            Style::Warn,
            format!("  ... {} more trust issues", issues.len() - 5),
        )?;
    }
    Ok(false)
}

pub fn ensure_trusted_data_path(
    context: &CommandContext,
    output: &mut Output,
    path: &Path,
) -> BatmanResult<bool> {
    if context.global.insecure || !is_privileged() {
        return Ok(true);
    }
    let issues = data_path_trust_issues(path, true);
    if issues.is_empty() {
        return Ok(true);
    }
    output.error(format!("Refusing untrusted database {}", path.display()))?;
    for issue in issues.iter().take(5) {
        output.line(
            Style::Warn,
            format!("  {}: {}", issue.path.display(), issue.message),
        )?;
    }
    if issues.len() > 5 {
        output.line(
            Style::Warn,
            format!("  ... {} more trust issues", issues.len() - 5),
        )?;
    }
    Ok(false)
}
