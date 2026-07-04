use std::path::{Path, PathBuf};

use crate::audit::audit_path;
use crate::cli::HardenOptions;
use crate::commands::{CommandContext, ensure_trusted_config, ensure_trusted_data_path};
use crate::config::BatmanConfig;
use crate::errors::{BatmanError, BatmanResult};
use crate::output::{Output, Style};
use crate::security::{secure_config_path, secure_data_directory, secure_data_file};
use crate::system::{is_privileged, required_privilege_description};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protection {
    Immutable,
    AppendOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HardenTarget {
    label: &'static str,
    path: PathBuf,
    protection: Protection,
}

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: HardenOptions,
    lock: bool,
) -> BatmanResult<u8> {
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "Error: You must run with {} to {} Batman artifacts",
            required_privilege_description(),
            if lock { "harden" } else { "unharden" }
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

    let targets = harden_targets(
        &context.local_settings.config_path,
        &config.file_integrity.db_path,
        std::env::current_exe().ok().as_deref(),
    );
    let title = if lock { "Hardening" } else { "Unhardening" };
    let suffix = if options.dry_run { " (dry run)" } else { "" };
    output.line(Style::Info, format!("{title} Batman artifacts{suffix}"))?;

    let mut failures = 0_u8;
    for target in &targets {
        match apply_target(target, lock, options.dry_run) {
            Ok(message) => output.line(
                Style::Success,
                format!(
                    "{}: {} {}",
                    target.label,
                    action_word(lock, target.protection),
                    message
                ),
            )?,
            Err(error) => {
                failures = 1;
                output.line(
                    Style::Warn,
                    format!("{}: {}: {error}", target.label, target.path.display()),
                )?;
            }
        }
    }

    if failures == 0 {
        output.line(
            Style::Success,
            if lock {
                "Batman artifacts hardened."
            } else {
                "Batman artifacts unlocked for maintenance. Re-run 'batman harden' afterwards."
            },
        )?;
    }
    Ok(failures)
}

fn harden_targets(
    config_path: &Path,
    db_path: &Path,
    executable_path: Option<&Path>,
) -> Vec<HardenTarget> {
    let mut targets = vec![
        HardenTarget {
            label: "config",
            path: config_path.to_path_buf(),
            protection: Protection::Immutable,
        },
        HardenTarget {
            label: "baseline records",
            path: db_path.join("baseline.bfi"),
            protection: Protection::Immutable,
        },
        HardenTarget {
            label: "baseline index",
            path: db_path.join("baseline.idx"),
            protection: Protection::Immutable,
        },
        HardenTarget {
            label: "baseline manifest",
            path: db_path.join("baseline.manifest"),
            protection: Protection::Immutable,
        },
        HardenTarget {
            label: "audit log",
            path: audit_path(db_path),
            protection: Protection::AppendOnly,
        },
    ];
    if let Some(executable_path) = executable_path {
        targets.push(HardenTarget {
            label: "executable",
            path: executable_path.to_path_buf(),
            protection: Protection::Immutable,
        });
    }
    targets
}

fn apply_target(target: &HardenTarget, lock: bool, dry_run: bool) -> BatmanResult<String> {
    if !target.path.exists() {
        return Err(BatmanError::Config(
            "missing; run 'batman baseline' before production hardening".to_string(),
        ));
    }
    if dry_run {
        return Ok(format!("would update {}", target.path.display()));
    }

    if lock {
        secure_before_lock(target)?;
        platform_set_protection(&target.path, target.protection, true)?;
        Ok(format!("{}", target.path.display()))
    } else {
        platform_set_protection(&target.path, target.protection, false)?;
        secure_before_lock(target)?;
        Ok(format!("{}", target.path.display()))
    }
}

fn secure_before_lock(target: &HardenTarget) -> BatmanResult<()> {
    if target.label == "executable" {
        Ok(())
    } else if target.label == "config" {
        secure_config_path(&target.path)
    } else {
        if let Some(parent) = target.path.parent() {
            secure_data_directory(parent)?;
        }
        secure_data_file(&target.path)
    }
}

fn action_word(lock: bool, protection: Protection) -> &'static str {
    match (lock, protection) {
        (true, Protection::Immutable) => "locked",
        (true, Protection::AppendOnly) => "append-locked",
        (false, Protection::Immutable) => "unlocked",
        (false, Protection::AppendOnly) => "append-unlocked",
    }
}

#[cfg(target_os = "linux")]
fn platform_set_protection(path: &Path, protection: Protection, lock: bool) -> BatmanResult<()> {
    let flag = match (lock, protection) {
        (true, Protection::Immutable) => "+i",
        (false, Protection::Immutable) => "-i",
        (true, Protection::AppendOnly) => "+a",
        (false, Protection::AppendOnly) => "-a",
    };
    run_flag_command("chattr", flag, path)
}

#[cfg(target_os = "macos")]
fn platform_set_protection(path: &Path, protection: Protection, lock: bool) -> BatmanResult<()> {
    let flag = match (lock, protection) {
        (true, Protection::Immutable) => "uchg",
        (false, Protection::Immutable) => "nouchg",
        (true, Protection::AppendOnly) => "uappnd",
        (false, Protection::AppendOnly) => "nouappnd",
    };
    run_flag_command("chflags", flag, path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_flag_command(command: &str, flag: &str, path: &Path) -> BatmanResult<()> {
    let status = std::process::Command::new(command)
        .arg(flag)
        .arg(path)
        .status()
        .map_err(|error| BatmanError::io(format!("run {command} {}", path.display()), error))?;
    if status.success() {
        Ok(())
    } else {
        Err(BatmanError::Config(format!(
            "{command} {flag} {} failed with {status}",
            path.display()
        )))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_set_protection(_path: &Path, _protection: Protection, _lock: bool) -> BatmanResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Protection, harden_targets};

    #[test]
    fn harden_targets_cover_config_baseline_and_audit() {
        let targets = harden_targets(
            "/etc/batman/batman.yaml".as_ref(),
            "/var/lib/batman".as_ref(),
            Some("/usr/local/bin/batman".as_ref()),
        );

        assert_eq!(targets.len(), 6);
        assert_eq!(targets[0].label, "config");
        assert_eq!(targets[0].protection, Protection::Immutable);
        assert_eq!(
            targets[1].path,
            std::path::Path::new("/var/lib/batman/baseline.bfi")
        );
        assert_eq!(
            targets[2].path,
            std::path::Path::new("/var/lib/batman/baseline.idx")
        );
        assert_eq!(
            targets[3].path,
            std::path::Path::new("/var/lib/batman/baseline.manifest")
        );
        assert_eq!(
            targets[4].path,
            std::path::Path::new("/var/lib/batman/audit.log")
        );
        assert_eq!(targets[4].protection, Protection::AppendOnly);
        assert_eq!(
            targets[5].path,
            std::path::Path::new("/usr/local/bin/batman")
        );
        assert_eq!(targets[5].protection, Protection::Immutable);
    }
}
