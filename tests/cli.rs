use std::path::PathBuf;

use batman::cli::{Cli, Command};

#[test]
fn parses_global_flags_and_baseline_options() {
    let cli = Cli::parse(vec![
        "--insecure".to_string(),
        "--quiet".to_string(),
        "--config".to_string(),
        "/tmp/batman.yaml".to_string(),
        "baseline".to_string(),
    ])
    .unwrap();

    assert!(cli.global.insecure);
    assert!(cli.global.quiet);
    assert_eq!(
        cli.global.config_path,
        Some(PathBuf::from("/tmp/batman.yaml"))
    );
    assert!(matches!(
        cli.command,
        Command::Baseline(options) if !options.unsigned
    ));
}

#[test]
fn parses_unsigned_baseline_option() {
    let cli = Cli::parse(vec!["baseline".to_string(), "--unsigned".to_string()]).unwrap();

    assert!(matches!(
        cli.command,
        Command::Baseline(options) if options.unsigned
    ));
}

#[test]
fn parses_install_scheduler_artifact_options() {
    let cli = Cli::parse(vec![
        "install".to_string(),
        "--systemd-dir".to_string(),
        "/etc/systemd/system".to_string(),
        "--launchd-dir".to_string(),
        "/Library/LaunchDaemons".to_string(),
        "--windows-task-dir".to_string(),
        "C:\\Batman".to_string(),
        "--production-scheduler".to_string(),
        "--scheduler-env".to_string(),
        "BATMAN_BASELINE_PUBLIC_KEY=abc123".to_string(),
        "--scheduler-env".to_string(),
        "BATMAN_BASELINE_MIN_GENERATION=42".to_string(),
    ])
    .unwrap();

    match cli.command {
        Command::Install(options) => {
            assert_eq!(
                options.systemd_dir,
                Some(PathBuf::from("/etc/systemd/system"))
            );
            assert_eq!(
                options.launchd_dir,
                Some(PathBuf::from("/Library/LaunchDaemons"))
            );
            assert_eq!(options.windows_task_dir, Some(PathBuf::from("C:\\Batman")));
            assert!(options.production_scheduler);
            assert_eq!(
                options.scheduler_env,
                vec![
                    "BATMAN_BASELINE_PUBLIC_KEY=abc123".to_string(),
                    "BATMAN_BASELINE_MIN_GENERATION=42".to_string()
                ]
            );
        }
        _ => panic!("expected install command"),
    }
}

#[test]
fn parses_logs_config_path_requirements_later() {
    let cli = Cli::parse(vec![
        "logs".to_string(),
        "creditcard".to_string(),
        "test/sample_logs/creditcards.log".to_string(),
    ])
    .unwrap();

    match cli.command {
        Command::Logs(options) => {
            assert_eq!(options.selector.as_deref(), Some("creditcard"));
            assert_eq!(
                options.path,
                Some(PathBuf::from("test/sample_logs/creditcards.log"))
            );
        }
        _ => panic!("expected logs command"),
    }
}

#[test]
fn parses_scan_target_path() {
    let cli = Cli::parse(vec!["scan".to_string(), "/tmp/file.txt".to_string()]).unwrap();

    match cli.command {
        Command::Scan(options) => {
            assert_eq!(options.path, Some(PathBuf::from("/tmp/file.txt")));
        }
        _ => panic!("expected scan command"),
    }
}

#[test]
fn parses_accept_positional_path() {
    let cli = Cli::parse(vec!["accept".to_string(), "/tmp/file.txt".to_string()]).unwrap();

    match cli.command {
        Command::Accept(options) => {
            assert_eq!(options.path, PathBuf::from("/tmp/file.txt"));
        }
        _ => panic!("expected accept command"),
    }
}

#[test]
fn parses_review_apply_export_and_session_options() {
    let cli = Cli::parse(vec!["review".to_string(), "--dry-run".to_string()]).unwrap();

    match cli.command {
        Command::Review(options) => {
            assert!(options.dry_run);
            assert!(!options.apply);
            assert_eq!(options.apply_path, None);
            assert_eq!(options.export, None);
        }
        _ => panic!("expected review command"),
    }

    let cli = Cli::parse(vec![
        "review".to_string(),
        "--apply".to_string(),
        "--operator".to_string(),
        "alice".to_string(),
        "--comment".to_string(),
        "ticket-123".to_string(),
        "/tmp/review.txt".to_string(),
    ])
    .unwrap();

    match cli.command {
        Command::Review(options) => {
            assert!(options.apply);
            assert_eq!(options.apply_path, Some(PathBuf::from("/tmp/review.txt")));
            assert_eq!(options.operator.as_deref(), Some("alice"));
            assert_eq!(options.comment.as_deref(), Some("ticket-123"));
            assert_eq!(options.export, None);
        }
        _ => panic!("expected review command"),
    }

    let cli = Cli::parse(vec!["review".to_string(), "--apply".to_string()]).unwrap();

    match cli.command {
        Command::Review(options) => {
            assert!(options.apply);
            assert_eq!(options.apply_path, None);
        }
        _ => panic!("expected review command"),
    }

    let cli = Cli::parse(vec![
        "review".to_string(),
        "--export".to_string(),
        "latest".to_string(),
        "--output".to_string(),
        "/tmp/review.txt".to_string(),
    ])
    .unwrap();

    match cli.command {
        Command::Review(options) => {
            assert_eq!(options.export.as_deref(), Some("latest"));
            assert_eq!(options.output, Some(PathBuf::from("/tmp/review.txt")));
        }
        _ => panic!("expected review command"),
    }
}

#[test]
fn parses_harden_and_unharden_options() {
    let cli = Cli::parse(vec!["harden".to_string(), "--dry-run".to_string()]).unwrap();

    match cli.command {
        Command::Harden(options) => assert!(options.dry_run),
        _ => panic!("expected harden command"),
    }

    let cli = Cli::parse(vec!["unharden".to_string(), "--dry-run".to_string()]).unwrap();

    match cli.command {
        Command::Unharden(options) => assert!(options.dry_run),
        _ => panic!("expected unharden command"),
    }
}

#[test]
fn parses_checkpoint_options() {
    let cli = Cli::parse(vec!["checkpoint".to_string(), "--json".to_string()]).unwrap();

    match cli.command {
        Command::Checkpoint(options) => assert!(options.json),
        _ => panic!("expected checkpoint command"),
    }
}

#[test]
fn rejects_path_option_where_positional_path_is_required() {
    let accept_error = Cli::parse(vec![
        "accept".to_string(),
        "--path".to_string(),
        "/tmp/file.txt".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(accept_error.contains("unexpected argument"));

    let review_error = Cli::parse(vec!["review".to_string(), "/tmp/cache".to_string()])
        .unwrap_err()
        .to_string();
    assert!(review_error.contains("--apply"));

    let logs_error = Cli::parse(vec![
        "logs".to_string(),
        "--path".to_string(),
        "/tmp/app.log".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(logs_error.contains("unexpected argument"));

    let logs_name_error = Cli::parse(vec!["logs".to_string(), "--name=app".to_string()])
        .unwrap_err()
        .to_string();
    assert!(logs_name_error.contains("unexpected argument"));

    let logs_rule_error = Cli::parse(vec!["logs".to_string(), "--rule=errors".to_string()])
        .unwrap_err()
        .to_string();
    assert!(logs_rule_error.contains("unexpected argument"));
}

#[test]
fn accepts_global_flags_after_command() {
    let cli = Cli::parse(vec!["baseline".to_string(), "--insecure".to_string()]).unwrap();

    assert!(cli.global.insecure);
    assert!(matches!(cli.command, Command::Baseline(_)));
}

#[test]
fn parses_progress_flag_and_rejects_removed_count_flag() {
    let cli = Cli::parse(vec!["--progress".to_string(), "baseline".to_string()]).unwrap();

    assert!(cli.global.progress);

    let error = Cli::parse(vec!["--count".to_string(), "baseline".to_string()])
        .unwrap_err()
        .to_string();
    assert!(error.contains("unexpected argument"));
}

#[test]
fn rejects_extra_args_for_no_arg_commands() {
    let error = Cli::parse(vec!["doctor".to_string(), "extra".to_string()])
        .unwrap_err()
        .to_string();

    assert!(error.contains("unexpected argument"));
}

#[test]
fn parses_doctor_strict_option() {
    let cli = Cli::parse(vec!["doctor".to_string(), "--strict".to_string()]).unwrap();

    match cli.command {
        Command::Doctor(options) => {
            assert!(options.strict);
            assert!(!options.production);
        }
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn parses_doctor_production_option() {
    let cli = Cli::parse(vec!["doctor".to_string(), "--production".to_string()]).unwrap();

    match cli.command {
        Command::Doctor(options) => {
            assert!(options.production);
            assert!(!options.strict);
        }
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn parses_keygen_command() {
    let cli = Cli::parse(vec!["keygen".to_string()]).unwrap();

    assert!(matches!(cli.command, Command::Keygen(_)));
}

#[test]
fn help_documents_core_commands_and_options() {
    let help = Cli::help();

    for expected in [
        "--config",
        "--progress",
        "--quiet",
        "--verbose",
        "--insecure",
        "baseline",
        "scan",
        "accept",
        "review",
        "harden",
        "unharden",
        "checkpoint",
        "doctor",
        "keygen",
    ] {
        assert!(help.contains(expected), "top-level help missing {expected}");
    }
    assert!(!help.contains("--count"));
    assert!(!help.contains("--rule-path"));
}

#[test]
fn command_help_documents_operational_options() {
    let install = Cli::command_help("install");
    for expected in [
        "--db-path",
        "--systemd-dir",
        "--launchd-dir",
        "--windows-task-dir",
        "--scheduler-env",
        "--production-scheduler",
    ] {
        assert!(
            install.contains(expected),
            "install help missing {expected}"
        );
    }

    let review = Cli::command_help("review");
    for expected in [
        "--apply",
        "--operator",
        "--comment",
        "--export",
        "--output",
        "--session",
        "--list",
        "--dry-run",
    ] {
        assert!(review.contains(expected), "review help missing {expected}");
    }

    let doctor = Cli::command_help("doctor");
    assert!(doctor.contains("--strict"));
    assert!(doctor.contains("--production"));

    let harden = Cli::command_help("harden");
    assert!(harden.contains("--dry-run"));
    assert!(harden.contains("executable"));

    let unharden = Cli::command_help("unharden");
    assert!(unharden.contains("--dry-run"));
    assert!(unharden.contains("executable"));

    let checkpoint = Cli::command_help("checkpoint");
    assert!(checkpoint.contains("--json"));

    let scan = Cli::command_help("scan");
    assert!(scan.contains("PATH"));

    let accept = Cli::command_help("accept");
    assert!(accept.contains("PATH"));

    let logs = Cli::command_help("logs");
    assert!(logs.contains("SOURCE_OR_RULE_OR_PATH"));

    let cron = Cli::command_help("cron");
    assert!(cron.contains("--baseline"));
    assert!(cron.contains("--scan"));
    assert!(cron.contains("--no-scan"));
    assert!(cron.contains("--logs"));
    assert!(cron.contains("--no-logs"));
}

#[test]
fn rejects_removed_docker_options_and_commands() {
    let docker_error = Cli::parse(vec!["baseline".to_string(), "--docker".to_string()])
        .unwrap_err()
        .to_string();
    assert!(docker_error.contains("unexpected argument"));

    let up_error = Cli::parse(vec!["up".to_string()]).unwrap_err().to_string();
    assert!(up_error.contains("unrecognized subcommand"));
}

#[test]
fn renders_top_level_help() {
    let help = Cli::help();

    assert!(help.contains("Usage:"));
    assert!(help.contains("Commands:"));
    assert!(help.contains("baseline"));
    assert!(help.contains("scan"));
    assert!(help.contains("logs"));
    assert!(help.contains("doctor"));
    assert!(help.contains("keygen"));
}
