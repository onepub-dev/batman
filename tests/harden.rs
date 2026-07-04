use std::fs;
use std::path::PathBuf;

use batman::cli::{GlobalOptions, HardenOptions};
use batman::commands::{CommandContext, harden};
use batman::config::LocalSettings;
use batman::output::Output;

#[test]
fn harden_dry_run_lists_artifacts_without_changing_flags() {
    let root = unique_dir("batman-harden-dry-run");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("harden.log");
    write_config_and_artifacts(&config_path, &db_path);

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let code = harden::run(&context, &mut output, HardenOptions { dry_run: true }, true).unwrap();

    assert_eq!(code, 0);
    let log = fs::read_to_string(logfile).unwrap();
    assert!(log.contains("Hardening Batman artifacts (dry run)"));
    assert!(log.contains("config: locked would update"));
    assert!(log.contains("baseline records: locked would update"));
    assert!(log.contains("baseline index: locked would update"));
    assert!(log.contains("baseline manifest: locked would update"));
    assert!(log.contains("audit log: append-locked would update"));
    assert!(log.contains("executable: locked would update"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unharden_dry_run_lists_artifacts_without_changing_flags() {
    let root = unique_dir("batman-unharden-dry-run");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("unharden.log");
    write_config_and_artifacts(&config_path, &db_path);

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let code = harden::run(
        &context,
        &mut output,
        HardenOptions { dry_run: true },
        false,
    )
    .unwrap();

    assert_eq!(code, 0);
    let log = fs::read_to_string(logfile).unwrap();
    assert!(log.contains("Unhardening Batman artifacts (dry run)"));
    assert!(log.contains("config: unlocked would update"));
    assert!(log.contains("audit log: append-unlocked would update"));
    assert!(log.contains("executable: unlocked would update"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn harden_reports_missing_baseline_artifacts() {
    let root = unique_dir("batman-harden-missing");
    let config_path = root.join("config").join("batman.yaml");
    let db_path = root.join("db");
    let logfile = root.join("harden-missing.log");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::create_dir_all(&db_path).unwrap();
    fs::write(
        &config_path,
        format!(
            "file_integrity:\n  db_path: {}\n  scan_paths: []\n",
            db_path.display()
        ),
    )
    .unwrap();

    let context = test_context(&config_path, &logfile);
    let mut output = Output::new(&context.global).unwrap();
    let code = harden::run(&context, &mut output, HardenOptions { dry_run: true }, true).unwrap();

    assert_eq!(code, 1);
    assert!(
        fs::read_to_string(logfile)
            .unwrap()
            .contains("run 'batman baseline' before production hardening")
    );

    fs::remove_dir_all(root).unwrap();
}

fn test_context(config_path: &std::path::Path, logfile: &std::path::Path) -> CommandContext {
    CommandContext {
        global: GlobalOptions {
            colour: false,
            insecure: true,
            logfile: Some(logfile.to_path_buf()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.to_path_buf()),
    }
}

fn write_config_and_artifacts(config_path: &std::path::Path, db_path: &std::path::Path) {
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::create_dir_all(db_path).unwrap();
    fs::write(
        config_path,
        format!(
            "file_integrity:\n  db_path: {}\n  scan_paths: []\n",
            db_path.display()
        ),
    )
    .unwrap();
    for name in [
        "baseline.bfi",
        "baseline.idx",
        "baseline.manifest",
        "audit.log",
    ] {
        fs::write(db_path.join(name), name).unwrap();
    }
}

fn unique_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
