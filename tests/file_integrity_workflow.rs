use std::fs;
use std::path::PathBuf;

use batman::cli::{AcceptOptions, BaselineOptions, GlobalOptions, ReviewOptions, ScanOptions};
use batman::commands::{CommandContext, accept, baseline, review, scan};
use batman::config::LocalSettings;
use batman::integrity::store::BaselineReader;
use batman::output::Output;
use batman::security::file_content_hash;

#[test]
fn baseline_then_scan_over_fixture_tree() {
    let root = unique_dir("batman-workflow");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("workflow.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("one.txt"), "abc").unwrap();
    fs::write(scan_dir.join("two.txt"), "def").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(log_path.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    let reader = BaselineReader::open(&db_dir).unwrap();
    assert_eq!(reader.record_count(), 3);

    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        0
    );

    let review_file = db_dir.join("reviews").join("latest.review.yaml");
    assert!(review_file.exists());
    let review_content = fs::read_to_string(&review_file).unwrap();
    assert!(review_content.contains("status: clean"));
    assert!(review_content.contains("scanned_at:"));
    assert!(review_content.contains("findings: []"));
    let audit = fs::read_to_string(db_dir.join("audit.log")).unwrap();
    assert!(audit.contains("\"action\":\"baseline\""));
    assert!(audit.contains("\"action\":\"scan\""));
    assert!(audit.contains("\"issues\":\"0\""));

    assert_eq!(
        review::run(&context, &mut output, ReviewOptions::default()).unwrap(),
        0
    );
    drop(output);

    let log = fs::read_to_string(log_path).unwrap();
    assert!(log.contains("No findings to review. Last scan:"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scan_reports_altered_new_and_deleted_files() {
    let root = unique_dir("batman-findings");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("scan.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("altered.txt"), "abc").unwrap();
    fs::write(scan_dir.join("deleted.txt"), "def").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
send_email_on_fail: false
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(log_path.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    fs::write(scan_dir.join("altered.txt"), "changed").unwrap();
    fs::write(scan_dir.join("new.txt"), "ghi").unwrap();
    fs::remove_file(scan_dir.join("deleted.txt")).unwrap();

    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        1
    );
    drop(output);

    let output = fs::read_to_string(log_path).unwrap();
    assert!(!output.contains(&format!(
        "MODIFIED {}",
        scan_dir.join("altered.txt").display()
    )));
    assert!(!output.contains(&format!("ADDED    {}", scan_dir.join("new.txt").display())));
    assert!(!output.contains(&format!(
        "DELETED  {}",
        scan_dir.join("deleted.txt").display()
    )));
    assert!(output.contains(
        "\n\nFile Integrity Scan found 3 issues: modified 1 added 1 deleted 1 moved 0. Scanned files: 2 Dirs: 1 Bytes:"
    ));
    assert!(!output.contains("Integrity: Detected altered file"));
    assert!(!output.contains("Integrity: New file created since baseline"));
    assert!(!output.contains("Error: file deleted"));

    let review = fs::read_to_string(db_dir.join("reviews").join("latest.review.yaml")).unwrap();
    assert!(review.contains(&format!("path: {}", scan_dir.join("altered.txt").display())));
    assert!(review.contains("kind: modified"));
    assert!(review.contains("before:"));
    assert!(review.contains("after:"));
    assert!(review.contains("checksum:"));
    assert!(review.contains("permissions_octal:"));
    assert!(review.contains(&format!("path: {}", scan_dir.join("new.txt").display())));
    assert!(review.contains("kind: added"));
    assert!(review.contains(&format!("path: {}", scan_dir.join("deleted.txt").display())));
    assert!(review.contains("kind: deleted"));
    assert!(review.contains("state: unreviewed"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scan_reports_and_approves_moved_files() {
    let root = unique_dir("batman-moved-file");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("moved.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    let old_path = scan_dir.join("old-name.txt");
    let new_path = scan_dir.join("new-name.txt");
    fs::write(&old_path, "same content").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
send_email_on_fail: false
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(log_path.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    fs::rename(&old_path, &new_path).unwrap();
    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        1
    );

    let review_file = db_dir.join("reviews").join("latest.review.yaml");
    let mut review_content = fs::read_to_string(&review_file).unwrap();
    assert!(review_content.contains("kind: moved"));
    assert!(review_content.contains(&format!("path: {}", new_path.display())));
    assert!(review_content.contains(&format!("previous_path: {}", old_path.display())));
    assert!(review_content.contains("before:"));
    assert!(review_content.contains("after:"));
    assert!(review_content.contains("moved: 1"));

    review_content = review_content
        .replace("state: unreviewed", "state: approved")
        .replace("action: none", "action: approve");
    fs::write(&review_file, review_content).unwrap();

    assert_eq!(
        review::run(
            &context,
            &mut output,
            ReviewOptions {
                apply: true,
                ..ReviewOptions::default()
            },
        )
        .unwrap(),
        0
    );
    drop(output);

    let mut reader = BaselineReader::open(&db_dir).unwrap();
    assert_eq!(reader.record_count(), 2);
    assert!(matches!(
        reader.lookup(&old_path).unwrap(),
        batman::integrity::store::LookupResult::Missing
    ));
    assert!(matches!(
        reader.lookup(&new_path).unwrap(),
        batman::integrity::store::LookupResult::Found { .. }
    ));

    let output = fs::read_to_string(log_path).unwrap();
    assert!(
        output
            .contains("File Integrity Scan found 1 issues: modified 0 added 0 deleted 0 moved 1.")
    );
    assert!(output.contains("Applied review. Exclusions: 0 Approvals: 1."));
    let audit = fs::read_to_string(db_dir.join("audit.log")).unwrap();
    assert!(audit.contains("\"action\":\"review_apply\""));
    assert!(audit.contains("\"approved_add\":\"1\""));
    assert!(audit.contains("\"approved_remove\":\"1\""));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scan_reports_and_approves_config_policy_changes() {
    let root = unique_dir("batman-policy-change");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("policy.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("one.txt"), "abc").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
send_email_on_fail: false
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(log_path.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    fs::write(
        &config_path,
        format!(
            r#"
send_email_on_fail: false
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
  metadata_only: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        1
    );
    let review_file = db_dir.join("reviews").join("latest.review.yaml");
    let mut review_content = fs::read_to_string(&review_file).unwrap();
    assert!(review_content.contains("kind: modified"));
    assert!(review_content.contains(&format!("path: {}", config_path.display())));
    assert!(review_content.contains("reason: policy"));
    assert!(review_content.contains("modified: 1"));

    review_content = review_content
        .replace("state: unreviewed", "state: approved")
        .replace("action: none", "action: approve");
    fs::write(&review_file, review_content).unwrap();

    assert_eq!(
        review::run(
            &context,
            &mut output,
            ReviewOptions {
                apply: true,
                ..ReviewOptions::default()
            },
        )
        .unwrap(),
        0
    );

    let reader = BaselineReader::open(&db_dir).unwrap();
    assert_eq!(
        reader.config_hash(),
        file_content_hash(&config_path).unwrap()
    );

    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        0
    );
    drop(output);

    let output = fs::read_to_string(log_path).unwrap();
    assert!(output.contains("Config changed since the baseline was created"));
    assert!(
        output
            .contains("File Integrity Scan found 1 issues: modified 1 added 0 deleted 0 moved 0.")
    );
    assert!(output.contains("File Integrity Scan complete. No errors."));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn file_command_reports_baseline_and_current_diagnostics() {
    let root = unique_dir("batman-file-command");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("command.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    let file_path = scan_dir.join("one.txt");
    fs::write(&file_path, "abc").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 25000000
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(log_path.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    assert_eq!(
        scan::run(
            &context,
            &mut output,
            ScanOptions {
                path: Some(file_path.clone()),
            },
        )
        .unwrap(),
        0
    );
    drop(output);

    let output = fs::read_to_string(log_path).unwrap();
    assert!(output.contains("Path Key:"));
    assert!(output.contains("Path Hash:"));
    assert!(output.contains("Marked: false"));
    assert!(output.contains("File integrity is intact!"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accept_directory_reconciles_baseline_records() {
    let root = unique_dir("batman-accept-command");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("changed.txt"), "before").unwrap();
    fs::write(scan_dir.join("deleted.txt"), "remove me").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 0
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    fs::write(scan_dir.join("changed.txt"), "after").unwrap();
    fs::write(scan_dir.join("new.txt"), "new file").unwrap();
    fs::remove_file(scan_dir.join("deleted.txt")).unwrap();

    assert_eq!(
        accept::run(
            &context,
            &mut output,
            AcceptOptions {
                path: scan_dir.clone(),
            },
        )
        .unwrap(),
        0
    );

    let mut reader = BaselineReader::open(&db_dir).unwrap();
    assert_eq!(reader.record_count(), 3);
    assert!(matches!(
        reader.lookup(&scan_dir.join("changed.txt")).unwrap(),
        batman::integrity::store::LookupResult::Found { .. }
    ));
    assert!(matches!(
        reader.lookup(&scan_dir.join("new.txt")).unwrap(),
        batman::integrity::store::LookupResult::Found { .. }
    ));
    assert!(matches!(
        reader.lookup(&scan_dir.join("deleted.txt")).unwrap(),
        batman::integrity::store::LookupResult::Missing
    ));
    let audit = fs::read_to_string(db_dir.join("audit.log")).unwrap();
    assert!(audit.contains("\"action\":\"accept\""));
    assert!(audit.contains(&format!(
        "\"scope\":\"{}\"",
        json_string_value(&scan_dir.display().to_string())
    )));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn review_command_adds_noisy_directory_to_config() {
    let root = unique_dir("batman-review-command");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let cache_dir = scan_dir.join("cache");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(scan_dir.join("stable.txt"), "stable").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 0
  db_path: {}
  scan_paths:
    - {}
  exclusions: []
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        baseline::run(&context, &mut output, BaselineOptions::default()).unwrap(),
        0
    );
    for index in 0..5 {
        fs::write(
            cache_dir.join(format!("generated-{index}.tmp")),
            "generated",
        )
        .unwrap();
    }

    assert_eq!(
        scan::run(&context, &mut output, ScanOptions::default()).unwrap(),
        1
    );

    let review_file = db_dir.join("reviews").join("latest.review.yaml");
    assert!(review_file.exists());
    let mut review_content = fs::read_to_string(&review_file).unwrap();
    assert!(review_content.contains(&cache_dir.display().to_string()));
    review_content = review_content.replace(
        "actions: []",
        &format!(
            "actions:\n- id: 1\n  kind: exclude\n  target: {}\n  affected_ids: ''\n  previous: []\n  applied: false",
            cache_dir.display()
        ),
    );
    fs::write(&review_file, review_content).unwrap();

    assert_eq!(
        review::run(
            &context,
            &mut output,
            ReviewOptions {
                apply: true,
                apply_path: Some(review_file.clone()),
                operator: Some("alice".to_string()),
                comment: Some("normal cache churn".to_string()),
                export: None,
                output: None,
                session: None,
                list: false,
                dry_run: false,
            },
        )
        .unwrap(),
        0
    );

    let updated = fs::read_to_string(&config_path).unwrap();
    assert!(
        updated.contains(&cache_dir.display().to_string())
            || updated.contains(&yaml_escaped_path(&cache_dir))
    );
    assert!(!updated.contains("log_audits:"));
    let applied_review = fs::read_to_string(&review_file).unwrap();
    assert!(applied_review.contains("status: applied"));
    assert!(applied_review.contains("applied_by: alice"));
    assert!(applied_review.contains("apply_comment: normal cache churn"));
    let audit = fs::read_to_string(db_dir.join("audit.log")).unwrap();
    assert!(audit.contains("\"action\":\"review_apply\""));
    assert!(audit.contains("\"exclusions\":\"1\""));
    assert!(audit.contains("\"approvals\":\"0\""));
    assert!(audit.contains("\"operator\":\"alice\""));
    assert!(audit.contains("\"comment\":\"normal cache churn\""));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn review_reports_actionable_message_when_no_review_exists() {
    let root = unique_dir("batman-missing-review");
    let config_dir = root.join("config");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let context = CommandContext {
        global: GlobalOptions {
            insecure: true,
            colour: false,
            quiet: true,
            logfile: Some(root.join("review.log")),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        review::run(&context, &mut output, ReviewOptions::default()).unwrap(),
        1
    );
    drop(output);

    let log = fs::read_to_string(root.join("review.log")).unwrap();
    assert!(log.contains("no review session found. Run 'batman scan' first."));
    assert!(!log.contains("latest.review.yaml"));
    assert!(!log.contains("No such file or directory"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_unsigned_is_rejected_when_signed_baselines_are_required() {
    let root = unique_dir("batman-unsigned-rejected");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("db");
    let log_path = root.join("baseline.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();
    fs::write(scan_dir.join("one.txt"), "abc").unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            "file_integrity:\n  db_path: {}\n  scan_paths:\n    - {}\n  exclusions: []\n",
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_batman"))
        .env("BATMAN_REQUIRE_SIGNED_BASELINE", "1")
        .env_remove("BATMAN_BASELINE_PRIVATE_KEY")
        .env_remove("BATMAN_BASELINE_PUBLIC_KEY")
        .env_remove("BATMAN_BASELINE_KEY")
        .args([
            "--insecure",
            "--quiet",
            "--no-colour",
            "--logfile",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "baseline",
            "--unsigned",
        ])
        .status()
        .unwrap();

    assert!(!status.success());

    let log = fs::read_to_string(log_path).unwrap();
    assert!(log.contains("Refusing --unsigned"));
    assert!(log.contains("batman keygen"));
    assert!(!db_dir.join("baseline.manifest").exists());

    fs::remove_dir_all(root).unwrap();
}

fn unique_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn json_string_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn yaml_escaped_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}
