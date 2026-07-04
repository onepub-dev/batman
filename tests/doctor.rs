use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};

use batman::cli::{DoctorOptions, GlobalOptions};
use batman::commands::{CommandContext, doctor};
use batman::config::{BatmanConfig, LocalSettings};
use batman::integrity::store::BaselineWriter;
use batman::output::Output;
use batman::security::file_content_hash;

const EXPECTED_CONFIG_HASH_ENV: &str = "BATMAN_EXPECTED_CONFIG_HASH";

#[test]
fn doctor_reports_runtime_paths_and_missing_baseline() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Batman Doctor"));
    assert!(report.contains("Runtime"));
    assert!(report.contains("Settings"));
    assert!(report.contains(&format!(
        "Active config file  : {} (file exists, test fixture)",
        config_path.display()
    )));
    assert!(report.contains("Config file search:"));
    assert!(report.contains("  system default"));
    assert!(!report.contains(&format!("  user default       : {}", config_path.display())));
    assert!(report.contains(&format!(
        "Database path       : {} (missing)",
        db_dir.display()
    )));
    assert!(report.contains("Baseline            : missing - run 'batman baseline'"));
    assert!(report.contains("Scan paths          : 1"));
    assert!(report.contains("Log Scanning"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_reports_file_integrity_policy_warnings() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-policy");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-policy.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

    let config_path = config_dir.join("batman.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 42
  scan_threads: 999
  db_path: {}
  scan_paths:
    - {}
  exclusions:
    - /
  excluded_filesystems: []
  metadata_only:
    - /
"#,
            db_dir.display(),
            scan_dir.display()
        ),
    )
    .unwrap();
    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Policy lint"));
    assert!(report.contains("scan_byte_limit is 42B"));
    assert!(report.contains("scan_threads 999 exceeds default worker cap"));
    assert!(report.contains("exclusion / removes an entire scan root"));
    assert!(report.contains("metadata_only / disables content hashing broadly"));
    if cfg!(target_os = "linux") {
        assert!(report.contains("excluded_filesystems is empty"));
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_policy_lint_accepts_enabled_signed_baseline_policy() {
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
    }
    let root = unique_dir("batman-doctor-signing-policy");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-signing-policy.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
    unsafe {
        std::env::set_var(
            EXPECTED_CONFIG_HASH_ENV,
            hex_hash(&file_content_hash(&config_path).unwrap()),
        );
    }

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Policy lint         : ok"));
    assert!(report.contains("Config pin          : ok"));
    assert!(!report.contains("BATMAN_REQUIRE_SIGNED_BASELINE is not enabled"));
    assert!(!report.contains("signed baselines cannot be verified"));

    unsafe {
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_AUDIT_TCP");
        std::env::remove_var("BATMAN_AUDIT_SYSLOG");
        std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        std::env::remove_var(EXPECTED_CONFIG_HASH_ENV);
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_strict_fails_when_production_hardening_is_missing() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-strict");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-strict.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(
            &context,
            &mut output,
            DoctorOptions {
                strict: true,
                production: false
            }
        )
        .unwrap(),
        1
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Production doctor failed"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_reports_config_drift_against_baseline_hash() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-config-drift");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-config-drift.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

    let config_path = config_dir.join("batman.yaml");
    let initial_config = format!(
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
    );
    fs::write(&config_path, initial_config).unwrap();

    let config_hash = file_content_hash(&config_path).unwrap();
    let writer = BaselineWriter::create_with_config_hash(&db_dir, 0, config_hash).unwrap();
    writer.finish().unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );
    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Baseline generation : 1"));
    assert!(report.contains("Baseline created    : "));
    assert!(report.contains(" UTC"));
    assert!(report.contains("Config drift        : ok"));

    fs::write(
        &config_path,
        format!(
            r#"
file_integrity:
  scan_byte_limit: 0
  db_path: {}
  scan_paths:
    - {}
  exclusions:
    - {}
"#,
            db_dir.display(),
            scan_dir.display(),
            scan_dir.join("cache").display()
        ),
    )
    .unwrap();
    let drift_logfile = root.join("doctor-config-drift-after.log");
    let drift_context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(drift_logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut drift_output = Output::new(&drift_context.global).unwrap();

    assert_eq!(
        doctor::run(
            &drift_context,
            &mut drift_output,
            DoctorOptions {
                strict: true,
                production: false
            }
        )
        .unwrap(),
        1
    );
    let drift_report = fs::read_to_string(&drift_logfile).unwrap();
    assert!(drift_report.contains("Config drift        : active config differs from baseline"));

    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_linux_file_flag_advisories_when_supported() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-linux-flags");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-linux-flags.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
    let config_hash = file_content_hash(&config_path).unwrap();
    let writer = BaselineWriter::create_with_config_hash(&db_dir, 0, config_hash).unwrap();
    writer.finish().unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );

    let report = fs::read_to_string(&logfile).unwrap();
    if batman::integrity::store::linux_inode_flags(&config_path)
        .unwrap()
        .is_some()
    {
        assert!(report.contains("Linux file flags    : 4 advisory item(s)"));
        assert!(report.contains(&format!(
            "config {} is not immutable",
            config_path.display()
        )));
        assert!(report.contains("baseline.bfi"));
        assert!(report.contains("consider chattr +i"));
    } else {
        assert!(report.contains("Linux file flags    : ok or unsupported"));
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_production_fails_when_batman_paths_are_not_monitored() {
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
    }
    let root = unique_dir("batman-doctor-production-self");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-production-self.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(
            &context,
            &mut output,
            DoctorOptions {
                strict: false,
                production: true
            }
        )
        .unwrap(),
        1
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Self monitoring"));
    assert!(report.contains(&format!(
        "active config {} is not covered",
        config_path.display()
    )));
    assert!(report.contains("executable "));
    assert!(report.contains("Production doctor failed"));

    unsafe {
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_AUDIT_TCP");
        std::env::remove_var("BATMAN_AUDIT_SYSLOG");
        std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_production_rejects_metadata_only_self_monitoring() {
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
    }
    let root = unique_dir("batman-doctor-production-metadata-self");
    let config_dir = root.join("config");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-production-metadata-self.log");
    fs::create_dir_all(&config_dir).unwrap();

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
  metadata_only:
    - {}
"#,
            db_dir.display(),
            root.display(),
            config_path.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let loaded = BatmanConfig::load(&config_path, &config_dir).unwrap();
    assert!(
        loaded.file_integrity.is_metadata_only(&config_path),
        "metadata_only={:?} metadata_directories={:?}",
        loaded.file_integrity.metadata_only,
        loaded.file_integrity.metadata_directories
    );
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(
            &context,
            &mut output,
            DoctorOptions {
                strict: false,
                production: true
            }
        )
        .unwrap(),
        1
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Self monitoring"));
    assert!(report.contains(&format!(
        "active config {} is metadata-only",
        config_path.display()
    )));
    assert!(report.contains("Production doctor failed"));

    unsafe {
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_AUDIT_TCP");
        std::env::remove_var("BATMAN_AUDIT_SYSLOG");
        std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn doctor_reports_untrusted_scheduler_artifacts() {
    use std::os::unix::fs::PermissionsExt;

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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-scheduler-trust");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-scheduler-trust.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
    let service = config_dir.join("batman-scan.service");
    fs::write(&service, "[Service]\nExecStart=/usr/bin/batman scan\n").unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o666)).unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(&context, &mut output, DoctorOptions::default()).unwrap(),
        0
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Scheduler trust"));
    assert!(report.contains(&service.display().to_string()));
    assert!(report.contains("group/world writable"));

    unsafe {
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_AUDIT_TCP");
        std::env::remove_var("BATMAN_AUDIT_SYSLOG");
        std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn doctor_production_reports_scheduler_policy_warnings() {
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
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    let root = unique_dir("batman-doctor-scheduler-policy");
    let config_dir = root.join("config");
    let scan_dir = root.join("scan");
    let db_dir = root.join("baseline");
    let logfile = root.join("doctor-scheduler-policy.log");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&scan_dir).unwrap();

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
    fs::write(
        config_dir.join("batman-scan.service"),
        format!(
            "[Service]\nType=oneshot\nExecStart=/usr/bin/batman --quiet --config \"{}\" scan\n",
            config_path.display()
        ),
    )
    .unwrap();

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path),
    };
    let mut output = Output::new(&context.global).unwrap();

    assert_eq!(
        doctor::run(
            &context,
            &mut output,
            DoctorOptions {
                strict: false,
                production: true
            }
        )
        .unwrap(),
        1
    );

    let report = fs::read_to_string(&logfile).unwrap();
    assert!(report.contains("Scheduler policy"));
    assert!(report.contains("BATMAN_REQUIRE_SIGNED_BASELINE=1"));
    assert!(report.contains("BATMAN_STRICT_CONFIG=1"));
    assert!(report.contains("BATMAN_AUDIT_SINK_REQUIRED=1"));

    unsafe {
        std::env::remove_var("BATMAN_REQUIRE_SIGNED_BASELINE");
        std::env::remove_var("BATMAN_BASELINE_KEY");
        std::env::remove_var("BATMAN_BASELINE_PUBLIC_KEY");
        std::env::remove_var("BATMAN_BASELINE_PRIVATE_KEY");
        std::env::remove_var("BATMAN_BASELINE_MIN_GENERATION");
        std::env::remove_var("BATMAN_AUDIT_TCP");
        std::env::remove_var("BATMAN_AUDIT_SYSLOG");
        std::env::remove_var("BATMAN_AUDIT_SINK_REQUIRED");
        std::env::remove_var("BATMAN_STRICT_CONFIG");
    }
    fs::remove_dir_all(root).unwrap();
}

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn hex_hash(hash: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in hash {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
