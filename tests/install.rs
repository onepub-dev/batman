use std::{fs, path::Path};

use batman::cli::{GlobalOptions, InstallOptions};
use batman::commands::{CommandContext, install};
use batman::config::LocalSettings;
use batman::output::Output;
use batman::security::file_content_hash;

const EXPECTED_CONFIG_HASH_ENV: &str = "BATMAN_EXPECTED_CONFIG_HASH";

#[test]
fn install_with_config_path_reports_written_paths() {
    let root = unique_dir("batman-install");
    let config_dir = root.join("config");
    fs::create_dir_all(&root).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let logfile = root.join("install.log");

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::run(
        &context,
        &mut output,
        InstallOptions {
            db_path: Some(config_dir.join("db")),
            overwrite: true,
            systemd_dir: None,
            launchd_dir: None,
            windows_task_dir: None,
            ..InstallOptions::default()
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    assert!(config_path.exists());
    assert!(!config_dir.join("docker-compose.yaml").exists());
    assert!(!config_dir.join("DockerFile").exists());
    assert!(
        fs::read_to_string(&config_path)
            .unwrap()
            .contains(&format!("db_path: {}", config_dir.join("db").display()))
    );
    let installed_rules = fs::read_to_string(config_dir.join("batman.yaml")).unwrap();
    assert!(!installed_rules.contains("log_audits:"));
    assert!(!installed_rules.contains("/var/log/myapp/file.log"));
    let install_output = fs::read_to_string(logfile).unwrap();
    assert!(install_output.contains("Installation complete."));
    assert!(install_output.contains(&format!("Configuration: {}", config_path.display())));
    assert!(install_output.contains(&format!(
        "Database path: {}",
        config_dir.join("db").display()
    )));
    assert!(!install_output.contains("Docker"));
    assert!(install_output.ends_with("Run 'batman baseline' to create the initial baseline.\n"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_can_write_systemd_service_and_timer() {
    let root = unique_dir("batman-install-systemd");
    let config_dir = root.join("config");
    let systemd_dir = root.join("systemd");
    fs::create_dir_all(&root).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let logfile = root.join("install.log");

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::run(
        &context,
        &mut output,
        InstallOptions {
            db_path: Some(config_dir.join("db")),
            overwrite: true,
            systemd_dir: Some(systemd_dir.clone()),
            launchd_dir: None,
            windows_task_dir: None,
            ..InstallOptions::default()
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    let service = fs::read_to_string(systemd_dir.join("batman-scan.service")).unwrap();
    let timer = fs::read_to_string(systemd_dir.join("batman-scan.timer")).unwrap();
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--quiet --config"));
    assert!(!service.contains("BATMAN_REQUIRE_SIGNED_BASELINE"));
    assert!(service.contains(&systemd_arg(&config_path)));
    assert!(timer.contains("OnCalendar=*-*-* 22:30:00"));
    assert!(
        fs::read_to_string(logfile)
            .unwrap()
            .contains("Systemd units:")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_can_write_launchd_plist() {
    let root = unique_dir("batman-install-launchd");
    let config_dir = root.join("config");
    let launchd_dir = root.join("launchd");
    fs::create_dir_all(&root).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let logfile = root.join("install.log");

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::run(
        &context,
        &mut output,
        InstallOptions {
            db_path: Some(config_dir.join("db")),
            overwrite: true,
            systemd_dir: None,
            launchd_dir: Some(launchd_dir.clone()),
            windows_task_dir: None,
            ..InstallOptions::default()
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    let plist = fs::read_to_string(launchd_dir.join("com.noojee.batman.scan.plist")).unwrap();
    assert!(plist.contains("<string>com.noojee.batman.scan</string>"));
    assert!(plist.contains("<string>--quiet</string>"));
    assert!(plist.contains("<string>--config</string>"));
    assert!(!plist.contains("EnvironmentVariables"));
    assert!(plist.contains(&config_path.display().to_string()));
    assert!(plist.contains("<integer>22</integer>"));
    assert!(
        fs::read_to_string(logfile)
            .unwrap()
            .contains("Launchd plist:")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_can_write_windows_task_xml() {
    let root = unique_dir("batman-install-windows-task");
    let config_dir = root.join("config");
    let task_dir = root.join("tasks");
    fs::create_dir_all(&root).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let logfile = root.join("install.log");

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::run(
        &context,
        &mut output,
        InstallOptions {
            db_path: Some(config_dir.join("db")),
            overwrite: true,
            systemd_dir: None,
            launchd_dir: None,
            windows_task_dir: Some(task_dir.clone()),
            ..InstallOptions::default()
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    let task = fs::read_to_string(task_dir.join("batman-scan.xml")).unwrap();
    assert!(task.contains("<Task version=\"1.4\""));
    assert!(task.contains("<RunLevel>HighestAvailable</RunLevel>"));
    assert!(task.contains("<Command>"));
    assert!(task.contains("--quiet --config"));
    assert!(!task_dir.join("batman-scan.cmd").exists());
    assert!(task.contains(&config_path.display().to_string()));
    assert!(
        fs::read_to_string(logfile)
            .unwrap()
            .contains("Windows task XML:")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_scheduler_artifacts_can_include_production_environment() {
    let root = unique_dir("batman-install-production-scheduler");
    let config_dir = root.join("config");
    let systemd_dir = root.join("systemd");
    let launchd_dir = root.join("launchd");
    let task_dir = root.join("tasks");
    fs::create_dir_all(&root).unwrap();
    let config_path = config_dir.join("batman.yaml");
    let logfile = root.join("install.log");

    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::run(
        &context,
        &mut output,
        InstallOptions {
            db_path: Some(config_dir.join("db")),
            overwrite: true,
            systemd_dir: Some(systemd_dir.clone()),
            launchd_dir: Some(launchd_dir.clone()),
            windows_task_dir: Some(task_dir.clone()),
            production_scheduler: true,
            scheduler_env: vec![
                "BATMAN_BASELINE_PUBLIC_KEY=abc123".to_string(),
                "BATMAN_BASELINE_MIN_GENERATION=42".to_string(),
                "BATMAN_AUDIT_TCP=127.0.0.1:2525".to_string(),
            ],
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    let expected_config_env = format!(
        "{EXPECTED_CONFIG_HASH_ENV}={}",
        hex_hash(&file_content_hash(&config_path).unwrap())
    );
    let service = fs::read_to_string(systemd_dir.join("batman-scan.service")).unwrap();
    assert!(service.contains("Environment=\"BATMAN_REQUIRE_SIGNED_BASELINE=1\""));
    assert!(service.contains("Environment=\"BATMAN_STRICT_CONFIG=1\""));
    assert!(service.contains("Environment=\"BATMAN_AUDIT_SINK_REQUIRED=1\""));
    assert!(service.contains(&format!("Environment=\"{expected_config_env}\"")));
    assert!(service.contains("Environment=\"BATMAN_BASELINE_PUBLIC_KEY=abc123\""));
    assert!(service.contains("Environment=\"BATMAN_BASELINE_MIN_GENERATION=42\""));
    assert!(service.contains("Environment=\"BATMAN_AUDIT_TCP=127.0.0.1:2525\""));

    let plist = fs::read_to_string(launchd_dir.join("com.noojee.batman.scan.plist")).unwrap();
    assert!(plist.contains("<key>EnvironmentVariables</key>"));
    assert!(plist.contains("<key>BATMAN_REQUIRE_SIGNED_BASELINE</key>"));
    assert!(plist.contains(&format!("<key>{EXPECTED_CONFIG_HASH_ENV}</key>")));
    assert!(plist.contains("<string>abc123</string>"));
    assert!(plist.contains("<key>BATMAN_BASELINE_MIN_GENERATION</key>"));
    assert!(plist.contains("<string>42</string>"));

    let task = fs::read_to_string(task_dir.join("batman-scan.xml")).unwrap();
    let script = fs::read_to_string(task_dir.join("batman-scan.cmd")).unwrap();
    assert!(task.contains("batman-scan.cmd"));
    assert!(script.contains("set \"BATMAN_REQUIRE_SIGNED_BASELINE=1\""));
    assert!(script.contains(&format!("set \"{expected_config_env}\"")));
    assert!(script.contains("set \"BATMAN_BASELINE_PUBLIC_KEY=abc123\""));
    assert!(script.contains("set \"BATMAN_BASELINE_MIN_GENERATION=42\""));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn host_default_rules_are_platform_specific_and_do_not_include_log_examples() {
    let rules = install::default_rules();

    assert!(rules.contains("file_integrity:"));
    assert!(rules.contains("scan_byte_limit: 0"));
    #[cfg(target_os = "linux")]
    assert!(rules.contains("- /snap"));
    assert!(!rules.contains("log_audits:"));
    assert!(!rules.contains("myapp"));
}

#[test]
fn windows_install_rules_can_expand_fixed_drive_scan_paths() {
    let rules = install::with_windows_scan_paths(
        r#"
file_integrity:
  scan_paths:
    - C:\
  exclusions:
    - C:\Windows\Temp
"#,
        &["C:\\".to_string(), "D:\\".to_string()],
    );

    assert!(rules.contains("  scan_paths:\n    - C:\\\n    - D:\\"));
    assert!(rules.contains("  exclusions:\n    - C:\\Windows\\Temp"));
}

#[test]
fn missing_rule_file_returns_install_error() {
    let root = unique_dir("batman-install-missing-rule");
    fs::create_dir_all(&root).unwrap();
    let config_path = root.join("batman.yaml");
    let logfile = root.join("output.log");
    let context = CommandContext {
        global: GlobalOptions {
            colour: false,
            logfile: Some(logfile.clone()),
            ..GlobalOptions::default()
        },
        local_settings: LocalSettings::for_config_path(config_path.clone()),
    };
    let mut output = Output::new(&context.global).unwrap();

    let code = install::ensure_rule_file(&context, &mut output).unwrap();

    assert_eq!(code, 1);
    assert!(!config_path.exists());
    assert!(
        fs::read_to_string(logfile)
            .unwrap()
            .contains("You must run 'batman install' first")
    );

    fs::remove_dir_all(root).unwrap();
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

fn systemd_arg(path: &Path) -> String {
    format!(
        "\"{}\"",
        path.display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}
