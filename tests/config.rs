use std::fs;

use batman::config::BatmanConfig;

#[test]
fn loads_file_integrity_settings() {
    let dir = unique_dir("batman-config");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
file_integrity:
  scan_byte_limit: 42
  scan_threads: 6
  scan_buffer_size: 131072
  db_path: ~/batman-db
  scan_paths:
    - /etc
    - /bin
  exclusions:
    - /etc/ssl
  excluded_filesystems:
    - squashfs
    - proc
  metadata_only:
    - /var/lib/app.db
    - /var/lib/runtime/
    - /var/lib/cache/*
  registry_paths:
    - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    assert_eq!(config.file_integrity.scan_byte_limit, 42);
    assert_eq!(config.file_integrity.scan_threads, 6);
    assert_eq!(config.file_integrity.scan_buffer_size, 131072);
    assert_eq!(config.file_integrity.scan_paths.len(), 2);
    assert_eq!(config.file_integrity.exclusions.len(), 1);
    assert_eq!(
        config.file_integrity.excluded_filesystems,
        vec!["squashfs".to_string(), "proc".to_string()]
    );
    assert_eq!(config.file_integrity.metadata_only.len(), 2);
    assert_eq!(config.file_integrity.metadata_directories.len(), 1);
    assert_eq!(
        config.file_integrity.registry_paths,
        vec!["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()]
    );
    assert!(
        config
            .file_integrity
            .is_metadata_only("/var/lib/app.db".as_ref())
    );
    assert!(
        config
            .file_integrity
            .is_metadata_only("/var/lib/cache/object.bin".as_ref())
    );
    assert!(
        config
            .file_integrity
            .is_metadata_directory("/var/lib/runtime".as_ref())
    );
    assert!(
        !config
            .file_integrity
            .is_metadata_only("/var/lib/runtime/file.log".as_ref())
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loads_baseline_public_key_from_file_integrity_settings() {
    let dir = unique_dir("batman-config-public-key");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
file_integrity:
  baseline_public_key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  scan_paths: []
  exclusions: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    assert_eq!(
        config.file_integrity.baseline_public_key.as_deref(),
        Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn defaults_scan_threads_to_low_memory_worker_count() {
    let dir = unique_dir("batman-config-scan-threads");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
file_integrity:
  scan_paths: []
  exclusions: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();
    let expected = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_sub(2)
        .clamp(1, 4);

    assert_eq!(config.file_integrity.scan_threads, expected);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn defaults_scan_byte_limit_to_whole_file() {
    let dir = unique_dir("batman-config-scan-byte-limit");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
file_integrity:
  scan_paths: []
  exclusions: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    assert_eq!(config.file_integrity.scan_byte_limit, 0);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn defaults_linux_excluded_filesystems_unless_overridden() {
    let dir = unique_dir("batman-config-filesystems");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
file_integrity:
  scan_paths: []
  exclusions: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    if cfg!(target_os = "linux") {
        assert!(config.file_integrity.is_filesystem_excluded("squashfs"));
        assert!(config.file_integrity.is_filesystem_excluded("proc"));
    } else {
        assert!(config.file_integrity.excluded_filesystems.is_empty());
    }

    fs::write(
        &yaml,
        r#"
file_integrity:
  scan_paths: []
  exclusions: []
  excluded_filesystems: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    assert!(config.file_integrity.excluded_filesystems.is_empty());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn supports_legacy_email_aliases_from_bundled_rules() {
    let dir = unique_dir("batman-config-email");
    fs::create_dir_all(&dir).unwrap();
    let yaml = dir.join("batman.yaml");
    fs::write(
        &yaml,
        r#"
report_on_success: true
report_to: failed.scan@example.com
email_from_address: scanner@example.com
file_integrity:
  scan_paths: []
  exclusions: []
"#,
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &dir).unwrap();

    assert!(config.email.send_on_success);
    assert_eq!(config.email.fail_to_address, "failed.scan@example.com");

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn excludes_database_but_not_settings_directory() {
    let dir = unique_dir("batman-config-exclusions");
    let config_dir = dir.join("config");
    fs::create_dir_all(&config_dir).unwrap();
    let yaml = config_dir.join("batman.yaml");
    let db_path = dir.join("db");
    fs::write(
        &yaml,
        format!(
            r#"
file_integrity:
  db_path: {}
  scan_paths:
    - /
  exclusions: []
"#,
            db_path.display()
        ),
    )
    .unwrap();

    let config = BatmanConfig::load(&yaml, &config_dir).unwrap();

    assert!(!config.file_integrity.is_excluded(&dir.join("batman.yaml")));
    assert!(
        config
            .file_integrity
            .is_excluded(&db_path.join("baseline.bfi"))
    );

    fs::remove_dir_all(dir).unwrap();
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
}
