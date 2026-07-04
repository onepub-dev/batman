use std::fs;

use batman::logscan::{LogAuditConfig, scan_log_source};

#[test]
fn reset_discards_prior_grouped_matches_and_count() {
    let dir = unique_dir("batman-logscan-grouped-reset");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("grouped.log");
    fs::write(
        &log_path,
        "\
WARN [001] (Old.java:1) Slow before restart
INFO Service restarted
WARN [002] (New.java:2) Slow after restart
WARN [003] (New.java:2) Slow again
",
    )
    .unwrap();

    let yaml = format!(
        r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: grouped
      description: Grouped logs
      top: 10
      reset: Service restarted
      trim_prefix: '^\w+ \[[0-9]+\] '
      group_by: '\(.*?\.java\:.*?\)'
      rules:
        - rule: slow
  rules:
    - rule:
      name: slow
      description: Slow calls.
      selectors:
        - selector:
          type: contains
          description: Slow call
          match: ['Slow']
          risk: medium
"#,
        log_path.display()
    );

    let config = LogAuditConfig::parse(&yaml).unwrap();
    let source = config.find_source("grouped").unwrap();
    let summary = scan_log_source(&config, source).unwrap();

    assert_eq!(summary.line_count, 4);
    assert_eq!(summary.match_count, 2);
    assert!(summary.report.contains("Encountered reset marker"));
    assert!(summary.report.contains("(New.java:2)"));
    assert!(!summary.report.contains("(Old.java:1)"));
    assert!(!summary.report.contains("[002]"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rule_level_group_by_is_supported_for_existing_configs() {
    let dir = unique_dir("batman-logscan-rule-grouped");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("rule-grouped.log");
    fs::write(
        &log_path,
        "\
INFO (Worker.java:10) .java first
INFO (Worker.java:10) .java second
INFO (Other.java:20) .java third
",
    )
    .unwrap();

    let yaml = format!(
        r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: frequency
      description: Frequency logs
      top: 10
      rules:
        - rule: frequency
  rules:
    - rule:
      name: frequency
      description: High frequency source locations.
      group_by: '\(.*?\.java\:.*?\)'
      selectors:
        - selector:
          type: contains
          description: Java line
          match: ['.java']
          risk: low
"#,
        log_path.display()
    );

    let config = LogAuditConfig::parse(&yaml).unwrap();
    let source = config.find_source("frequency").unwrap();
    let summary = scan_log_source(&config, source).unwrap();

    assert_eq!(summary.match_count, 3);
    assert!(
        summary
            .report
            .contains("Java line (Worker.java:10) (occurred: 2)")
    );
    assert!(
        summary
            .report
            .contains("Java line (Other.java:20) (occurred: 1)")
    );

    fs::remove_dir_all(dir).unwrap();
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
