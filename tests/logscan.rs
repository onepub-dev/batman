use std::fs;

use batman::logscan::{LogAuditConfig, Risk, scan_log_source};

#[test]
fn parses_rules_sources_and_scans_file_logs() {
    let dir = unique_dir("batman-logscan");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("app.log");
    fs::write(
        &log_path,
        "Info: started\nError: failed card 4111111111111111\nWarning: noisy\n",
    )
    .unwrap();

    let yaml = format!(
        r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: app
      description: App log
      top: 10
      rules:
        - rule: errors
        - rule: creditcard
  rules:
    - rule:
      name: errors
      description: Scans for errors.
      selectors:
        - selector:
          type: contains
          description: An error was detected
          match: ['Error']
          risk: high
          continue: false
    - rule:
      name: creditcard
      description: Scans for credit cards.
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected
          risk: critical
"#,
        log_path.display()
    );

    let config = LogAuditConfig::parse(&yaml).unwrap();
    let source = config.find_source("app").unwrap();
    let summary = scan_log_source(&config, source).unwrap();

    assert_eq!(summary.line_count, 3);
    assert_eq!(summary.match_count, 2);
    assert!(summary.report.contains("XXXX XXXX XXXX XXXX"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn simple_report_follows_log_source_rule_order() {
    let dir = unique_dir("batman-logscan-order");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("app.log");
    fs::write(&log_path, "Error and Warning\n").unwrap();

    let yaml = format!(
        r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: app
      top: 10
      rules:
        - rule: warnings
        - rule: errors
  rules:
    - rule:
      name: errors
      description: Error rule.
      selectors:
        - selector:
          type: contains
          description: Error found
          match: ['Error']
    - rule:
      name: warnings
      description: Warning rule.
      selectors:
        - selector:
          type: contains
          description: Warning found
          match: ['Warning']
"#,
        log_path.display()
    );

    let config = LogAuditConfig::parse(&yaml).unwrap();
    let source = config.find_source("app").unwrap();
    let summary = scan_log_source(&config, source).unwrap();
    let warning_index = summary.report.find("Rule: warnings").unwrap();
    let error_index = summary.report.find("Rule: errors").unwrap();

    assert!(warning_index < error_index);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_duplicate_log_source_names() {
    let yaml = r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: /tmp/one.log
      name: duplicate
      rules:
        - rule: errors
    - log_source:
      type: file
      path: /tmp/two.log
      name: duplicate
      rules:
        - rule: errors
  rules:
    - rule:
      name: errors
      description: Scans for errors.
      selectors:
        - selector:
          type: contains
          description: An error was detected
          match: ['Error']
"#;

    let error = LogAuditConfig::parse(yaml).unwrap_err().to_string();
    assert!(error.contains("duplicate log_source name"));
}

#[test]
fn rejects_log_sources_with_missing_required_fields() {
    let missing_file_path = r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      name: file_source
      rules:
        - rule: errors
  rules:
    - rule:
      name: errors
      selectors:
        - selector:
          type: contains
          match: ['Error']
"#;
    assert!(
        LogAuditConfig::parse(missing_file_path)
            .unwrap_err()
            .to_string()
            .contains("missing a path")
    );

    let docker_source = r#"
log_audits:
  log_sources:
    - log_source:
      type: docker
      name: docker_source
      rules:
        - rule: errors
  rules:
    - rule:
      name: errors
      selectors:
        - selector:
          type: contains
          match: ['Error']
"#;
    assert!(
        LogAuditConfig::parse(docker_source)
            .unwrap_err()
            .to_string()
            .contains("invalid log_source type docker")
    );
}

#[test]
fn rejects_unknown_rule_references_on_load() {
    let yaml = r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: /tmp/app.log
      name: app
      rules:
        - rule: missing
  rules:
    - rule:
      name: errors
      selectors:
        - selector:
          type: contains
          match: ['Error']
"#;

    assert!(
        LogAuditConfig::parse(yaml)
            .unwrap_err()
            .to_string()
            .contains("unknown rule missing")
    );
}

#[test]
fn supports_regex_and_one_of_selectors() {
    let dir = unique_dir("batman-logscan-regex");
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("app.log");
    fs::write(&log_path, "warn code=42\nignore code=10\nfatal code=99\n").unwrap();

    let yaml = format!(
        r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: app
      top: 10
      rules:
        - rule: regex_rule
        - rule: one_rule
  rules:
    - rule:
      name: regex_rule
      description: Regex rule.
      selectors:
        - selector:
          type: regex
          description: Code 42
          match: ['code=42']
          risk: low
    - rule:
      name: one_rule
      description: One rule.
      selectors:
        - selector:
          type: one_of
          description: Warn or fatal
          match: ['warn', 'fatal']
          risk: medium
"#,
        log_path.display()
    );

    let config = LogAuditConfig::parse(&yaml).unwrap();
    let source = config.find_source("app").unwrap();
    let summary = scan_log_source(&config, source).unwrap();

    assert_eq!(summary.match_count, 3);
    assert!(summary.report.contains("warn code=42"));
    assert!(summary.report.contains("fatal code=99"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parses_repo_test_rules_yaml() {
    let config =
        LogAuditConfig::load(std::path::Path::new("tests/fixtures/test_rules.yaml")).unwrap();

    assert_eq!(config.sources.len(), 2);
    assert_eq!(config.rules.len(), 5);
    assert!(config.find_rule("creditcard").is_some());
    assert!(config.find_source("bad_things").is_some());
}

#[test]
fn selector_defaults_match_dart_tests() {
    let yaml = r#"
log_audits:
  rules:
    - rule:
      name: locker
      selectors:
      - selector:
        description: Locker
        type: contains
        match: ["Locker"]
        exclude: ["Key"]
        risk: medium
    - rule:
      name: one
      selectors:
      - selector:
        description: Locker Key
        type: one_of
        match: ["Locker", "Key"]
        exclude: ["Note"]
        risk: high
    - rule:
      name: card
      selectors:
      - selector:
        description: A credit card was detected in a log file
        type: creditcard
        risk: critical
"#;

    let config = LogAuditConfig::parse(yaml).unwrap();
    let contains = &config.find_rule("locker").unwrap().selectors[0];
    let one_of = &config.find_rule("one").unwrap().selectors[0];
    let card = &config.find_rule("card").unwrap().selectors[0];

    assert_eq!(contains.risk(), Risk::Medium);
    assert!(!contains.terminate());
    assert_eq!(
        contains.evaluate("Locker"),
        batman::logscan::Selection::MatchContinue
    );
    assert_eq!(
        contains.evaluate("Locker Key"),
        batman::logscan::Selection::NoMatch
    );

    assert_eq!(one_of.risk(), Risk::High);
    assert!(!one_of.terminate());
    assert_eq!(
        one_of.evaluate("Key"),
        batman::logscan::Selection::MatchContinue
    );
    assert_eq!(
        one_of.evaluate("Locker Key Note"),
        batman::logscan::Selection::NoMatch
    );

    assert_eq!(card.risk(), Risk::Critical);
    assert!(!card.terminate());
    assert_eq!(
        card.evaluate("4111111111111111"),
        batman::logscan::Selection::MatchContinue
    );
}

#[test]
fn selector_continue_false_terminates() {
    let yaml = r#"
log_audits:
  rules:
    - rule:
      name: locker
      selectors:
      - selector:
        description: Locker
        type: contains
        continue: false
        match: ["Locker"]
        exclude: ["Key"]
        risk: none
"#;

    let config = LogAuditConfig::parse(yaml).unwrap();
    let selector = &config.find_rule("locker").unwrap().selectors[0];

    assert_eq!(selector.risk(), Risk::None);
    assert!(selector.terminate());
    assert_eq!(
        selector.evaluate("Locker"),
        batman::logscan::Selection::MatchTerminate
    );
}

#[test]
fn contains_case_insensitive_matches_dart_behavior() {
    let yaml = r#"
log_audits:
  rules:
    - rule:
      name: locker
      selectors:
      - selector:
        description: Locker
        type: contains
        match: ["Locker"]
        exclude: ["Key"]
        insensitive: true
        continue: false
        risk: none
"#;

    let config = LogAuditConfig::parse(yaml).unwrap();
    let selector = &config.find_rule("locker").unwrap().selectors[0];

    assert_eq!(
        selector.evaluate("LOCKER"),
        batman::logscan::Selection::MatchTerminate
    );
    assert_eq!(
        selector.evaluate("LOCKER KEY"),
        batman::logscan::Selection::NoMatch
    );
}

#[test]
fn trim_prefix_is_generic_regex() {
    let source = batman::logscan::LogSource {
        kind: batman::logscan::SourceKind::File,
        name: "regex".to_string(),
        description: String::new(),
        top: 10,
        rule_names: Vec::new(),
        path: None,
        container: None,
        since: None,
        args: None,
        trim_prefix: Some(r"^\[[0-9]+\] ".to_string()),
        reset: None,
        group_by: None,
        report_to: None,
        override_source: None,
    };
    assert_eq!(source.tidy_line("[123] payload"), "payload");
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
