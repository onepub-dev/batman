use batman::logscan::{LogAuditConfig, Selection};

#[test]
fn parses_selector_match_and_exclude_block_lists() {
    let yaml = r#"
log_audits:
  rules:
    - rule:
      name: noisy_service
      description: service-specific noisy lines
      selectors:
        - selector:
          description: ignore noisy lines
          type: contains
          continue: false
          match:
            - 'AgiHangupException'
            - 'Setting logging level to'
            - 'com.mysql.cj.'
          exclude:
            - 'allowed'
          risk: none
        - selector:
          description: Slow
          type: one_of
          match:
            - 'Locker'
            - 'Slow'
          exclude:
            - 'debug'
          risk: medium
"#;

    let config = LogAuditConfig::parse(yaml).unwrap();
    let rule = config.find_rule("noisy_service").unwrap();
    let ignore = &rule.selectors[0];
    let slow = &rule.selectors[1];

    assert_eq!(
        ignore.evaluate("AgiHangupException Setting logging level to com.mysql.cj."),
        Selection::MatchTerminate
    );
    assert_eq!(
        ignore.evaluate("AgiHangupException Setting logging level to com.mysql.cj. allowed"),
        Selection::NoMatch
    );
    assert_eq!(ignore.evaluate("AgiHangupException"), Selection::NoMatch);
    assert_eq!(slow.evaluate("Slow query"), Selection::MatchContinue);
    assert_eq!(slow.evaluate("Slow debug query"), Selection::NoMatch);
}

#[test]
fn parses_grouped_reset_journalctl_source_configuration() {
    let yaml = r#"
log_audits:
  log_sources:
    - log_source:
      description: File Integrity logs
      type: file
      top: 1000
      name: integrity
      path: /var/log/batman.log
      trim_prefix: ':::'
      rules:
        - rule: integrity check
        - rule: errors
    - log_source:
      type: journalctl
      args: -u appserver --since '1 day ago'
      name: app_service
      description: Application service logs
      top: 1000
      reset: Service restarted
      trim_prefix: ':::'
      group_by: '(.*?\.java\:.*?)'
      rules:
        - rule: creditcard
        - rule: errors
        - rule: service_errors
  rules:
    - rule:
      name: creditcard
      description: Scans for credit cards
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected in a log file
          risk: critical
    - rule:
      name: integrity check
      description: Scans the file integrity logs for issues
      selectors:
        - selector:
          type: contains
          description: The contents of a file has changed.
          match: ['Integrity:']
          risk: critical
          continue: false
    - rule:
      name: errors
      description: Scans for general errors and warnings.
      selectors:
        - selector:
          type: contains
          description: An error was detected
          match: ['Error']
          risk: high
          continue: false
    - rule:
      name: service_errors
      description: service-specific errors
      selectors:
        - selector:
          description: ignore deleterious lines
          type: contains
          continue: false
          match:
            - 'AgiHangupException'
            - 'Setting logging level to'
            - 'com.mysql.cj.'
            - 'RejectedExecutionHandlerImpl'
            - 'Logs begin at'
            - 'LoggingOutputStream'
          risk: none
        - selector:
          description: Java is reporting an out of memory condition
          type: contains
          match:
            - 'Terminating due to java.lang.OutOfMemoryError'
          risk: high
"#;

    let config = LogAuditConfig::parse(yaml).unwrap();

    assert_eq!(config.sources.len(), 2);
    assert_eq!(config.rules.len(), 4);
    assert!(config.find_source("app_service").is_some());
    assert!(config.find_rule("service_errors").is_some());
}

#[test]
fn rejects_unknown_log_source_types() {
    let yaml = r#"
log_audits:
  log_sources:
    - log_source:
      type: custom_service
      name: app_service
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

    let error = LogAuditConfig::parse(yaml).unwrap_err().to_string();
    assert!(error.contains("invalid log_source type custom_service"));
}

#[test]
fn rejects_docker_log_sources() {
    let yaml = r#"
log_audits:
  log_sources:
    - log_source:
      type: docker
      container: appserver
      since: '1 day ago'
      name: app_service
      report_to: support@example.com
      reset: Application restarted
      trim_prefix: '^[0-9-]+ [0-9:,]+ '
      group_by: '\(.*?\.java\:.*?\)'
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

    let error = LogAuditConfig::parse(yaml).unwrap_err().to_string();

    assert!(error.contains("invalid log_source type docker"));
}
