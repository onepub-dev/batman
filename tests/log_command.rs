use std::fs;

use batman::cli::{GlobalOptions, LogOptions};
use batman::commands::{CommandContext, logs};
use batman::config::LocalSettings;
use batman::output::Output;

#[test]
fn log_name_reports_missing_configured_file_source_without_io_error() {
    let fixture = Fixture::new("batman-log-command-missing");
    let missing_log = fixture.root.join("missing.log");
    fixture.write_rules(&missing_log);
    let mut output = fixture.output();

    let code = logs::run(
        &fixture.context,
        &mut output,
        LogOptions {
            selector: Some("app".to_string()),
            path: None,
        },
    )
    .unwrap();

    assert_eq!(code, 1);
    assert!(
        fs::read_to_string(&fixture.logfile)
            .unwrap()
            .contains("A log_source with name app was not found")
    );
}

#[test]
fn log_name_override_path_scans_even_when_configured_source_is_missing() {
    let fixture = Fixture::new("batman-log-command-override");
    let missing_log = fixture.root.join("missing.log");
    let override_log = fixture.root.join("override.log");
    fs::write(&override_log, "Error: failure\n").unwrap();
    fixture.write_rules(&missing_log);
    let mut output = fixture.output();

    let code = logs::run(
        &fixture.context,
        &mut output,
        LogOptions {
            selector: Some("app".to_string()),
            path: Some(override_log),
        },
    )
    .unwrap();

    assert_eq!(code, 0);
    let output = fs::read_to_string(&fixture.logfile).unwrap();
    assert!(output.contains("Checked 1 log lines, matched: 1"));
    assert!(output.contains("Found 1 problems."));
}

struct Fixture {
    root: std::path::PathBuf,
    logfile: std::path::PathBuf,
    context: CommandContext,
}

impl Fixture {
    fn new(prefix: &str) -> Self {
        let root = unique_dir(prefix);
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("batman.yaml");
        let logfile = root.join("output.log");
        let context = CommandContext {
            global: GlobalOptions {
                colour: false,
                insecure: true,
                logfile: Some(logfile.clone()),
                ..GlobalOptions::default()
            },
            local_settings: LocalSettings::for_config_path(config_path),
        };
        Self {
            root,
            logfile,
            context,
        }
    }

    fn output(&self) -> Output {
        Output::new(&self.context.global).unwrap()
    }

    fn write_rules(&self, log_path: &std::path::Path) {
        fs::write(
            &self.context.local_settings.config_path,
            format!(
                r#"
log_audits:
  log_sources:
    - log_source:
      type: file
      path: {}
      name: app
      description: App log
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
          risk: high
"#,
                log_path.display()
            ),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
