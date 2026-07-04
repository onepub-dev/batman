use std::fs;
use std::path::Path;

use crate::cli::InstallOptions;
use crate::commands::CommandContext;
use crate::errors::{BatmanError, BatmanResult};
use crate::output::{Output, Style};
use crate::security::{
    EXPECTED_CONFIG_HASH_ENV, file_content_hash, hex_hash, secure_config_path,
    secure_data_directory, write_secure_config_atomic,
};

const DEFAULT_LINUX_BATMAN_YAML: &str = include_str!("../../resource/batman_linux.yaml");
const DEFAULT_MACOS_BATMAN_YAML: &str = include_str!("../../resource/batman_macos.yaml");
const DEFAULT_WINDOWS_BATMAN_YAML: &str = include_str!("../../resource/batman_windows.yaml");
const PRODUCTION_SCHEDULER_ENV: &[(&str, &str)] = &[
    ("BATMAN_REQUIRE_SIGNED_BASELINE", "1"),
    ("BATMAN_STRICT_CONFIG", "1"),
    ("BATMAN_AUDIT_SINK_REQUIRED", "1"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct SchedulerEnv {
    key: String,
    value: String,
}

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: InstallOptions,
) -> BatmanResult<u8> {
    let config_path = context.local_settings.config_path.clone();
    if !config_path.ends_with("batman.yaml") {
        output.error("The --config path must end with \"batman.yaml\"")?;
        return Ok(1);
    }

    let settings_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| context.local_settings.settings_dir());
    fs::create_dir_all(&settings_dir)
        .map_err(|error| BatmanError::io(format!("create {}", settings_dir.display()), error))?;
    let db_path = options
        .db_path
        .clone()
        .unwrap_or_else(|| context.local_settings.default_db_path.clone());
    let default_rules = default_rule_content();
    let rule_content = with_db_path(&default_rules, &db_path.display().to_string());
    write_if_needed(&config_path, &rule_content, options.overwrite)?;
    if config_path.exists() {
        rewrite_db_path(&config_path, &db_path.display().to_string())?;
    }
    secure_config_path(&config_path)?;
    fs::create_dir_all(&db_path)
        .map_err(|error| BatmanError::io(format!("create {}", db_path.display()), error))?;
    secure_data_directory(&db_path)?;
    let scheduler_env = scheduler_env(
        &options.scheduler_env,
        options.production_scheduler,
        &config_path,
    )?;
    if let Some(systemd_dir) = &options.systemd_dir {
        write_systemd_units(systemd_dir, &config_path, &scheduler_env)?;
        output.line(
            Style::Plain,
            format!("Systemd units: {}", systemd_dir.display()),
        )?;
    }
    if let Some(launchd_dir) = &options.launchd_dir {
        write_launchd_plist(launchd_dir, &config_path, &scheduler_env)?;
        output.line(
            Style::Plain,
            format!("Launchd plist: {}", launchd_dir.display()),
        )?;
    }
    if let Some(windows_task_dir) = &options.windows_task_dir {
        write_windows_task_xml(windows_task_dir, &config_path, &scheduler_env)?;
        output.line(
            Style::Plain,
            format!("Windows task XML: {}", windows_task_dir.display()),
        )?;
    }

    output.line(Style::Success, "Installation complete.")?;
    output.line(
        Style::Plain,
        format!("Configuration: {}", config_path.display()),
    )?;
    output.line(
        Style::Plain,
        format!("Database path: {}", db_path.display()),
    )?;
    output.line(
        Style::Warn,
        "Run 'batman baseline' to create the initial baseline.",
    )?;
    Ok(0)
}

fn write_systemd_units(
    systemd_dir: &Path,
    config_path: &Path,
    env: &[SchedulerEnv],
) -> BatmanResult<()> {
    fs::create_dir_all(systemd_dir)
        .map_err(|error| BatmanError::io(format!("create {}", systemd_dir.display()), error))?;
    let executable = std::env::current_exe()
        .map_err(|error| BatmanError::io("resolve current executable", error))?;
    let service = format!(
        "[Unit]\nDescription=Batman file integrity scan\nAfter=local-fs.target\n\n[Service]\nType=oneshot\n{}ExecStart={} --quiet --config {} scan\n",
        systemd_environment(env),
        systemd_arg(&executable.display().to_string()),
        systemd_arg(&config_path.display().to_string())
    );
    let timer = "[Unit]\nDescription=Run Batman file integrity scan daily\n\n[Timer]\nOnCalendar=*-*-* 22:30:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";
    fs::write(systemd_dir.join("batman-scan.service"), service).map_err(|error| {
        BatmanError::io(
            format!(
                "write {}",
                systemd_dir.join("batman-scan.service").display()
            ),
            error,
        )
    })?;
    fs::write(systemd_dir.join("batman-scan.timer"), timer).map_err(|error| {
        BatmanError::io(
            format!("write {}", systemd_dir.join("batman-scan.timer").display()),
            error,
        )
    })?;
    Ok(())
}

fn write_launchd_plist(
    launchd_dir: &Path,
    config_path: &Path,
    env: &[SchedulerEnv],
) -> BatmanResult<()> {
    fs::create_dir_all(launchd_dir)
        .map_err(|error| BatmanError::io(format!("create {}", launchd_dir.display()), error))?;
    let executable = std::env::current_exe()
        .map_err(|error| BatmanError::io("resolve current executable", error))?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.noojee.batman.scan</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--quiet</string>
    <string>--config</string>
    <string>{}</string>
    <string>scan</string>
  </array>
{}
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>22</integer>
    <key>Minute</key>
    <integer>30</integer>
  </dict>
</dict>
</plist>
"#,
        xml_escape(&executable.display().to_string()),
        xml_escape(&config_path.display().to_string()),
        launchd_environment(env)
    );
    fs::write(launchd_dir.join("com.noojee.batman.scan.plist"), plist).map_err(|error| {
        BatmanError::io(
            format!(
                "write {}",
                launchd_dir.join("com.noojee.batman.scan.plist").display()
            ),
            error,
        )
    })
}

fn write_windows_task_xml(
    task_dir: &Path,
    config_path: &Path,
    env: &[SchedulerEnv],
) -> BatmanResult<()> {
    fs::create_dir_all(task_dir)
        .map_err(|error| BatmanError::io(format!("create {}", task_dir.display()), error))?;
    let executable = std::env::current_exe()
        .map_err(|error| BatmanError::io("resolve current executable", error))?;
    let (command, arguments) = if env.is_empty() {
        (
            xml_escape(&executable.display().to_string()),
            format!(
                "--quiet --config &quot;{}&quot; scan",
                xml_escape(&config_path.display().to_string())
            ),
        )
    } else {
        let script = task_dir.join("batman-scan.cmd");
        write_windows_task_script(&script, &executable, config_path, env)?;
        (xml_escape(&script.display().to_string()), String::new())
    };
    let task = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Batman file integrity scan</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T22:30:00</StartBoundary>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
      <Enabled>true</Enabled>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        command, arguments
    );
    fs::write(task_dir.join("batman-scan.xml"), task).map_err(|error| {
        BatmanError::io(
            format!("write {}", task_dir.join("batman-scan.xml").display()),
            error,
        )
    })
}

fn write_windows_task_script(
    script: &Path,
    executable: &Path,
    config_path: &Path,
    env: &[SchedulerEnv],
) -> BatmanResult<()> {
    let mut content = String::from("@echo off\r\n");
    for entry in env {
        content.push_str("set \"");
        content.push_str(&cmd_escape(&entry.key));
        content.push('=');
        content.push_str(&cmd_escape(&entry.value));
        content.push_str("\"\r\n");
    }
    content.push('"');
    content.push_str(&cmd_escape(&executable.display().to_string()));
    content.push_str("\" --quiet --config \"");
    content.push_str(&cmd_escape(&config_path.display().to_string()));
    content.push_str("\" scan\r\n");
    fs::write(script, content)
        .map_err(|error| BatmanError::io(format!("write {}", script.display()), error))
}

fn scheduler_env(
    raw: &[String],
    production: bool,
    config_path: &Path,
) -> BatmanResult<Vec<SchedulerEnv>> {
    let mut env = Vec::new();
    if production {
        env.extend(
            PRODUCTION_SCHEDULER_ENV
                .iter()
                .map(|(key, value)| SchedulerEnv {
                    key: (*key).to_string(),
                    value: (*value).to_string(),
                }),
        );
        let config_hash = file_content_hash(config_path)?;
        env.push(SchedulerEnv {
            key: EXPECTED_CONFIG_HASH_ENV.to_string(),
            value: hex_hash(&config_hash),
        });
    }
    for value in raw {
        let Some((key, value)) = value.split_once('=') else {
            return Err(BatmanError::Config(format!(
                "--scheduler-env expects KEY=VALUE, got {value}"
            )));
        };
        if key.is_empty()
            || key
                .chars()
                .any(|character| !(character == '_' || character.is_ascii_alphanumeric()))
        {
            return Err(BatmanError::Config(format!(
                "invalid scheduler environment variable name {key}"
            )));
        }
        if let Some(existing) = env.iter_mut().find(|entry| entry.key == key) {
            existing.value = value.to_string();
        } else {
            env.push(SchedulerEnv {
                key: key.to_string(),
                value: value.to_string(),
            });
        }
    }
    Ok(env)
}

fn systemd_environment(env: &[SchedulerEnv]) -> String {
    env.iter()
        .map(|entry| {
            format!(
                "Environment={}\n",
                systemd_arg(&format!("{}={}", entry.key, entry.value))
            )
        })
        .collect()
}

fn launchd_environment(env: &[SchedulerEnv]) -> String {
    if env.is_empty() {
        return String::new();
    }
    let mut output = String::from("  <key>EnvironmentVariables</key>\n  <dict>\n");
    for entry in env {
        output.push_str("    <key>");
        output.push_str(&xml_escape(&entry.key));
        output.push_str("</key>\n    <string>");
        output.push_str(&xml_escape(&entry.value));
        output.push_str("</string>\n");
    }
    output.push_str("  </dict>\n");
    output
}

fn systemd_arg(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn cmd_escape(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn default_rules() -> &'static str {
    if cfg!(target_os = "macos") {
        DEFAULT_MACOS_BATMAN_YAML
    } else if cfg!(target_os = "windows") {
        DEFAULT_WINDOWS_BATMAN_YAML
    } else {
        DEFAULT_LINUX_BATMAN_YAML
    }
}

fn default_rule_content() -> String {
    let rules = default_rules();
    #[cfg(target_os = "windows")]
    {
        with_windows_scan_paths(rules, &fixed_drive_roots())
    }
    #[cfg(not(target_os = "windows"))]
    {
        rules.to_string()
    }
}

pub fn ensure_rule_file(context: &CommandContext, output: &mut Output) -> BatmanResult<u8> {
    if context.local_settings.config_path.exists() {
        return Ok(0);
    }
    output.error("Error: You must run 'batman install' first.")?;
    Ok(1)
}

fn write_if_needed(path: &Path, content: &str, overwrite: bool) -> BatmanResult<()> {
    if path.exists() && !overwrite {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| BatmanError::io(format!("create {}", parent.display()), error))?;
    }
    write_secure_config_atomic(path, content)
}

fn rewrite_db_path(path: &Path, db_path: &str) -> BatmanResult<()> {
    let content = fs::read_to_string(path)
        .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
    let updated = with_db_path(&content, db_path);
    write_secure_config_atomic(path, &updated)
}

fn with_db_path(content: &str, db_path: &str) -> String {
    content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("db_path:") {
                let indent = line.len() - line.trim_start().len();
                format!("{}db_path: {db_path}", " ".repeat(indent))
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

pub fn with_windows_scan_paths(content: &str, drives: &[String]) -> String {
    let drives = if drives.is_empty() {
        vec!["C:\\".to_string()]
    } else {
        drives.to_vec()
    };
    let mut output = Vec::new();
    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        output.push(line.to_string());
        if line.trim() != "scan_paths:" {
            continue;
        }
        let scan_indent = line.len() - line.trim_start().len();
        let item_indent = scan_indent + 2;
        for drive in &drives {
            output.push(format!("{}- {drive}", " ".repeat(item_indent)));
        }
        while let Some(next) = lines.peek() {
            let next_indent = next.len() - next.trim_start().len();
            if next_indent > scan_indent && next.trim_start().starts_with("- ") {
                lines.next();
            } else {
                break;
            }
        }
    }
    output.join("\n") + "\n"
}

#[cfg(target_os = "windows")]
fn fixed_drive_roots() -> Vec<String> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

    let mask = unsafe { GetLogicalDrives() };
    let mut drives = Vec::new();
    for index in 0..26 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = (b'A' + index as u8) as char;
        let root = format!("{letter}:\\");
        let wide = [letter as u16, ':' as u16, '\\' as u16, 0];
        if unsafe { GetDriveTypeW(wide.as_ptr()) } == DRIVE_FIXED {
            drives.push(root);
        }
    }
    drives
}
