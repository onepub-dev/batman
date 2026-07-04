use std::path::PathBuf;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, error::ErrorKind};

use crate::errors::{BatmanError, BatmanResult};

#[derive(Clone, Debug, Default)]
pub struct GlobalOptions {
    pub verbose: bool,
    pub colour: bool,
    pub insecure: bool,
    pub quiet: bool,
    pub quiet_explicit: bool,
    pub progress: bool,
    pub version: bool,
    pub logfile: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug)]
pub struct Cli {
    pub global: GlobalOptions,
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Install(InstallOptions),
    Baseline(BaselineOptions),
    Scan(ScanOptions),
    Accept(AcceptOptions),
    Review(ReviewOptions),
    Harden(HardenOptions),
    Unharden(HardenOptions),
    Checkpoint(CheckpointOptions),
    Logs(LogOptions),
    Cron(CronOptions),
    Doctor(DoctorOptions),
    Keygen(KeygenOptions),
}

#[derive(Debug, Default)]
pub struct InstallOptions {
    pub db_path: Option<PathBuf>,
    pub overwrite: bool,
    pub systemd_dir: Option<PathBuf>,
    pub launchd_dir: Option<PathBuf>,
    pub windows_task_dir: Option<PathBuf>,
    pub scheduler_env: Vec<String>,
    pub production_scheduler: bool,
}

#[derive(Debug, Default)]
pub struct BaselineOptions {
    pub unsigned: bool,
}

#[derive(Debug, Default)]
pub struct ScanOptions {
    pub path: Option<PathBuf>,
}

#[derive(Debug)]
pub struct AcceptOptions {
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct ReviewOptions {
    pub apply: bool,
    pub apply_path: Option<PathBuf>,
    pub operator: Option<String>,
    pub comment: Option<String>,
    pub export: Option<String>,
    pub output: Option<PathBuf>,
    pub session: Option<String>,
    pub list: bool,
    pub dry_run: bool,
}

#[derive(Debug, Default)]
pub struct HardenOptions {
    pub dry_run: bool,
}

#[derive(Debug, Default)]
pub struct CheckpointOptions {
    pub json: bool,
}

#[derive(Debug, Default)]
pub struct LogOptions {
    pub selector: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Debug)]
pub struct CronOptions {
    pub baseline: bool,
    pub scan: bool,
    pub logs: bool,
    pub schedule: String,
}

#[derive(Debug, Default)]
pub struct DoctorOptions {
    pub strict: bool,
    pub production: bool,
}

#[derive(Debug, Default)]
pub struct KeygenOptions {}

impl Cli {
    pub fn parse(args: Vec<String>) -> BatmanResult<Self> {
        let raw = RawCli::try_parse_from(std::iter::once("batman".to_string()).chain(args))
            .map_err(|error| BatmanError::Usage(error.to_string()))?;
        Ok(raw.into())
    }

    pub fn parse_env() -> BatmanResult<Self> {
        match RawCli::try_parse() {
            Ok(raw) => Ok(raw.into()),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                ) =>
            {
                let _ = error.print();
                std::process::exit(0);
            }
            Err(error) => {
                let _ = error.print();
                std::process::exit(2);
            }
        }
    }

    pub fn help() -> String {
        let mut command = RawCli::command();
        let mut buffer = Vec::new();
        command
            .write_long_help(&mut buffer)
            .expect("write clap help");
        String::from_utf8(buffer).expect("clap help is UTF-8")
    }

    pub fn command_help(command_name: &str) -> String {
        let mut command = RawCli::command();
        let subcommand = command
            .find_subcommand_mut(command_name)
            .unwrap_or_else(|| panic!("unknown command {command_name}"));
        let mut buffer = Vec::new();
        subcommand
            .write_long_help(&mut buffer)
            .expect("write clap command help");
        String::from_utf8(buffer).expect("clap help is UTF-8")
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "batman",
    version,
    about = "Low-memory file integrity monitoring tool",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct RawCli {
    #[arg(
        short = 'v',
        long,
        global = true,
        help = "Show additional diagnostic/profiling output"
    )]
    verbose: bool,

    #[arg(
        short = 'c',
        long,
        global = true,
        help = "Force coloured terminal output"
    )]
    colour: bool,

    #[arg(
        long = "no-colour",
        global = true,
        help = "Disable coloured terminal output"
    )]
    no_colour: bool,

    #[arg(
        long,
        global = true,
        help = "Skip elevated privilege checks; intended for local testing"
    )]
    insecure: bool,

    #[arg(
        short = 'q',
        long,
        global = true,
        help = "Suppress progress output for scheduled jobs"
    )]
    quiet: bool,

    #[arg(
        long,
        global = true,
        help = "Show count-oriented progress even when stdout is not a terminal"
    )]
    progress: bool,

    #[arg(
        short = 'l',
        long,
        global = true,
        value_name = "PATH",
        help = "Append output to a log file"
    )]
    logfile: Option<PathBuf>,

    #[arg(
        long = "config",
        global = true,
        value_name = "PATH",
        help = "Path to batman.yaml"
    )]
    config_path: Option<PathBuf>,

    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Debug, Subcommand)]
enum RawCommand {
    #[command(about = "Install Batman configuration and resource files")]
    Install(RawInstallOptions),
    #[command(about = "Create a file-integrity baseline")]
    Baseline(RawBaselineOptions),
    #[command(about = "Run a file-integrity scan against the baseline")]
    Scan(RawScanOptions),
    #[command(about = "Accept a known-good file or directory change")]
    Accept(RawPathOption),
    #[command(about = "Review scan findings, approve changes, and configure exclusions")]
    Review(RawReviewOptions),
    #[command(about = "Lock Batman config, executable, baseline, and audit artifacts")]
    Harden(RawHardenOptions),
    #[command(
        about = "Unlock Batman config, executable, baseline, and audit artifacts before approved maintenance"
    )]
    Unharden(RawHardenOptions),
    #[command(about = "Print a verified baseline checkpoint for off-host storage")]
    Checkpoint(RawCheckpointOptions),
    #[command(about = "Run configured log scans")]
    Logs(RawLogOptions),
    #[command(about = "Run Batman scans on a schedule")]
    Cron(RawCronOptions),
    #[command(about = "Print Batman diagnostics")]
    Doctor(RawDoctorOptions),
    #[command(about = "Generate an Ed25519 baseline signing key pair")]
    Keygen(RawKeygenOptions),
}

#[derive(Debug, Args)]
struct RawInstallOptions {
    #[arg(
        short = 'd',
        long = "db-path",
        alias = "db_path",
        value_name = "PATH",
        help = "Directory for baseline database and review sessions"
    )]
    db_path: Option<PathBuf>,

    #[arg(short = 'o', long, help = "Overwrite an existing batman.yaml")]
    overwrite: bool,

    #[arg(
        long = "systemd-dir",
        value_name = "PATH",
        help = "Write batman-scan.service and batman-scan.timer into PATH"
    )]
    systemd_dir: Option<PathBuf>,

    #[arg(
        long = "launchd-dir",
        value_name = "PATH",
        help = "Write com.noojee.batman.scan.plist into PATH"
    )]
    launchd_dir: Option<PathBuf>,

    #[arg(
        long = "windows-task-dir",
        value_name = "PATH",
        help = "Write batman-scan.xml Windows Task Scheduler definition into PATH"
    )]
    windows_task_dir: Option<PathBuf>,

    #[arg(
        long = "scheduler-env",
        value_name = "KEY=VALUE",
        action = ArgAction::Append,
        help = "Add an environment variable to generated scheduler artifacts"
    )]
    scheduler_env: Vec<String>,

    #[arg(
        long = "production-scheduler",
        help = "Add strict production environment defaults to generated scheduler artifacts"
    )]
    production_scheduler: bool,
}

#[derive(Debug, Args)]
struct RawBaselineOptions {
    #[arg(
        long,
        help = "Create an unsigned baseline. Scans that require signed baselines will reject it."
    )]
    unsigned: bool,
}

#[derive(Debug, Args)]
struct RawPathOption {
    #[arg(help = "File or directory path to accept into the baseline")]
    path: PathBuf,
}

#[derive(Debug, Args)]
struct RawScanOptions {
    #[arg(help = "Optional file or directory to scan instead of all configured scan paths")]
    path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RawReviewOptions {
    #[arg(
        long,
        help = "Apply reviewed exclusions and approvals from a review session"
    )]
    apply: bool,

    #[arg(
        value_name = "REVIEW_FILE",
        requires = "apply",
        help = "Review file to apply; only used with --apply and defaults to the latest review when omitted"
    )]
    apply_path: Option<PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        requires = "apply",
        help = "Operator name to record when applying reviewed actions"
    )]
    operator: Option<String>,

    #[arg(
        long,
        value_name = "TEXT",
        requires = "apply",
        help = "Reason or ticket reference to record when applying reviewed actions"
    )]
    comment: Option<String>,

    #[arg(
        long,
        value_name = "SESSION",
        help = "Export a review session, such as 'latest' or a session id"
    )]
    export: Option<String>,

    #[arg(
        short = 'o',
        long,
        value_name = "PATH",
        requires = "export",
        help = "Output path for --export"
    )]
    output: Option<PathBuf>,

    #[arg(
        long,
        value_name = "SESSION",
        help = "Open a specific review session in the TUI"
    )]
    session: Option<String>,

    #[arg(long, help = "List saved review sessions")]
    list: bool,

    #[arg(
        long,
        help = "Preview --apply without changing config or baseline; only useful with --apply"
    )]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RawHardenOptions {
    #[arg(
        long,
        help = "Show the files and hardening actions without changing them"
    )]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RawCheckpointOptions {
    #[arg(long, help = "Print the checkpoint as a single JSON object")]
    json: bool,
}

#[derive(Debug, Args)]
struct RawLogOptions {
    #[arg(
        value_name = "SOURCE_OR_RULE_OR_PATH",
        help = "Configured log source, rule name, or direct log path"
    )]
    selector: Option<String>,

    #[arg(
        value_name = "PATH",
        help = "Override path for the selected source or rule"
    )]
    path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RawCronOptions {
    #[arg(long, help = "Create a new baseline before scheduled work starts")]
    baseline: bool,

    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_scan", help = "Run file-integrity scans on the schedule")]
    scan: bool,

    #[arg(long = "no-scan", action = ArgAction::SetTrue, help = "Disable scheduled file-integrity scans")]
    no_scan: bool,

    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_logs", help = "Run log scans on the schedule")]
    logs: bool,

    #[arg(long = "no-logs", action = ArgAction::SetTrue, help = "Disable scheduled log scans")]
    no_logs: bool,

    #[arg(
        default_value = "0 30 22 * * *",
        help = "Cron-style schedule expression"
    )]
    schedule: String,
}

#[derive(Debug, Args)]
struct RawDoctorOptions {
    #[arg(
        long,
        help = "Exit non-zero when production hardening checks are missing or unhealthy"
    )]
    strict: bool,

    #[arg(
        long,
        alias = "hardened",
        help = "Alias for --strict; intended for production deployment checks"
    )]
    production: bool,
}

#[derive(Debug, Args)]
struct RawKeygenOptions {}

impl From<RawCli> for Cli {
    fn from(raw: RawCli) -> Self {
        let global = GlobalOptions {
            verbose: raw.verbose,
            colour: raw.colour || !raw.no_colour,
            insecure: raw.insecure,
            quiet: raw.quiet,
            quiet_explicit: raw.quiet,
            progress: raw.progress,
            version: false,
            logfile: raw.logfile,
            config_path: raw.config_path,
        };
        let command = match raw.command {
            RawCommand::Install(options) => Command::Install(InstallOptions {
                db_path: options.db_path,
                overwrite: options.overwrite,
                systemd_dir: options.systemd_dir,
                launchd_dir: options.launchd_dir,
                windows_task_dir: options.windows_task_dir,
                scheduler_env: options.scheduler_env,
                production_scheduler: options.production_scheduler,
            }),
            RawCommand::Baseline(options) => Command::Baseline(BaselineOptions {
                unsigned: options.unsigned,
            }),
            RawCommand::Scan(options) => Command::Scan(ScanOptions { path: options.path }),
            RawCommand::Accept(options) => Command::Accept(AcceptOptions { path: options.path }),
            RawCommand::Review(options) => Command::Review(ReviewOptions {
                apply: options.apply,
                apply_path: options.apply_path,
                operator: options.operator,
                comment: options.comment,
                export: options.export,
                output: options.output,
                session: options.session,
                list: options.list,
                dry_run: options.dry_run,
            }),
            RawCommand::Harden(options) => Command::Harden(HardenOptions {
                dry_run: options.dry_run,
            }),
            RawCommand::Unharden(options) => Command::Unharden(HardenOptions {
                dry_run: options.dry_run,
            }),
            RawCommand::Checkpoint(options) => {
                Command::Checkpoint(CheckpointOptions { json: options.json })
            }
            RawCommand::Logs(options) => Command::Logs(LogOptions {
                selector: options.selector,
                path: options.path,
            }),
            RawCommand::Cron(options) => Command::Cron(CronOptions {
                baseline: options.baseline,
                scan: options.scan || !options.no_scan,
                logs: options.logs || !options.no_logs,
                schedule: options.schedule,
            }),
            RawCommand::Doctor(options) => Command::Doctor(DoctorOptions {
                strict: options.strict,
                production: options.production,
            }),
            RawCommand::Keygen(_) => Command::Keygen(KeygenOptions::default()),
        };

        Self { global, command }
    }
}
