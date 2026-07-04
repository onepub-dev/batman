use std::io::IsTerminal;

use crate::cli::{Cli, Command};
use crate::commands;
use crate::config::LocalSettings;
use crate::errors::BatmanResult;
use crate::output::Output;

pub struct App {
    cli: Cli,
}

impl App {
    pub fn from_env() -> BatmanResult<Self> {
        Ok(Self {
            cli: Cli::parse_env()?,
        })
    }

    pub fn run(self) -> BatmanResult<u8> {
        if self.cli.global.version {
            println!("batman {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }

        let local_settings = LocalSettings::load(self.cli.global.config_path.as_deref())?;
        let global = effective_global_options(self.cli.global, std::io::stdout().is_terminal());
        let mut output = Output::new(&global)?;
        let context = commands::CommandContext {
            global,
            local_settings,
        };

        match self.cli.command {
            Command::Install(options) => commands::install::run(&context, &mut output, options),
            Command::Baseline(options) => commands::baseline::run(&context, &mut output, options),
            Command::Scan(options) => commands::scan::run(&context, &mut output, options),
            Command::Accept(options) => commands::accept::run(&context, &mut output, options),
            Command::Review(options) => commands::review::run(&context, &mut output, options),
            Command::Harden(options) => commands::harden::run(&context, &mut output, options, true),
            Command::Unharden(options) => {
                commands::harden::run(&context, &mut output, options, false)
            }
            Command::Checkpoint(options) => {
                commands::checkpoint::run(&context, &mut output, options)
            }
            Command::Doctor(options) => commands::doctor::run(&context, &mut output, options),
            Command::Keygen(options) => commands::keygen::run(&context, &mut output, options),
            Command::Logs(options) => commands::logs::run(&context, &mut output, options),
            Command::Cron(options) => commands::cron::run(&context, &mut output, options),
        }
    }
}

pub fn effective_global_options(
    mut global: crate::cli::GlobalOptions,
    stdout_is_terminal: bool,
) -> crate::cli::GlobalOptions {
    if !global.quiet_explicit && !global.progress && !stdout_is_terminal {
        global.quiet = true;
    }
    global
}

#[cfg(test)]
mod tests {
    use crate::app::effective_global_options;
    use crate::cli::GlobalOptions;

    #[test]
    fn terminal_runs_are_not_quiet_by_default() {
        let global = effective_global_options(GlobalOptions::default(), true);

        assert!(!global.quiet);
    }

    #[test]
    fn non_terminal_runs_are_quiet_by_default() {
        let global = effective_global_options(GlobalOptions::default(), false);

        assert!(global.quiet);
    }

    #[test]
    fn progress_overrides_non_terminal_quiet_default() {
        let global = effective_global_options(
            GlobalOptions {
                progress: true,
                ..GlobalOptions::default()
            },
            false,
        );

        assert!(!global.quiet);
    }

    #[test]
    fn explicit_quiet_wins_over_progress() {
        let global = effective_global_options(
            GlobalOptions {
                quiet: true,
                quiet_explicit: true,
                progress: true,
                ..GlobalOptions::default()
            },
            true,
        );

        assert!(global.quiet);
    }
}
