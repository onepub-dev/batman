use std::thread;
use std::time::Duration;

use crate::cli::{CronOptions, LogOptions, ScanOptions};
use crate::commands::{CommandContext, baseline, ensure_trusted_config, install, logs, scan};
use crate::errors::BatmanResult;
use crate::output::Output;
use crate::system::{CronSchedule, DateParts, is_privileged, required_privilege_description};

pub fn run(
    context: &CommandContext,
    output: &mut Output,
    options: CronOptions,
) -> BatmanResult<u8> {
    if !options.scan && !options.logs {
        output.error("You have disabled both scans. Enable one of the scans.")?;
        return Ok(1);
    }
    if !context.global.insecure && !is_privileged() {
        output.error(format!(
            "You must run with {} to run scheduled scans",
            required_privilege_description()
        ))?;
        return Ok(1);
    }
    if !ensure_trusted_config(context, output)? {
        return Ok(1);
    }

    if install::ensure_rule_file(context, output)? != 0 {
        return Ok(1);
    }

    let schedule = CronSchedule::parse(&options.schedule)?;
    if options.baseline {
        baseline::run(context, output, Default::default())?;
    }

    let mut last_run: Option<DateParts> = None;
    loop {
        let now = DateParts::now_local();
        if schedule.should_run_at(now) && last_run != Some(now) {
            if options.scan {
                output.line(crate::output::Style::Plain, "Running scheduled File Scan")?;
                scan::run(context, output, ScanOptions::default())?;
            }
            if options.logs {
                output.line(crate::output::Style::Plain, "Running scheduled Log Scan")?;
                logs::run(context, output, LogOptions::default())?;
            }
            last_run = Some(now);
        }
        thread::sleep(Duration::from_secs(1));
    }
}
