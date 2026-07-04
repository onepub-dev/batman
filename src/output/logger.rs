use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use terminal_size::{Width, terminal_size_of};

use crate::cli::GlobalOptions;
use crate::errors::{BatmanError, BatmanResult};
use crate::output::progress::{ProgressSnapshot, format_count_progress, format_path_progress};

pub struct Output {
    colour: bool,
    logfile: Option<File>,
    progress_width: usize,
    terminal_width: usize,
    verbose: bool,
}

#[derive(Clone, Copy)]
pub enum Style {
    Plain,
    Info,
    Success,
    Warn,
    Error,
    Added,
    Modified,
    Deleted,
    Summary,
}

impl Output {
    pub fn new(options: &GlobalOptions) -> BatmanResult<Self> {
        let logfile = match &options.logfile {
            Some(path) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?,
            ),
            None => None,
        };
        Ok(Self {
            colour: options.colour,
            terminal_width: if logfile.is_some() {
                usize::MAX
            } else {
                terminal_columns()
            },
            logfile,
            progress_width: 0,
            verbose: options.verbose,
        })
    }

    pub fn line(&mut self, style: Style, message: impl AsRef<str>) -> BatmanResult<()> {
        self.write(style, message.as_ref(), false)
    }

    pub fn error(&mut self, message: impl AsRef<str>) -> BatmanResult<()> {
        self.write(Style::Error, message.as_ref(), true)
    }

    pub fn progress(&mut self, style: Style, message: impl AsRef<str>) -> BatmanResult<()> {
        let message = message.as_ref();
        if let Some(file) = self.logfile.as_mut() {
            writeln!(file, "{message}").map_err(|error| BatmanError::io("write logfile", error))?;
            return Ok(());
        }

        let rendered = self.render(style, message);
        let width = message.chars().count().max(self.progress_width);
        print!("\r{rendered:<width$}");
        io::stdout()
            .flush()
            .map_err(|error| BatmanError::io("flush progress", error))?;
        self.progress_width = message.chars().count();
        Ok(())
    }

    pub fn progress_path(
        &mut self,
        style: Style,
        prefix: &str,
        count: u64,
        snapshot: ProgressSnapshot,
        path: &Path,
    ) -> BatmanResult<()> {
        self.progress(
            style,
            format_path_progress(
                prefix,
                count,
                snapshot,
                path,
                self.terminal_width,
                self.verbose,
            ),
        )
    }

    pub fn progress_count(
        &mut self,
        style: Style,
        prefix: &str,
        directories: u64,
        files: u64,
        snapshot: ProgressSnapshot,
    ) -> BatmanResult<()> {
        self.progress(
            style,
            format_count_progress(prefix, directories, files, snapshot, self.verbose),
        )
    }

    fn write(&mut self, style: Style, message: &str, stderr: bool) -> BatmanResult<()> {
        let rendered = self.render(style, message);
        if let Some(file) = self.logfile.as_mut() {
            writeln!(file, "{message}").map_err(|error| BatmanError::io("write logfile", error))?;
        } else if stderr {
            self.finish_progress_line();
            eprintln!("{rendered}");
        } else {
            self.finish_progress_line();
            println!("{rendered}");
        }
        Ok(())
    }

    fn finish_progress_line(&mut self) {
        if self.progress_width > 0 {
            println!();
            self.progress_width = 0;
        }
    }

    fn render(&self, style: Style, message: &str) -> String {
        if !self.colour {
            return message.to_string();
        }

        let code = match style {
            Style::Plain => return message.to_string(),
            Style::Info => "34",
            Style::Success => "32",
            Style::Warn => "33",
            Style::Error => "31",
            Style::Added => "36",
            Style::Modified => "35",
            Style::Deleted => "31",
            Style::Summary => "1;32",
        };
        format!("\x1b[{code}m{message}\x1b[0m")
    }
}

fn terminal_columns() -> usize {
    let columns = terminal_size_of(io::stdout())
        .map(|(Width(width), _)| usize::from(width))
        .filter(|value| *value >= 40)
        .or_else(env_columns)
        .unwrap_or(80);
    columns.saturating_sub(1).max(1)
}

fn env_columns() -> Option<usize> {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 40)
}
