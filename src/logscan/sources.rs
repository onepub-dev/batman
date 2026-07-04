use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};

use regex::Regex;

use crate::errors::{BatmanError, BatmanResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    File,
    JournalCtl,
}

#[derive(Clone, Debug)]
pub struct LogSource {
    pub kind: SourceKind,
    pub name: String,
    pub description: String,
    pub top: usize,
    pub rule_names: Vec<String>,
    pub path: Option<PathBuf>,
    pub container: Option<String>,
    pub since: Option<String>,
    pub args: Option<String>,
    pub trim_prefix: Option<String>,
    pub reset: Option<String>,
    pub group_by: Option<String>,
    pub report_to: Option<String>,
    pub override_source: Option<PathBuf>,
}

struct ProcessLines {
    child: Child,
    lines: std::io::Lines<BufReader<ChildStdout>>,
}

impl LogSource {
    pub fn exists(&self) -> bool {
        match self.kind {
            SourceKind::File => self
                .override_source
                .as_ref()
                .or(self.path.as_ref())
                .is_some_and(|path| path.exists()),
            SourceKind::JournalCtl => true,
        }
    }

    pub fn source_label(&self) -> String {
        if let Some(path) = &self.override_source {
            return path.display().to_string();
        }
        match self.kind {
            SourceKind::File => self
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            SourceKind::JournalCtl => format!("journalctl {}", self.args.as_deref().unwrap_or("")),
        }
    }

    pub fn open_lines(&self) -> BatmanResult<Box<dyn Iterator<Item = BatmanResult<String>>>> {
        if let Some(path) = self.override_source.as_ref().or(self.path.as_ref())
            && (self.kind == SourceKind::File || self.override_source.is_some())
        {
            let file = File::open(path)
                .map_err(|error| BatmanError::io(format!("open {}", path.display()), error))?;
            let lines = BufReader::new(file)
                .lines()
                .map(|line| line.map_err(|error| BatmanError::io("read log line", error)));
            return Ok(Box::new(lines));
        }

        let mut command = match self.kind {
            SourceKind::JournalCtl => {
                let mut command = Command::new("journalctl");
                if let Some(args) = &self.args {
                    command.args(args.split_whitespace());
                }
                command
            }
            SourceKind::File => {
                return Err(BatmanError::Config(format!(
                    "file log source {} has no path",
                    self.name
                )));
            }
        };

        let mut child = command
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| BatmanError::io(format!("run {}", self.source_label()), error))?;
        let stdout = child.stdout.take().ok_or_else(|| BatmanError::Io {
            context: "capture journalctl stdout".to_string(),
            source: std::io::Error::other("stdout unavailable"),
        })?;
        Ok(Box::new(ProcessLines {
            child,
            lines: BufReader::new(stdout).lines(),
        }))
    }

    pub fn tidy_line(&self, line: &str) -> String {
        trim_regex_prefix(line, self.trim_prefix.as_deref())
    }
}

impl Iterator for ProcessLines {
    type Item = BatmanResult<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines
            .next()
            .map(|line| line.map_err(|error| BatmanError::io("read log line", error)))
    }
}

impl Drop for ProcessLines {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {}
        }
    }
}

fn trim_regex_prefix(line: &str, prefix: Option<&str>) -> String {
    let Some(prefix) = prefix.filter(|prefix| !prefix.is_empty()) else {
        return line.to_string();
    };
    let Ok(regex) = Regex::new(prefix) else {
        return line.to_string();
    };
    let index = regex.find(line).map(|found| found.end()).unwrap_or(0);
    line[index..].to_string()
}
