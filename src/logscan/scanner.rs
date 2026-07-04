use std::collections::{HashMap, HashSet};

use regex::Regex;

use crate::errors::{BatmanError, BatmanResult};
use crate::logscan::config::{LogAuditConfig, LogRule};
use crate::logscan::selectors::{Risk, Selection, Selector};
use crate::logscan::sources::LogSource;

#[derive(Clone, Debug)]
pub struct LogScanSummary {
    pub line_count: u64,
    pub match_count: u64,
    pub report: String,
}

#[derive(Clone)]
struct MatchEvent {
    rule_name: String,
    rule_description: String,
    selector: Selector,
    line: String,
    line_no: u64,
}

pub fn scan_log_source(
    config: &LogAuditConfig,
    source: &LogSource,
) -> BatmanResult<LogScanSummary> {
    let mut line_count = 0_u64;
    let mut simple_match_count = 0_u64;
    let mut events = Vec::new();
    let mut grouped = GroupedReport::new();
    let group_by = effective_group_by(config, source)
        .map(Regex::new)
        .transpose()
        .map_err(|error| BatmanError::Parse(error.to_string()))?;

    for line in source.open_lines()? {
        let line = line?;
        line_count += 1;
        if source
            .reset
            .as_ref()
            .is_some_and(|reset| line.contains(reset))
        {
            events.clear();
            grouped.reset_occurred = true;
            grouped.groups.clear();
            grouped.match_count = 0;
            simple_match_count = 0;
            continue;
        }

        for event in matched_events(config, source, &line, line_count)? {
            if let Some(group_by) = &group_by {
                let key = group_by
                    .find(&event.line)
                    .map(|matched| matched.as_str().to_string())
                    .unwrap_or_else(|| event.selector.description().to_string());
                grouped.add(key, &event);
            } else if events.len() < source.top {
                simple_match_count += 1;
                events.push(event);
            } else {
                simple_match_count += 1;
            }
        }
    }

    let match_count = if group_by.is_some() {
        grouped.match_count
    } else {
        simple_match_count
    };
    let report = if group_by.is_some() {
        grouped.render(source.top)
    } else {
        render_simple(source, &events, match_count)
    };

    Ok(LogScanSummary {
        line_count,
        match_count,
        report,
    })
}

fn effective_group_by<'a>(config: &'a LogAuditConfig, source: &'a LogSource) -> Option<&'a str> {
    source.group_by.as_deref().or_else(|| {
        source
            .rule_names
            .iter()
            .filter_map(|name| config.find_rule(name))
            .find_map(|rule| rule.group_by.as_deref())
    })
}

fn matched_events(
    config: &LogAuditConfig,
    source: &LogSource,
    line: &str,
    line_no: u64,
) -> BatmanResult<Vec<MatchEvent>> {
    let mut events = Vec::new();
    for rule_name in &source.rule_names {
        let rule = config.find_rule(rule_name).ok_or_else(|| {
            BatmanError::Parse(format!(
                "LogSource {} references unknown rule {rule_name}",
                source.description
            ))
        })?;
        for selector in &rule.selectors {
            match selector.evaluate(line) {
                Selection::NoMatch => {}
                selection => {
                    events.push(build_event(source, rule, selector, line, line_no));
                    if selection == Selection::MatchTerminate {
                        break;
                    }
                }
            }
        }
    }
    Ok(events)
}

fn build_event(
    source: &LogSource,
    rule: &LogRule,
    selector: &Selector,
    line: &str,
    line_no: u64,
) -> MatchEvent {
    let mut clean_line = source.tidy_line(line);
    for rule_selector in &rule.selectors {
        clean_line = rule_selector.sanitise(&clean_line);
    }
    MatchEvent {
        rule_name: rule.name.clone(),
        rule_description: rule.description.clone(),
        selector: selector.clone(),
        line: clean_line,
        line_no,
    }
}

fn render_simple(source: &LogSource, events: &[MatchEvent], match_count: u64) -> String {
    if match_count == 0 {
        return format!("No failures for {}", source.description);
    }

    let mut report = format!(
        "{match_count} events were detected in {}\n",
        source.description
    );
    let mut by_rule: HashMap<&str, Vec<&MatchEvent>> = HashMap::new();
    for event in events {
        by_rule.entry(&event.rule_name).or_default().push(event);
    }

    let mut reported_rules = HashSet::new();
    for rule_name in &source.rule_names {
        if let Some(rule_events) = by_rule.remove(rule_name.as_str()) {
            append_rule_report(&mut report, rule_name, rule_events, source.top);
            reported_rules.insert(rule_name.as_str());
        }
    }
    for event in events {
        if reported_rules.insert(event.rule_name.as_str())
            && let Some(rule_events) = by_rule.remove(event.rule_name.as_str())
        {
            append_rule_report(&mut report, &event.rule_name, rule_events, source.top);
        }
    }
    report
}

fn append_rule_report(
    report: &mut String,
    rule_name: &str,
    mut rule_events: Vec<&MatchEvent>,
    top: usize,
) {
    let description = rule_events
        .first()
        .map(|event| event.rule_description.as_str())
        .unwrap_or("");
    report.push_str(&format!("Rule: {rule_name} - {description}\n"));
    rule_events.sort_by_key(|event| event.selector.risk());
    for event in rule_events.into_iter().take(top) {
        report.push_str(&format!("{}\n", event.line));
    }
}

#[derive(Default)]
struct GroupedReport {
    groups: HashMap<String, GroupStats>,
    match_count: u64,
    reset_occurred: bool,
}

struct GroupStats {
    key: String,
    description: String,
    risk: Risk,
    count: u64,
    first: Option<(u64, String)>,
    last: Option<(u64, String)>,
}

impl GroupedReport {
    fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, key: String, event: &MatchEvent) {
        self.match_count += 1;
        let stats = self
            .groups
            .entry(key.clone())
            .or_insert_with(|| GroupStats {
                key,
                description: event.selector.description().to_string(),
                risk: Risk::None,
                count: 0,
                first: None,
                last: None,
            });
        stats.count += 1;
        if event.selector.risk() > stats.risk {
            stats.risk = event.selector.risk();
        }
        if stats.first.is_none() {
            stats.first = Some((event.line_no, event.line.clone()));
        } else {
            stats.last = Some((event.line_no, event.line.clone()));
        }
    }

    fn render(&self, top: usize) -> String {
        if self.groups.is_empty() {
            return "No problems found".to_string();
        }
        let mut report = String::new();
        if self.reset_occurred {
            report.push_str("Encountered reset marker in logs, discarded prior logs.\n\n");
        }
        let mut groups = self.groups.values().collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            right
                .risk
                .cmp(&left.risk)
                .then_with(|| right.count.cmp(&left.count))
        });
        for group in groups.into_iter().take(top) {
            report.push_str(&format!(
                "{} {} (occurred: {})\n",
                group.description, group.key, group.count
            ));
            if let Some((line_no, line)) = &group.first {
                report.push_str(&format!("  FIRST line: {line_no} {line}\n"));
            }
            if let Some((line_no, line)) = &group.last {
                report.push_str(&format!("  LAST {line_no} {line}\n"));
            }
        }
        report
    }
}
