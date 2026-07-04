use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::{BatmanError, BatmanResult};
use crate::logscan::selectors::{
    ContainsSelector, CreditCardSelector, OneOfSelector, RegexSelector, Risk, Selector,
    SelectorBase, compile_regexes,
};
use crate::logscan::sources::{LogSource, SourceKind};
use crate::logscan::yaml_util::{
    clean_list_item, clean_value, count_indent, parse_bool, parse_list, strip_comment,
};

#[derive(Clone, Debug)]
pub struct LogAuditConfig {
    pub rules: Vec<LogRule>,
    pub sources: Vec<LogSource>,
}

#[derive(Clone, Debug)]
pub struct LogRule {
    pub name: String,
    pub description: String,
    pub group_by: Option<String>,
    pub selectors: Vec<Selector>,
}

#[derive(Default)]
struct RuleBuilder {
    name: String,
    description: String,
    group_by: Option<String>,
    selectors: Vec<SelectorBuilder>,
}

#[derive(Default)]
struct SelectorBuilder {
    selector_type: String,
    description: String,
    risk: String,
    continue_scan: Option<bool>,
    matches: Vec<String>,
    excludes: Vec<String>,
    insensitive: bool,
}

#[derive(Default)]
struct SourceBuilder {
    source_type: String,
    name: String,
    description: String,
    top: Option<usize>,
    path: Option<PathBuf>,
    container: Option<String>,
    since: Option<String>,
    args: Option<String>,
    trim_prefix: Option<String>,
    reset: Option<String>,
    group_by: Option<String>,
    report_to: Option<String>,
    rule_names: Vec<String>,
}

enum Mode {
    None,
    Sources,
    Rules,
}

#[derive(Clone, Copy)]
enum SelectorListKind {
    Matches,
    Excludes,
}

impl LogAuditConfig {
    pub fn load(path: &Path) -> BatmanResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> BatmanResult<Self> {
        let mut mode = Mode::None;
        let mut sources = Vec::new();
        let mut rules = Vec::new();
        let mut source = None::<SourceBuilder>;
        let mut rule = None::<RuleBuilder>;
        let mut selector = None::<SelectorBuilder>;
        let mut in_source_rules = false;
        let mut in_selectors = false;
        let mut selector_list = None::<SelectorListKind>;

        for raw_line in content.lines() {
            let line = strip_comment(raw_line);
            if line.trim().is_empty() {
                continue;
            }
            let indent = count_indent(line);
            let trimmed = line.trim();

            if indent <= 2 && trimmed == "log_sources:" {
                flush_selector(&mut rule, &mut selector);
                flush_rule(&mut rules, &mut rule)?;
                flush_source(&mut sources, &mut source)?;
                mode = Mode::Sources;
                in_source_rules = false;
                in_selectors = false;
                selector_list = None;
                continue;
            }
            if indent <= 2 && trimmed == "rules:" {
                flush_source(&mut sources, &mut source)?;
                mode = Mode::Rules;
                in_source_rules = false;
                in_selectors = false;
                selector_list = None;
                continue;
            }

            match mode {
                Mode::Sources => {
                    parse_source_line(trimmed, &mut sources, &mut source, &mut in_source_rules)?
                }
                Mode::Rules => parse_rule_line(
                    trimmed,
                    &mut rules,
                    &mut rule,
                    &mut selector,
                    &mut in_selectors,
                    &mut selector_list,
                )?,
                Mode::None => {}
            }
        }

        flush_selector(&mut rule, &mut selector);
        flush_rule(&mut rules, &mut rule)?;
        flush_source(&mut sources, &mut source)?;
        validate_source_names(&sources)?;
        validate_rule_references(&sources, &rules)?;
        Ok(Self { rules, sources })
    }

    pub fn find_rule(&self, name: &str) -> Option<&LogRule> {
        self.rules.iter().find(|rule| rule.name == name)
    }

    pub fn find_source(&self, name: &str) -> Option<&LogSource> {
        self.sources.iter().find(|source| source.name == name)
    }
}

fn parse_source_line(
    trimmed: &str,
    sources: &mut Vec<LogSource>,
    source: &mut Option<SourceBuilder>,
    in_source_rules: &mut bool,
) -> BatmanResult<()> {
    if trimmed.starts_with("- log_source:") {
        flush_source(sources, source)?;
        *source = Some(SourceBuilder::default());
        *in_source_rules = false;
        return Ok(());
    }
    let Some(current) = source.as_mut() else {
        return Ok(());
    };
    if trimmed == "rules:" {
        *in_source_rules = true;
        return Ok(());
    }
    if *in_source_rules {
        if let Some(value) = trimmed.strip_prefix("- rule:") {
            current.rule_names.push(clean_value(value).to_string());
        }
        return Ok(());
    }
    let Some((key, value)) = trimmed.split_once(':') else {
        return Ok(());
    };
    let value = clean_value(value);
    match key.trim() {
        "type" => current.source_type = value.to_string(),
        "name" => current.name = value.to_string(),
        "description" => current.description = value.to_string(),
        "top" => current.top = value.parse().ok(),
        "path" => current.path = Some(PathBuf::from(value)),
        "container" => current.container = Some(value.to_string()),
        "since" => current.since = Some(value.to_string()),
        "args" => current.args = Some(value.to_string()),
        "trim_prefix" => current.trim_prefix = Some(value.to_string()),
        "reset" => current.reset = Some(value.to_string()),
        "group_by" => current.group_by = Some(value.to_string()),
        "report_to" => current.report_to = Some(value.to_string()),
        _ => {}
    }
    Ok(())
}

fn parse_rule_line(
    trimmed: &str,
    rules: &mut Vec<LogRule>,
    rule: &mut Option<RuleBuilder>,
    selector: &mut Option<SelectorBuilder>,
    in_selectors: &mut bool,
    selector_list: &mut Option<SelectorListKind>,
) -> BatmanResult<()> {
    if trimmed.starts_with("- rule:") {
        flush_selector(rule, selector);
        flush_rule(rules, rule)?;
        *rule = Some(RuleBuilder::default());
        *in_selectors = false;
        *selector_list = None;
        return Ok(());
    }
    let Some(current_rule) = rule.as_mut() else {
        return Ok(());
    };
    if trimmed == "selectors:" {
        *in_selectors = true;
        *selector_list = None;
        return Ok(());
    }
    if *in_selectors {
        if trimmed.starts_with("- selector:") {
            flush_selector(rule, selector);
            *selector = Some(SelectorBuilder::default());
            *selector_list = None;
            return Ok(());
        }
        if trimmed.starts_with("- ") {
            if let (Some(kind), Some(current_selector)) = (*selector_list, selector.as_mut()) {
                add_selector_list_item(trimmed, current_selector, kind);
            }
            return Ok(());
        }
        if let Some(current_selector) = selector.as_mut() {
            *selector_list = parse_selector_key(trimmed, current_selector);
        }
        return Ok(());
    }
    *selector_list = None;
    let Some((key, value)) = trimmed.split_once(':') else {
        return Ok(());
    };
    let value = clean_value(value);
    match key.trim() {
        "name" => current_rule.name = value.to_string(),
        "description" => current_rule.description = value.to_string(),
        "group_by" => current_rule.group_by = Some(value.to_string()),
        _ => {}
    }
    Ok(())
}

fn parse_selector_key(trimmed: &str, selector: &mut SelectorBuilder) -> Option<SelectorListKind> {
    let (key, value) = trimmed.split_once(':')?;
    let value = value.trim();
    match key.trim() {
        "type" => selector.selector_type = clean_value(value).to_string(),
        "description" => selector.description = clean_value(value).to_string(),
        "risk" => selector.risk = clean_value(value).to_string(),
        "continue" => selector.continue_scan = parse_bool(clean_value(value)),
        "match" => {
            return parse_selector_list(value, &mut selector.matches, SelectorListKind::Matches);
        }
        "exclude" => {
            return parse_selector_list(value, &mut selector.excludes, SelectorListKind::Excludes);
        }
        "insensitive" => selector.insensitive = parse_bool(clean_value(value)).unwrap_or(false),
        _ => {}
    }
    None
}

fn parse_selector_list(
    value: &str,
    target: &mut Vec<String>,
    kind: SelectorListKind,
) -> Option<SelectorListKind> {
    if value.is_empty() {
        target.clear();
        Some(kind)
    } else {
        *target = parse_list(value);
        None
    }
}

fn add_selector_list_item(trimmed: &str, selector: &mut SelectorBuilder, kind: SelectorListKind) {
    let Some(item) = clean_list_item(trimmed) else {
        return;
    };
    match kind {
        SelectorListKind::Matches => selector.matches.push(item),
        SelectorListKind::Excludes => selector.excludes.push(item),
    }
}

fn flush_source(
    sources: &mut Vec<LogSource>,
    source: &mut Option<SourceBuilder>,
) -> BatmanResult<()> {
    let Some(builder) = source.take() else {
        return Ok(());
    };
    if builder.source_type.is_empty() {
        return Err(BatmanError::Parse("log_source missing type".to_string()));
    }
    let kind = match builder.source_type.as_str() {
        "file" => SourceKind::File,
        "journalctl" => SourceKind::JournalCtl,
        other => {
            return Err(BatmanError::Parse(format!(
                "invalid log_source type {other}"
            )));
        }
    };
    if builder.name.contains(' ') {
        return Err(BatmanError::Parse(format!(
            "log_source name '{}' may not contain spaces",
            builder.name
        )));
    }
    match kind {
        SourceKind::File if builder.path.is_none() => {
            return Err(BatmanError::Parse(format!(
                "log_source {} is missing a path attribute",
                builder.name
            )));
        }
        _ => {}
    }
    sources.push(LogSource {
        kind,
        name: builder.name,
        description: if builder.description.is_empty() {
            "not supplied".to_string()
        } else {
            builder.description
        },
        top: builder.top.unwrap_or(1000),
        rule_names: builder.rule_names,
        path: builder.path,
        container: builder.container,
        since: builder.since,
        args: builder.args,
        trim_prefix: builder.trim_prefix,
        reset: builder.reset,
        group_by: builder.group_by,
        report_to: builder.report_to,
        override_source: None,
    });
    Ok(())
}

fn flush_rule(rules: &mut Vec<LogRule>, rule: &mut Option<RuleBuilder>) -> BatmanResult<()> {
    let Some(builder) = rule.take() else {
        return Ok(());
    };
    if builder.name.is_empty() {
        return Err(BatmanError::Parse("rule missing name".to_string()));
    }
    let selectors = builder
        .selectors
        .iter()
        .map(build_selector)
        .collect::<BatmanResult<Vec<_>>>()?;
    rules.push(LogRule {
        name: builder.name,
        description: builder.description,
        group_by: builder.group_by,
        selectors,
    });
    Ok(())
}

fn flush_selector(rule: &mut Option<RuleBuilder>, selector: &mut Option<SelectorBuilder>) {
    if let (Some(rule), Some(selector)) = (rule.as_mut(), selector.take()) {
        rule.selectors.push(selector);
    }
}

fn build_selector(builder: &SelectorBuilder) -> BatmanResult<Selector> {
    let risk = if builder.risk.is_empty() {
        Risk::Critical
    } else {
        Risk::parse(&builder.risk)?
    };
    let base = SelectorBase {
        description: builder.description.clone(),
        risk,
        terminate: !builder.continue_scan.unwrap_or(true),
    };
    match builder.selector_type.as_str() {
        "contains" => {
            if builder.matches.is_empty() {
                return Err(BatmanError::Parse(
                    "contains selector missing match".to_string(),
                ));
            }
            let (matches, excludes) = normalise_case(builder);
            Ok(Selector::Contains(ContainsSelector {
                base,
                matches,
                excludes,
                insensitive: builder.insensitive,
            }))
        }
        "one_of" => {
            if builder.matches.is_empty() {
                return Err(BatmanError::Parse(
                    "one_of selector missing match".to_string(),
                ));
            }
            let (matches, excludes) = normalise_case(builder);
            Ok(Selector::OneOf(OneOfSelector {
                base,
                matches,
                excludes,
                insensitive: builder.insensitive,
            }))
        }
        "regex" => {
            if builder.matches.is_empty() {
                return Err(BatmanError::Parse(
                    "regex selector missing match".to_string(),
                ));
            }
            Ok(Selector::Regex(RegexSelector {
                base,
                matches: compile_regexes(&builder.matches)?,
                excludes: compile_regexes(&builder.excludes)?,
            }))
        }
        "creditcard" => Ok(Selector::CreditCard(CreditCardSelector::new(base)?)),
        other => Err(BatmanError::Parse(format!("invalid selector type {other}"))),
    }
}

fn validate_source_names(sources: &[LogSource]) -> BatmanResult<()> {
    let mut names = HashSet::new();
    for source in sources {
        if !names.insert(source.name.clone()) {
            return Err(BatmanError::Parse(format!(
                "duplicate log_source name '{}'",
                source.name
            )));
        }
    }
    Ok(())
}

fn validate_rule_references(sources: &[LogSource], rules: &[LogRule]) -> BatmanResult<()> {
    let rule_names = rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect::<HashSet<_>>();
    for source in sources {
        for rule_name in &source.rule_names {
            if !rule_names.contains(rule_name.as_str()) {
                return Err(BatmanError::Parse(format!(
                    "LogSource: {} references an unknown rule {}",
                    source.description, rule_name
                )));
            }
        }
    }
    Ok(())
}

fn normalise_case(builder: &SelectorBuilder) -> (Vec<String>, Vec<String>) {
    if builder.insensitive {
        (
            builder
                .matches
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
            builder
                .excludes
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
        )
    } else {
        (builder.matches.clone(), builder.excludes.clone())
    }
}
