use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::errors::{BatmanError, BatmanResult};

#[derive(Debug)]
pub struct SimpleYaml {
    scalars: HashMap<String, String>,
    lists: HashMap<String, Vec<String>>,
}

impl SimpleYaml {
    pub fn load(path: &Path) -> BatmanResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|error| BatmanError::io(format!("read {}", path.display()), error))?;
        Ok(Self::parse(&content))
    }

    pub fn parse(content: &str) -> Self {
        let mut scalars = HashMap::new();
        let mut lists: HashMap<String, Vec<String>> = HashMap::new();
        let mut stack: Vec<(usize, String)> = Vec::new();
        let mut current_list: Option<String> = None;

        for raw_line in content.lines() {
            let without_comment = strip_comment(raw_line);
            if without_comment.trim().is_empty() {
                continue;
            }

            let indent = without_comment
                .as_bytes()
                .iter()
                .take_while(|byte| **byte == b' ')
                .count();
            let line = without_comment.trim();

            while stack.last().is_some_and(|(level, _)| *level >= indent) {
                stack.pop();
            }

            if let Some(item) = line.strip_prefix("- ") {
                if item.contains(':') && !item.starts_with('"') && !item.starts_with('\'') {
                    current_list = None;
                    continue;
                }
                if let Some(path) = &current_list {
                    lists
                        .entry(path.clone())
                        .or_default()
                        .push(clean_value(item).to_string());
                }
                continue;
            }

            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            let path = join_path(&stack, key);
            let value = value.trim();

            if value.is_empty() {
                stack.push((indent, key.to_string()));
                current_list = Some(path);
                continue;
            }

            current_list = None;
            if value.starts_with('[') && value.ends_with(']') {
                lists.insert(path, parse_inline_list(value));
            } else {
                scalars.insert(path, clean_value(value).to_string());
            }
        }

        Self { scalars, lists }
    }

    pub fn scalar(&self, path: &str) -> Option<&str> {
        self.scalars.get(path).map(String::as_str)
    }

    pub fn bool(&self, path: &str, default: bool) -> bool {
        self.scalar(path)
            .and_then(|value| match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })
            .unwrap_or(default)
    }

    pub fn usize(&self, path: &str, default: usize) -> usize {
        self.scalar(path)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    pub fn list(&self, path: &str) -> Vec<String> {
        self.lists.get(path).cloned().unwrap_or_default()
    }

    pub fn has_list(&self, path: &str) -> bool {
        self.lists.contains_key(path)
    }
}

fn join_path(stack: &[(usize, String)], key: &str) -> String {
    let mut parts: Vec<&str> = stack.iter().map(|(_, part)| part.as_str()).collect();
    parts.push(key);
    parts.join(".")
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => return &line[..index],
            _ => {}
        }
    }
    line
}

fn clean_value(value: &str) -> &str {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
}

fn parse_inline_list(value: &str) -> Vec<String> {
    value
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(clean_value)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}
