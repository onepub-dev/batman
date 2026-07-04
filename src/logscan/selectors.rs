use regex::Regex;

use crate::errors::{BatmanError, BatmanResult};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Risk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    NoMatch,
    MatchContinue,
    MatchTerminate,
}

#[derive(Clone, Debug)]
pub enum Selector {
    Contains(ContainsSelector),
    OneOf(OneOfSelector),
    Regex(RegexSelector),
    CreditCard(CreditCardSelector),
}

#[derive(Clone, Debug)]
pub struct SelectorBase {
    pub description: String,
    pub risk: Risk,
    pub terminate: bool,
}

#[derive(Clone, Debug)]
pub struct ContainsSelector {
    pub base: SelectorBase,
    pub matches: Vec<String>,
    pub excludes: Vec<String>,
    pub insensitive: bool,
}

#[derive(Clone, Debug)]
pub struct OneOfSelector {
    pub base: SelectorBase,
    pub matches: Vec<String>,
    pub excludes: Vec<String>,
    pub insensitive: bool,
}

#[derive(Clone, Debug)]
pub struct RegexSelector {
    pub base: SelectorBase,
    pub matches: Vec<Regex>,
    pub excludes: Vec<Regex>,
}

#[derive(Clone, Debug)]
pub struct CreditCardSelector {
    pub base: SelectorBase,
    pattern: Regex,
}

impl Selector {
    pub fn evaluate(&self, line: &str) -> Selection {
        match self {
            Self::Contains(selector) => selector.evaluate(line),
            Self::OneOf(selector) => selector.evaluate(line),
            Self::Regex(selector) => selector.evaluate(line),
            Self::CreditCard(selector) => selector.evaluate(line),
        }
    }

    pub fn sanitise(&self, line: &str) -> String {
        match self {
            Self::CreditCard(selector) => selector.sanitise(line),
            _ => line.to_string(),
        }
    }

    pub fn description(&self) -> &str {
        &self.base().description
    }

    pub fn risk(&self) -> Risk {
        self.base().risk
    }

    pub fn terminate(&self) -> bool {
        self.base().terminate
    }

    fn base(&self) -> &SelectorBase {
        match self {
            Self::Contains(selector) => &selector.base,
            Self::OneOf(selector) => &selector.base,
            Self::Regex(selector) => &selector.base,
            Self::CreditCard(selector) => &selector.base,
        }
    }
}

impl ContainsSelector {
    pub fn evaluate(&self, line: &str) -> Selection {
        let haystack;
        let line = if self.insensitive {
            haystack = line.to_lowercase();
            haystack.as_str()
        } else {
            line
        };
        let matched = self.matches.iter().all(|value| line.contains(value))
            && !self.excludes.iter().any(|value| line.contains(value));
        self.base.selection(matched)
    }
}

impl OneOfSelector {
    pub fn evaluate(&self, line: &str) -> Selection {
        let haystack;
        let line = if self.insensitive {
            haystack = line.to_lowercase();
            haystack.as_str()
        } else {
            line
        };
        let matched = self.matches.iter().any(|value| line.contains(value))
            && !self.excludes.iter().any(|value| line.contains(value));
        self.base.selection(matched)
    }
}

impl RegexSelector {
    pub fn evaluate(&self, line: &str) -> Selection {
        let matched = self.matches.iter().all(|regex| regex.is_match(line))
            && !self.excludes.iter().any(|regex| regex.is_match(line));
        self.base.selection(matched)
    }
}

impl CreditCardSelector {
    pub fn new(base: SelectorBase) -> BatmanResult<Self> {
        Ok(Self {
            base,
            pattern: Regex::new(r"(\d{16}\d*)")
                .map_err(|error| BatmanError::Parse(error.to_string()))?,
        })
    }

    pub fn evaluate(&self, line: &str) -> Selection {
        let compacted = line.replace(['.', '-', ' '], "");
        let matched = self
            .pattern
            .captures_iter(&compacted)
            .filter_map(|capture| capture.get(1))
            .any(|capture| is_luhn(capture.as_str()));
        self.base.selection(matched)
    }

    pub fn sanitise(&self, line: &str) -> String {
        self.pattern
            .replace_all(line, "XXXX XXXX XXXX XXXX")
            .to_string()
    }
}

impl SelectorBase {
    pub fn selection(&self, matched: bool) -> Selection {
        if !matched {
            Selection::NoMatch
        } else if self.terminate {
            Selection::MatchTerminate
        } else {
            Selection::MatchContinue
        }
    }
}

impl Risk {
    pub fn parse(value: &str) -> BatmanResult<Self> {
        match value {
            "none" => Ok(Self::None),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(BatmanError::Parse(format!("invalid risk {value}"))),
        }
    }
}

pub fn compile_regexes(values: &[String]) -> BatmanResult<Vec<Regex>> {
    values
        .iter()
        .map(|value| Regex::new(value).map_err(|error| BatmanError::Parse(error.to_string())))
        .collect()
}

fn is_luhn(value: &str) -> bool {
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0_u32;
    let mut should_double = false;
    for digit in value.bytes().rev() {
        let mut number = (digit - b'0') as u32;
        if should_double {
            number *= 2;
            if number >= 10 {
                number = (number % 10) + 1;
            }
        }
        sum += number;
        should_double = !should_double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::{CreditCardSelector, Risk, Selection, SelectorBase};

    #[test]
    fn credit_card_uses_luhn_and_sanitises() {
        let selector = CreditCardSelector::new(SelectorBase {
            description: "cc".to_string(),
            risk: Risk::Critical,
            terminate: true,
        })
        .unwrap();

        assert_eq!(
            selector.evaluate("card 4111111111111111"),
            Selection::MatchTerminate
        );
        assert_eq!(
            selector.sanitise("card 4111111111111111"),
            "card XXXX XXXX XXXX XXXX"
        );
        assert_eq!(
            selector.evaluate("card 4111111111111112"),
            Selection::NoMatch
        );
    }
}
