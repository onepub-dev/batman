use std::fmt::{Display, Formatter};

pub type BatmanResult<T> = Result<T, BatmanError>;

#[derive(Debug)]
pub enum BatmanError {
    Config(String),
    Io {
        context: String,
        source: std::io::Error,
    },
    Parse(String),
    Store(String),
    Usage(String),
}

impl BatmanError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl Display for BatmanError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration error: {message}"),
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::Parse(message) => write!(formatter, "parse error: {message}"),
            Self::Store(message) => write!(formatter, "store error: {message}"),
            Self::Usage(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for BatmanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
