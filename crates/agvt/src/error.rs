use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct AgvtError {
    message: String,
}

impl AgvtError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for AgvtError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AgvtError {}

impl From<std::io::Error> for AgvtError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for AgvtError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AgvtError>;
