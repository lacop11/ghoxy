//! Token wrapper that prevents accidental logging.

/// Token wrapper that prevents accidental logging.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl Token {
    /// Wrap a sensitive string.
    pub fn new(token: String) -> Self {
        Token(token)
    }

    /// Unwrap the sensitive value.
    pub fn get_sensitive_value(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token({} chars)", self.0.len())
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token({} chars)", self.0.len())
    }
}
