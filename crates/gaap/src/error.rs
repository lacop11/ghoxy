use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {}

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, Error>;
