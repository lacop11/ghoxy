//! Client-side authentication.
//!
//! Client meaning the proxy client connecting to this server. We need to check provided JWT tokens and extract claims.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![deny(missing_docs)]

mod claims;
pub use claims::Claims;

mod validator;
pub use validator::{TokenValidator, TokenValidatorOptions};

mod error;
pub use error::{Error, Result};
