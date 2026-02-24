//! TODO document the project here briefly
//! main docs in readme but this shows up in the published crate so have some summary + reference here

mod error;
pub use error::{ProxyError, ProxyResult, ServerError, ServerResult};

mod server;
pub use server::{ServerOptions, create_server};

mod user_agent;
pub use user_agent::USER_AGENT;

pub(crate) mod proxy;
