/// User agent used for github requests.
// TODO: Include repository path?
pub const USER_AGENT: &str = concat!("ghoxy/", env!("CARGO_PKG_VERSION"));
