use axum::http::Request;
use axum::{body::Body, response::IntoResponse};

use crate::error::Result;

pub struct Proxy {}

impl Proxy {
    // Note on the weird "+ use<>", this is to prevent capturing self lifetime by default.
    // See https://blog.rust-lang.org/2024/09/05/impl-trait-capture-rules/#impl-traits-can-include-a-use-bound-to-specify-precisely-which-generic-types-and-lifetimes-they-use
    pub async fn handle_request(&self, _req: Request<Body>) -> Result<impl IntoResponse + use<>> {
        dbg!("Handling request: {:?}", _req);
        return Ok("TODO".to_string());
    }
}
