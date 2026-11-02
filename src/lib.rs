//! hdc-direct 库入口：协议编码、认证、会话。

pub mod auth;
pub mod proto;
pub mod session;

pub use session::HdcSession;
