//! The DNS server: sockets, request handling and the process lifecycle.

pub mod bind;
pub mod handler;

pub use handler::{Handler, Zones};
