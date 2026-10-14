//! Capturing the tools an MCP server offers.
//!
//! This module holds the pieces shared by the transports: the snapshot file
//! format, the guard that refuses unsafe addresses, the JSON-RPC message
//! builders, the Server-Sent Events reader, and the Streamable HTTP client.

use std::time::Duration;

mod error;
pub(crate) mod guard;
mod http;
pub(crate) mod jsonrpc;
pub mod snapshot;
pub(crate) mod sse;

pub use error::InspectError;
pub use http::{HttpTarget, capture_http};
pub use snapshot::{SNAPSHOT_SCHEMA, ServerInfo, Snapshot};

/// Time, size and page caps applied to every capture.
///
/// The defaults are chosen values: a server that is slow, large or endless is
/// refused instead of waited for.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest time to wait for a connection. Default 10 seconds.
    pub connect: Duration,
    /// Longest time for one whole request, including reading the reply.
    /// Default 30 seconds.
    pub total: Duration,
    /// Largest reply body accepted, in bytes. Default 4 MiB.
    pub max_body_bytes: u64,
    /// Most `tools/list` pages followed. Default 20.
    pub max_pages: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            total: Duration::from_secs(30),
            max_body_bytes: 4 * 1024 * 1024,
            max_pages: 20,
        }
    }
}

/// Which protocol revision a server answered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// The current revision, where each request names the version.
    Modern,
    /// The earlier revision that begins with an `initialize` handshake.
    Legacy,
}

impl Era {
    /// The name written to the snapshot file.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::Legacy => "legacy",
        }
    }
}

/// The tools a server listed, and how it was asked.
#[derive(Debug, Clone)]
pub struct Capture {
    /// The protocol era the server answered in.
    pub era: Era,
    /// The protocol version used for the requests.
    pub protocol_version: String,
    /// The tool definitions exactly as the server sent them. They are data
    /// from an untrusted server and are never interpreted.
    pub tools: Vec<serde_json::Value>,
}
