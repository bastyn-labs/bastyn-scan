//! Capturing the tools an MCP server offers.
//!
//! This module holds the pieces shared by the transports: the snapshot file
//! format, the guard that refuses unsafe addresses, the JSON-RPC message
//! builders, and the Server-Sent Events reader.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the HTTP and stdio clients that call these are added next; remove with them"
    )
)]
pub(crate) mod guard;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the HTTP and stdio clients that call these are added next; remove with them"
    )
)]
pub(crate) mod jsonrpc;
pub mod snapshot;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the HTTP and stdio clients that call these are added next; remove with them"
    )
)]
pub(crate) mod sse;

pub use snapshot::{SNAPSHOT_SCHEMA, ServerInfo, Snapshot};
