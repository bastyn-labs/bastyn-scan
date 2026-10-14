//! `bastyn inspect-server` — capture an MCP server's tool list to a file.

use std::io::Write as _;

use anyhow::Context as _;
use bastyn_core::inspect::{self, InspectRequest, Limits, escape_control};

use crate::cli::InspectServerArgs;

/// Map the arguments onto a request. Clap has already enforced which
/// combinations are allowed.
fn request_of(args: &InspectServerArgs) -> anyhow::Result<InspectRequest> {
    if let (Some(path), Some(server)) = (&args.config, &args.server) {
        return Ok(InspectRequest::Config {
            path: path.clone(),
            server: server.clone(),
            allow_spawn: args.allow_spawn,
        });
    }
    let url = args
        .url
        .clone()
        .context("pass --url, or --config with --server")?;
    Ok(InspectRequest::Http {
        url,
        headers: args.headers.clone(),
    })
}

/// Run the `inspect-server` subcommand.
pub(crate) fn run(args: &InspectServerArgs) -> anyhow::Result<()> {
    let request = request_of(args)?;
    if let InspectRequest::Http { url, .. } = &request
        && inspect::is_plain_http_to_remote_host(url)
    {
        eprintln!(
            "warning: {} is plain http to a non-local host; the traffic and any --header values are not encrypted",
            escape_control(url)
        );
    }

    // Error text can carry what the server sent, so it is escaped before it
    // reaches the terminal through the shared error path.
    let snapshot = inspect::inspect(&request, &Limits::default())
        .map_err(|error| anyhow::anyhow!(escape_control(&error.to_string())))?;
    let json = snapshot.to_json();

    match &args.out {
        Some(path) => std::fs::write(path, &json)
            .with_context(|| format!("could not write {}", path.display()))?,
        None => std::io::stdout()
            .lock()
            .write_all(json.as_bytes())
            .context("could not write to standard output")?,
    }

    eprintln!(
        "captured {} tools from {} ({})",
        snapshot.tools.len(),
        escape_control(&snapshot.server.name),
        escape_control(&snapshot.server.protocol_era)
    );
    Ok(())
}
