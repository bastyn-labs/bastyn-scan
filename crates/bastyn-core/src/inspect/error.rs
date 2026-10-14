//! The error type shared by the capture transports.

/// Why capturing a server's tools failed.
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    /// The address guard refused the URL.
    #[error("{0}")]
    Guard(String),
    /// The request could not be completed.
    #[error("network error: {0}")]
    Network(String),
    /// The server answered 401 or 403.
    #[error("the server requires authentication (HTTP {status}); pass credentials with --header")]
    AuthRequired {
        /// The HTTP status the server answered with.
        status: u16,
    },
    /// The server's reply did not follow the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The server speaks the deprecated HTTP+SSE transport.
    #[error("the server uses the deprecated HTTP+SSE transport, which this command does not speak")]
    DeprecatedSse,
    /// A reply was larger than the configured size cap.
    #[error("the server's reply is larger than the size limit")]
    TooLarge,
    /// The server kept offering further pages past the page cap.
    #[error("the server offered more pages of tools than the page limit allows")]
    TooManyPages,
    /// The server process could not be started.
    #[error("could not start the server: {0}")]
    Spawn(String),
    /// The command was refused before running.
    #[error("{0}")]
    Refused(String),
    /// The server configuration could not be used.
    #[error("{0}")]
    Config(String),
}
