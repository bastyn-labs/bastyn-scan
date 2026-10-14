//! Capturing a server's tools over the stdio transport.
//!
//! The command comes from a config file that may be untrusted, so it is run
//! under fixed rules: the environment is cleared except `PATH`, `HOME` and the
//! entry's own variables, every wait is bounded in time, a single output line
//! is read under a size cap, and the process is always shut down afterwards.
//! Whatever the server prints is kept as data and never interpreted.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::http::{error_text, tools_of};
use super::jsonrpc::{self, MODERN_VERSION, Reply, is_recognised_modern_error, next_cursor};
use super::{Capture, Era, InspectError, Limits};

/// How long a server gets to exit on its own after its input is closed.
const GRACE: Duration = Duration::from_secs(2);

/// How many output lines the reader thread may hold ahead of the consumer.
/// A line can be as large as the body cap (4 MiB by default), so a small
/// bound keeps a flooding server from filling memory.
const LINE_BUFFER: usize = 2;

/// A server started as a local process.
#[derive(Debug, Clone)]
pub struct StdioTarget {
    /// The program to run.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// Environment variables from the config entry, added on top of `PATH`
    /// and `HOME`.
    pub env: Vec<(String, String)>,
    /// The working directory, when the entry sets one.
    pub cwd: Option<PathBuf>,
}

/// One unit read from the server's output.
enum Line {
    Text(String),
    /// A single line exceeded the size cap.
    Overflow,
}

/// A running server and the state needed to talk to it.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Line>,
    next_id: u64,
    skipped: usize,
    total: Duration,
}

impl Session {
    fn start(target: &StdioTarget, limits: &Limits) -> Result<Self, InspectError> {
        let mut command = Command::new(&target.program);
        command.args(&target.args).env_clear();
        for name in ["PATH", "HOME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.envs(target.env.iter().map(|(name, value)| (name, value)));
        if let Some(cwd) = &target.cwd {
            command.current_dir(cwd);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| InspectError::Spawn(error.to_string()))?;
        let stdin = child.stdin.take();
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(InspectError::Spawn("the server has no output".into()));
        };
        let (sender, lines) = mpsc::sync_channel(LINE_BUFFER);
        let cap = limits.max_body_bytes;
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut buffer = Vec::new();
                let read = (&mut reader)
                    .take(cap.saturating_add(1))
                    .read_until(b'\n', &mut buffer);
                match read {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let line = if buffer.last() == Some(&b'\n') || buffer.len() as u64 <= cap {
                    Line::Text(String::from_utf8_lossy(&buffer).into_owned())
                } else {
                    Line::Overflow
                };
                let overflow = matches!(line, Line::Overflow);
                if sender.send(line).is_err() || overflow {
                    return;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            next_id: 1,
            skipped: 0,
            total: limits.total,
        })
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn send(&mut self, value: &Value) -> Result<(), InspectError> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| InspectError::Protocol("the server's input is closed".into()))?;
        writeln!(stdin, "{value}")
            .and_then(|()| stdin.flush())
            .map_err(|error| {
                InspectError::Protocol(format!("could not write to the server: {error}"))
            })
    }

    /// The reply to request `id`, or `None` when the deadline passes or the
    /// server closes its output first. Lines that are not JSON, or that answer
    /// a different request, are skipped and counted.
    fn wait_for(&mut self, id: u64, deadline: Instant) -> Result<Option<Reply>, InspectError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Line::Text(line)) => line,
                Ok(Line::Overflow) => return Err(InspectError::TooLarge),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Ok(None);
                }
            };
            let reply = serde_json::from_str::<Value>(line.trim())
                .ok()
                .and_then(|message| jsonrpc::parse_reply(&message, id));
            match reply {
                Some(reply) => return Ok(Some(reply)),
                None => self.skipped += 1,
            }
        }
    }

    /// Sends `request` (built from its id) and waits for its reply.
    fn call(&mut self, build: impl FnOnce(u64) -> Value) -> Result<Option<Reply>, InspectError> {
        let id = self.take_id();
        self.send(&build(id))?;
        let deadline = Instant::now() + self.total;
        self.wait_for(id, deadline)
    }

    fn no_reply(&self) -> InspectError {
        InspectError::Protocol(format!(
            "the server did not answer in time or closed its output ({} lines skipped)",
            self.skipped
        ))
    }

    fn list_pages(&mut self, modern: bool, limits: &Limits) -> Result<Vec<Value>, InspectError> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..limits.max_pages {
            let reply = self.call(|id| {
                if modern {
                    jsonrpc::modern_request(id, "tools/list", cursor.as_deref())
                } else {
                    jsonrpc::legacy_request(id, "tools/list", cursor.as_deref())
                }
            })?;
            match reply {
                Some(Reply::Result(result)) => {
                    tools.extend(tools_of(&result)?);
                    cursor = next_cursor(&result);
                    if cursor.is_none() {
                        return Ok(tools);
                    }
                }
                Some(Reply::Error {
                    code,
                    message,
                    data,
                }) => {
                    return Err(InspectError::Protocol(error_text(
                        code,
                        &message,
                        data.as_ref(),
                    )));
                }
                None => return Err(self.no_reply()),
            }
        }
        Err(InspectError::TooManyPages)
    }

    fn capture(&mut self, limits: &Limits) -> Result<Capture, InspectError> {
        match self.call(|id| jsonrpc::modern_request(id, "server/discover", None))? {
            Some(Reply::Result(_)) => {
                let tools = self.list_pages(true, limits)?;
                return Ok(Capture {
                    era: Era::Modern,
                    protocol_version: MODERN_VERSION.to_owned(),
                    tools,
                });
            }
            Some(Reply::Error {
                code,
                message,
                data,
            }) if is_recognised_modern_error(code) => {
                return Err(InspectError::Protocol(error_text(
                    code,
                    &message,
                    data.as_ref(),
                )));
            }
            _ => {}
        }
        let version = match self.call(jsonrpc::legacy_initialize)? {
            Some(Reply::Result(result)) => jsonrpc::negotiated_version(&result),
            Some(Reply::Error {
                code,
                message,
                data,
            }) => {
                return Err(InspectError::Protocol(error_text(
                    code,
                    &message,
                    data.as_ref(),
                )));
            }
            None => return Err(self.no_reply()),
        };
        self.send(&jsonrpc::notification("notifications/initialized"))?;
        let tools = self.list_pages(false, limits)?;
        Ok(Capture {
            era: Era::Legacy,
            protocol_version: version,
            tools,
        })
    }

    /// Closes the server's input, gives it a short time to exit, then kills
    /// it and collects its exit status. Safe to run more than once.
    fn shutdown(&mut self) {
        drop(self.stdin.take());
        let end = Instant::now() + GRACE;
        while Instant::now() < end {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Starts the server described by `target` and lists its tools.
///
/// Running a command taken from a configuration file executes code, so callers
/// must obtain the user's explicit consent (`--allow-spawn`) before calling
/// this function; it does not ask.
///
/// The child runs with a cleared environment holding only `PATH`, `HOME` (when
/// set in this process) and the variables in `target.env`; its standard error
/// is discarded. The server is first sent `server/discover`; if it does not
/// answer that with a result or a modern-only error within `limits.total`, the
/// legacy `initialize` handshake is used. Output lines that are not JSON, or
/// that answer another request, are skipped.
///
/// The process is always shut down, on success and on every error: its input
/// is closed, it is given up to two seconds to exit, and then it is killed and
/// reaped. The specification recommends escalating from SIGTERM to SIGKILL;
/// the standard library has no SIGTERM and unsafe code is forbidden here, so
/// this closes the input and then kills.
///
/// # Errors
///
/// Returns an [`InspectError`] when the process cannot be started, replies
/// outside the protocol, stays silent past `limits.total`, or exceeds a limit
/// in `limits`.
pub fn capture_stdio(target: &StdioTarget, limits: &Limits) -> Result<Capture, InspectError> {
    let mut session = Session::start(target, limits)?;
    let result = session.capture(limits);
    session.shutdown();
    result
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn sh(script: &str) -> StdioTarget {
        StdioTarget {
            program: "sh".into(),
            args: vec!["-c".into(), script.into()],
            env: Vec::new(),
            cwd: None,
        }
    }

    #[cfg(unix)]
    fn short(total_ms: u64) -> Limits {
        Limits {
            total: Duration::from_millis(total_ms),
            ..Limits::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_modern_stdio_server_is_probed_with_discover_then_listed() {
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"]}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","description":"d"}]}}'"#;
        let capture = capture_stdio(&sh(script), &Limits::default()).unwrap();
        assert_eq!(capture.era, Era::Modern);
        assert_eq!(capture.tools.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_legacy_stdio_server_falls_back_to_initialize() {
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"s","version":"1"}}}'; read c; read d; printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"a"}]}}'"#;
        let capture = capture_stdio(&sh(script), &Limits::default()).unwrap();
        assert_eq!(capture.era, Era::Legacy);
        assert_eq!(capture.tools.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_legacy_stdio_server_reports_the_version_it_chose() {
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}'; read c; read d; printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}'"#;
        let capture = capture_stdio(&sh(script), &Limits::default()).unwrap();
        assert_eq!(capture.era, Era::Legacy);
        assert_eq!(capture.protocol_version, "2025-06-18");
    }

    #[cfg(unix)]
    #[test]
    fn a_discover_probe_that_gets_no_answer_falls_back_to_legacy() {
        let script = r#"read a; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'; read c; read d; printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"a"}]}}'"#;
        let capture = capture_stdio(&sh(script), &short(700)).unwrap();
        assert_eq!(capture.era, Era::Legacy);
        assert_eq!(capture.tools.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_modern_only_error_is_not_retried_as_legacy() {
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported"}}'; sleep 5"#;
        let result = capture_stdio(&sh(script), &Limits::default());
        assert!(matches!(result, Err(InspectError::Protocol(_))));
    }

    #[cfg(unix)]
    #[test]
    fn non_json_banner_lines_are_skipped() {
        let script = r#"printf '%s\n' 'server starting...'; read a; printf '%s\n' 'warming up' '{"jsonrpc":"2.0","id":9,"result":{}}' '{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"]}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'"#;
        let capture = capture_stdio(&sh(script), &Limits::default()).unwrap();
        assert_eq!(capture.era, Era::Modern);
        assert_eq!(capture.tools.len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn tools_with_a_missing_or_null_description_are_kept_as_sent() {
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"},{"name":"b","description":null}]}}'"#;
        let capture = capture_stdio(&sh(script), &Limits::default()).unwrap();
        assert_eq!(capture.tools.len(), 2);
        assert!(capture.tools[0].get("description").is_none());
        assert!(capture.tools[1]["description"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn a_silent_server_times_out_and_is_killed() {
        let started = Instant::now();
        let result = capture_stdio(&sh("sleep 30"), &short(600));
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child must be killed, not waited for"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_process_is_gone_after_a_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("echo $$ > '{}'; exec sleep 30", pid_file.display());
        assert!(capture_stdio(&sh(&script), &short(600)).is_err());
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!alive, "the server process must not outlive the capture");
    }

    #[cfg(unix)]
    #[test]
    fn the_child_environment_is_cleared_except_path_home_and_configured_values() {
        // `CARGO_PKG_NAME` is set in the parent by `cargo test` and must not
        // reach the child; `CONFIGURED` comes from the target's own env and
        // must. The server reports both as its tool name.
        assert!(std::env::var_os("CARGO_PKG_NAME").is_some());
        let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"]}}'; read b; printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"%s"}]}}\n' "${CARGO_PKG_NAME:-unset}-${CONFIGURED:-unset}""#;
        let target = StdioTarget {
            env: vec![("CONFIGURED".into(), "yes".into())],
            ..sh(script)
        };
        let capture = capture_stdio(&target, &Limits::default()).unwrap();
        assert_eq!(capture.tools[0]["name"], "unset-yes");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let target = StdioTarget {
            program: "/nonexistent/definitely-not-here".into(),
            args: vec![],
            env: vec![],
            cwd: None,
        };
        assert!(matches!(
            capture_stdio(&target, &Limits::default()),
            Err(InspectError::Spawn(_))
        ));
    }
}
