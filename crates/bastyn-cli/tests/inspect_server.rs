//! Integration tests for `bastyn inspect-server`, driving the real binary
//! against loopback fake servers.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use assert_cmd::Command;
use serde_json::Value;

fn reply(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Serves `replies` in order, one per connection, then stops. Returns the URL.
fn serve(replies: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    thread::spawn(move || {
        for canned in replies {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = Vec::new();
            let mut chunk = [0_u8; 4096];
            let (head_end, content_length) = loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break (buffer.len(), 0);
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffer[..at]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (at + 4, length);
                }
            };
            while buffer.len() < head_end + content_length {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let _ = stream.write_all(canned.as_bytes());
        }
    });
    url
}

fn tools_reply(tools: &str) -> String {
    reply(
        "200 OK",
        "application/json",
        &format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":{tools}}}}}"#),
    )
}

fn bastyn() -> Command {
    Command::cargo_bin("bastyn").unwrap()
}

fn write_config(dir: &Path, servers: &Value) -> std::path::PathBuf {
    let path = dir.join("mcp.json");
    std::fs::write(
        &path,
        serde_json::json!({ "mcpServers": servers }).to_string(),
    )
    .unwrap();
    path
}

#[test]
fn url_capture_writes_a_sorted_snapshot_to_stdout() {
    let url = serve(vec![tools_reply(r#"[{"name":"b"},{"name":"a"}]"#)]);
    let output = bastyn()
        .args(["inspect-server", "--url", &url])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema"], "bastyn-tools-snapshot/1");
    assert_eq!(json["server"]["name"], "127.0.0.1");
    assert_eq!(json["server"]["transport"], "streamable-http");
    assert_eq!(json["tools"][0]["name"], "a");
    assert_eq!(json["tools"][1]["name"], "b");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("captured 2 tools from 127.0.0.1 (modern)"),
        "{stderr}"
    );
}

#[test]
fn out_writes_the_file_and_leaves_stdout_empty() {
    let url = serve(vec![tools_reply(r#"[{"name":"a"}]"#)]);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("snap.json");
    let output = bastyn()
        .args(["inspect-server", "--url", &url, "--out"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(json["tools"][0]["name"], "a");
}

#[test]
fn two_runs_produce_identical_bytes() {
    let body = r#"[{"name":"b","inputSchema":{"z":1,"a":2}},{"name":"a"}]"#;
    let first = serve(vec![tools_reply(body)]);
    let second = serve(vec![tools_reply(body)]);
    let one = bastyn()
        .args(["inspect-server", "--url", &first])
        .output()
        .unwrap();
    let two = bastyn()
        .args(["inspect-server", "--url", &second])
        .output()
        .unwrap();
    assert_eq!(one.stdout, two.stdout);
}

#[test]
fn a_stdio_entry_without_allow_spawn_is_refused_and_nothing_runs() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let script = format!("touch '{}'", marker.display());
    let config = write_config(
        dir.path(),
        &serde_json::json!({"s": {"command": "sh", "args": ["-c", script]}}),
    );
    let output = bastyn()
        .args(["inspect-server", "--server", "s", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--allow-spawn"), "{stderr}");
    assert!(stderr.contains("sh -c touch"), "{stderr}");
    assert!(!marker.exists(), "the command must not have run");
}

#[cfg(unix)]
#[test]
fn allow_spawn_runs_a_modern_stdio_server() {
    let dir = tempfile::tempdir().unwrap();
    let script = r#"read a; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"]}}'; read b; printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"x"}]}}'"#;
    let config = write_config(
        dir.path(),
        &serde_json::json!({"fake": {"command": "sh", "args": ["-c", script]}}),
    );
    let output = bastyn()
        .args([
            "inspect-server",
            "--server",
            "fake",
            "--allow-spawn",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["server"]["name"], "fake");
    assert_eq!(json["server"]["transport"], "stdio");
    assert_eq!(json["tools"][0]["name"], "x");
}

#[test]
fn a_metadata_address_is_refused_by_name() {
    let output = bastyn()
        .args(["inspect-server", "--url", "http://169.254.169.254/"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("169.254.169.254")
    );
}

#[test]
fn a_missing_server_name_lists_the_available_ones() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        dir.path(),
        &serde_json::json!({"alpha": {"command": "x"}, "beta": {"command": "y"}}),
    );
    let output = bastyn()
        .args(["inspect-server", "--server", "gamma", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("available: alpha, beta"), "{stderr}");
}

#[test]
fn url_and_config_together_are_rejected_by_the_parser() {
    let output = bastyn()
        .args([
            "inspect-server",
            "--url",
            "http://127.0.0.1:1/",
            "--config",
            "x.json",
            "--server",
            "s",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn server_and_allow_spawn_require_config() {
    for extra in [["--server", "s"], ["--allow-spawn", ""]] {
        let mut command = bastyn();
        command.args(["inspect-server", "--url", "http://127.0.0.1:1/"]);
        command.arg(extra[0]);
        if !extra[1].is_empty() {
            command.arg(extra[1]);
        }
        assert_eq!(
            command.output().unwrap().status.code(),
            Some(2),
            "{extra:?}"
        );
    }
}

#[test]
fn escape_bytes_from_the_server_never_reach_the_terminal() {
    let body = r#"[{"name":"a","description":"\u001b[31mred"}]"#;
    let url = serve(vec![tools_reply(body)]);
    let output = bastyn()
        .args(["inspect-server", "--url", &url])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !output.stderr.contains(&0x1b),
        "stderr holds a raw escape byte"
    );
    // The snapshot is JSON, which carries the escape as `\u001b`, not a raw byte.
    assert!(!output.stdout.contains(&0x1b));
}

#[test]
fn a_server_error_message_is_escaped_before_it_is_printed() {
    let body =
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"bad \u001b[31m thing"}}"#;
    let url = serve(vec![reply("200 OK", "application/json", body)]);
    let output = bastyn()
        .args(["inspect-server", "--url", &url])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.contains(&0x1b));
}
