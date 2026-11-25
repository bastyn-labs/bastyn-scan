//! The `OpenClaw` reporter against a real local listener: the request it sends
//! and how it classifies each answer.

#![expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bastyn_core::Severity;
use bastyn_core::watch::{Alert, DeliverOutcome, OpenClawReporter, ReportUrl, Reporter};

const TOKEN: &str = "tok-123.ABC_xyz";

struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break;
            }
        }
    }
    let end = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&data[..end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap().to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Captured {
        request_line,
        headers,
        body: data[end + 4..].to_vec(),
    }
}

/// Serves one canned response; returns the URL and the captured request.
fn serve_once(
    status_line: &'static str,
    extra: &'static str,
) -> (String, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hooks/agent", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let captured = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = tx.send(captured);
        }
    });
    (url, rx)
}

fn alert() -> Alert {
    Alert {
        key: "0123456789abcdef".repeat(4),
        rule_id: "BAS-SKILL-013".into(),
        severity: Severity::High,
        title: "Tells the agent to delete everything".into(),
        path: "skills/reset/SKILL.md".into(),
        line: 9,
        snippet: "SNIPPET-MARKER run rm -rf ~".into(),
    }
}

fn reporter(url: &str, agent: Option<&str>) -> OpenClawReporter {
    let url = ReportUrl::parse(url).unwrap();
    OpenClawReporter::new(&url, TOKEN.to_owned(), agent.map(str::to_owned)).unwrap()
}

#[test]
fn a_200_is_delivered_and_the_request_has_the_expected_shape() {
    let (url, rx) = serve_once("200 OK", "");
    let outcome = reporter(&url, Some("main")).deliver(&alert());
    assert_eq!(outcome, DeliverOutcome::Delivered);

    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(got.request_line, "POST /hooks/agent HTTP/1.1");
    assert_eq!(
        got.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(got.header("idempotency-key"), Some(alert().key.as_str()));
    assert_eq!(got.header("content-type"), Some("application/json"));

    let body: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(body["name"], "Bastyn");
    assert_eq!(body["wakeMode"], "now");
    assert_eq!(body["agentId"], "main");
    let message = body["message"].as_str().unwrap();
    assert!(message.starts_with(
        "Bastyn watchdog alert: BAS-SKILL-013 (high) in skills/reset/SKILL.md:9 - Tells the agent to delete everything."
    ));
    assert!(message.contains("do not open the file"));
    let raw = String::from_utf8(got.body).unwrap();
    assert!(
        !raw.contains("SNIPPET-MARKER") && !raw.contains("rm -rf"),
        "{raw}"
    );
    assert!(!raw.contains(TOKEN));
}

#[test]
fn agent_id_is_omitted_when_not_set() {
    let (url, rx) = serve_once("200 OK", "");
    assert_eq!(
        reporter(&url, None).deliver(&alert()),
        DeliverOutcome::Delivered
    );
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let body: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
    assert!(body.get("agentId").is_none());
}

#[test]
fn a_503_is_a_retry() {
    let (url, _rx) = serve_once("503 Service Unavailable", "");
    assert!(matches!(
        reporter(&url, None).deliver(&alert()),
        DeliverOutcome::Retry { after: None, .. }
    ));
}

#[test]
fn a_429_honours_retry_after() {
    let (url, _rx) = serve_once("429 Too Many Requests", "Retry-After: 17\r\n");
    assert!(matches!(
        reporter(&url, None).deliver(&alert()),
        DeliverOutcome::Retry { after: Some(d), .. } if d == Duration::from_secs(17)
    ));
}

#[test]
fn a_401_is_fatal_and_the_reason_has_no_secrets() {
    let (url, _rx) = serve_once("401 Unauthorized", "");
    let outcome = reporter(&url, None).deliver(&alert());
    let reason = match outcome {
        DeliverOutcome::Fatal { reason } => reason,
        other => format!("not fatal: {other:?}"),
    };
    assert!(!reason.starts_with("not fatal"), "{reason}");
    assert!(reason.contains("401"));
    assert!(!reason.contains(TOKEN) && !reason.contains("127.0.0.1"));
}

#[test]
fn a_redirect_is_fatal_and_not_followed() {
    let (url, _rx) = serve_once("302 Found", "Location: http://127.0.0.1:1/elsewhere\r\n");
    assert!(matches!(
        reporter(&url, None).deliver(&alert()),
        DeliverOutcome::Fatal { .. }
    ));
}

#[test]
fn a_closed_port_is_a_retry() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}/hooks/agent");
    assert!(matches!(
        reporter(&url, None).deliver(&alert()),
        DeliverOutcome::Retry { .. }
    ));
}
