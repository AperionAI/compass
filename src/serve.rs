//! `compass serve` — a tiny, dependency-free local dashboard server.
//!
//! Deliberately built on `std::net` only (no tokio, no hyper): binds to
//! localhost, serves the dashboard template at `/`, and recomputes the
//! scorecard live at `/api/scorecard` so the dashboard's "Re-scan" button
//! reflects edits to the assessment file or freshly exported logs without a
//! restart. Handles one connection at a time — this is a single-user local
//! tool, not a public server.

use crate::report::html;
use crate::scoring::Scorecard;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

/// Run the server until interrupted. `recompute` is called on every
/// `/api/scorecard` request so the view always reflects the current files.
pub fn run<F>(port: u16, recompute: F) -> Result<()>
where
    F: Fn() -> Result<Scorecard>,
{
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;
    let page = html::template_for_serve();

    println!("Aperion Compass dashboard serving at http://{addr}");
    println!("Open it in a browser; press Ctrl-C to stop.");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (method, path) = match read_request_line(&mut stream) {
            Some(v) => v,
            None => continue,
        };

        let response = match (method.as_str(), path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => {
                http_ok("text/html; charset=utf-8", page.as_bytes())
            }
            ("GET", "/api/scorecard") => match recompute() {
                Ok(card) => match serde_json::to_vec(&card) {
                    Ok(body) => http_ok("application/json", &body),
                    Err(e) => http_500(&e.to_string()),
                },
                Err(e) => http_500(&e.to_string()),
            },
            ("GET", "/healthz") => http_ok("text/plain", b"ok"),
            _ => http_404(),
        };

        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }
    Ok(())
}

/// Read the request line and drain headers/body enough to be polite.
fn read_request_line(stream: &mut std::net::TcpStream) -> Option<(String, String)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    // Drain remaining headers (until blank line) so the socket is in a sane
    // state; we ignore the body.
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            break;
        }
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length.min(1 << 20)];
        let _ = reader.read_exact(&mut body);
    }
    Some((method, path))
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

fn http_ok(content_type: &str, body: &[u8]) -> Vec<u8> {
    http_response("200 OK", content_type, body)
}

fn http_404() -> Vec<u8> {
    http_response("404 Not Found", "text/plain", b"not found")
}

fn http_500(msg: &str) -> Vec<u8> {
    let body = serde_json::json!({"error": "recompute_failed", "message": msg}).to_string();
    http_response(
        "500 Internal Server Error",
        "application/json",
        body.as_bytes(),
    )
}
