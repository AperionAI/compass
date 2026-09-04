//! `compass record` — capture governance evidence from live traffic.
//!
//! The cold-start problem: a team that wants to assess itself often has no
//! governance-grade logs at all. `record` fixes that without asking them to
//! instrument anything. It runs a localhost reverse proxy that speaks the
//! OpenAI-compatible HTTP API. Point your SDK's `base_url` at it, and every
//! request is forwarded to your real upstream (a local model server, a
//! gateway, or a hosted HTTPS API) while Compass writes one tamper-evident,
//! hash-chained JSONL record per call. That single file doubles as the audit
//! chain *and* the request log, so a later `compass report` can run the
//! chain-integrity, action-risk, and logging-completeness checks off it.
//!
//! Built on `std::net` — no async runtime, no HTTP client crate. HTTPS
//! upstreams use rustls (Mozilla webpki roots). Streaming (SSE) responses are
//! teed to the client as chunks arrive so SDKs keep streaming; Compass
//! buffers a copy to seal into the chain. It never talks to Aperion; the
//! only network peer is the upstream you name.

use crate::evidence::chain::{canonical_for_hmac, hmac_hex};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Map, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// Configuration for a recording session.
pub struct RecordConfig {
    pub port: u16,
    /// Upstream base URL, e.g. `http://localhost:4000`.
    pub upstream: String,
    /// Output JSONL path (chain + log in one file).
    pub out: String,
    /// HMAC key spec (`file:` | `base64:` | `hex:` | `env:` | bare). When
    /// absent, a fresh key is generated and written next to `out` as `<out>.key`.
    pub hmac_key: Option<String>,
}

struct Upstream {
    host: String,
    port: u16,
    /// Host header value (host[:port] as the user wrote it).
    host_header: String,
    tls: bool,
}

fn parse_upstream(url: &str) -> Result<Upstream> {
    let (rest, tls, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (r, true, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, false, 80u16)
    } else if !url.contains("://") {
        (url, false, 80u16)
    } else {
        return Err(anyhow!(
            "unsupported upstream scheme in '{url}' (use http:// or https://)"
        ));
    };

    // Strip any path; we only need host:port. Keep host_header as authority.
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(anyhow!("could not parse host from upstream '{url}'"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("bad port in upstream '{url}'"))?,
        ),
        _ => (authority.to_string(), default_port),
    };
    Ok(Upstream {
        host,
        port,
        host_header: authority.to_string(),
        tls,
    })
}

fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

enum UpStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for UpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            UpStream::Plain(s) => s.read(buf),
            UpStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for UpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            UpStream::Plain(s) => s.write(buf),
            UpStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpStream::Plain(s) => s.flush(),
            UpStream::Tls(s) => s.flush(),
        }
    }
}

fn connect_upstream(up: &Upstream) -> Result<UpStream> {
    let addr = format!("{}:{}", up.host, up.port);
    let sock = TcpStream::connect(&addr).with_context(|| format!("connecting upstream {addr}"))?;
    if !up.tls {
        return Ok(UpStream::Plain(sock));
    }
    let name = ServerName::try_from(up.host.clone())
        .map_err(|_| anyhow!("invalid TLS hostname '{}'", up.host))?;
    let conn = ClientConnection::new(tls_config(), name).context("TLS client setup")?;
    Ok(UpStream::Tls(Box::new(StreamOwned::new(conn, sock))))
}

fn provider_for(host: &str) -> &'static str {
    let h = host.to_ascii_lowercase();
    if h.contains("openai") {
        "openai"
    } else if h.contains("anthropic") {
        "anthropic"
    } else if h.contains("azure") {
        "azure"
    } else if h.contains("bedrock") || h.contains("amazonaws") {
        "bedrock"
    } else {
        "recorded"
    }
}

// ── Hash-chained writer (byte-compatible with evidence::chain::verify) ───────

/// Appends entries to a tamper-evident JSONL chain. Each entry is
/// `{seq, prev_hash, …payload, entry_hmac}` where `entry_hmac =
/// HMAC-SHA256(key, canonical(entry without entry_hmac))` and `prev_hash`
/// links to the previous entry's hmac (`genesis` for seq 1).
pub struct ChainWriter {
    key: Vec<u8>,
    seq: u64,
    prev: String,
}

impl ChainWriter {
    pub fn new(key: Vec<u8>) -> Self {
        ChainWriter {
            key,
            seq: 0,
            prev: "genesis".to_string(),
        }
    }

    /// Seed sequence + prev-hash from an existing chain file so a restart
    /// continues the same chain instead of forking it.
    pub fn resume_from(&mut self, existing: &str) {
        let mut max_seq = 0u64;
        let mut last_hmac: Option<String> = None;
        for line in existing.lines() {
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(s) {
                if let Some(seq) = v.get("seq").and_then(|x| x.as_u64()) {
                    if seq >= max_seq {
                        max_seq = seq;
                        last_hmac = v
                            .get("entry_hmac")
                            .and_then(|x| x.as_str())
                            .map(|x| x.to_string());
                    }
                }
            }
        }
        if max_seq > 0 {
            self.seq = max_seq;
            if let Some(h) = last_hmac {
                self.prev = h;
            }
        }
    }

    /// Build (but do not write) the next sealed entry from a payload map.
    pub fn seal(&mut self, payload: Map<String, Value>) -> Value {
        self.seq += 1;
        let mut obj = Map::new();
        obj.insert("seq".to_string(), Value::from(self.seq));
        obj.insert("prev_hash".to_string(), Value::from(self.prev.clone()));
        for (k, v) in payload {
            if k == "seq" || k == "prev_hash" || k == "entry_hmac" {
                continue; // payload can't clobber chain fields
            }
            obj.insert(k, v);
        }
        let entry = Value::Object(obj.clone());
        let hmac = hmac_hex(&self.key, &canonical_for_hmac(&entry));
        obj.insert("entry_hmac".to_string(), Value::from(hmac.clone()));
        self.prev = hmac;
        Value::Object(obj)
    }
}

// ── HTTP plumbing (std only) ─────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn recv_request(stream: &TcpStream) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

/// A parsed upstream response, already de-chunked.
struct HttpResponse {
    status_code: u16,
    body: Vec<u8>,
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
            | "transfer-encoding"
            | "content-length"
            | "accept-encoding"
    )
}

/// Write one HTTP/1.1 chunk to the client and flush so SSE arrives live.
fn write_http_chunk(client: &mut TcpStream, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    write!(client, "{:x}\r\n", data.len())?;
    client.write_all(data)?;
    client.write_all(b"\r\n")?;
    client.flush()?;
    Ok(())
}

fn end_http_chunks(client: &mut TcpStream) -> Result<()> {
    client.write_all(b"0\r\n\r\n")?;
    client.flush()?;
    Ok(())
}

fn send_client_headers(
    client: &mut TcpStream,
    status_line: &str,
    headers: &[(String, String)],
) -> Result<()> {
    let mut out = format!("{status_line}\r\n");
    for (k, v) in headers {
        if hop_by_hop(k) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    client.write_all(out.as_bytes())?;
    client.flush()?;
    Ok(())
}

fn tee_body<R: BufRead>(
    reader: &mut R,
    client: &mut TcpStream,
    chunked: bool,
    content_length: Option<usize>,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line)? == 0 {
                break;
            }
            let size_hex = size_line.trim().split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);
            if size == 0 {
                let mut trailing = String::new();
                let _ = reader.read_line(&mut trailing);
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
            write_http_chunk(client, &chunk)?;
            body.extend_from_slice(&chunk);
        }
        end_http_chunks(client)?;
        return Ok(body);
    }
    if let Some(n) = content_length {
        let mut remaining = n;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            let nread = reader.read(&mut buf[..want])?;
            if nread == 0 {
                break;
            }
            write_http_chunk(client, &buf[..nread])?;
            body.extend_from_slice(&buf[..nread]);
            remaining -= nread;
        }
        end_http_chunks(client)?;
        return Ok(body);
    }
    let mut buf = [0u8; 8192];
    loop {
        let nread = reader.read(&mut buf)?;
        if nread == 0 {
            break;
        }
        write_http_chunk(client, &buf[..nread])?;
        body.extend_from_slice(&buf[..nread]);
    }
    end_http_chunks(client)?;
    Ok(body)
}

/// Forward one request to the upstream, tee the response to the client as it
/// arrives, and return the de-chunked body for recording.
fn forward_and_tee(
    up: &Upstream,
    req: &HttpRequest,
    client: &mut TcpStream,
    headers_sent: &mut bool,
) -> Result<HttpResponse> {
    let mut sock = connect_upstream(up)?;

    let mut head = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    head.push_str(&format!("Host: {}\r\n", up.host_header));
    for (k, v) in &req.headers {
        if hop_by_hop(k) {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    head.push_str("Accept-Encoding: identity\r\n");
    head.push_str("Connection: close\r\n\r\n");

    sock.write_all(head.as_bytes())?;
    sock.write_all(&req.body)?;
    sock.flush()?;

    let mut reader = BufReader::new(sock);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((key, val));
        }
    }

    let status_line = status_line.trim_end().to_string();
    send_client_headers(client, &status_line, &headers)?;
    *headers_sent = true;
    let body = tee_body(&mut reader, client, chunked, content_length)?;

    Ok(HttpResponse { status_code, body })
}

// ── Record extraction ────────────────────────────────────────────────────────

/// Build the chain payload for one request/response exchange. Pure so it can be
/// unit-tested without sockets.
pub fn payload_for_exchange(
    provider: &str,
    req_body: &[u8],
    resp_body: &[u8],
    status_code: u16,
    latency_ms: u128,
) -> Map<String, Value> {
    let req: Value = serde_json::from_slice(req_body).unwrap_or(Value::Null);
    let resp = parse_response_body(resp_body);

    let mut o = Map::new();
    o.insert("type".into(), Value::from("llm_call"));
    o.insert(
        "timestamp".into(),
        Value::from(chrono::Utc::now().to_rfc3339()),
    );
    o.insert("provider".into(), Value::from(provider));
    o.insert("status_code".into(), Value::from(status_code));
    o.insert("latency_ms".into(), Value::from(latency_ms as u64));

    if let Some(id) = resp.get("id").and_then(|v| v.as_str()) {
        o.insert("request_id".into(), Value::from(id));
    }
    // Model: prefer the response's echoed model, else the request's.
    let model = resp
        .get("model")
        .and_then(|v| v.as_str())
        .or_else(|| req.get("model").and_then(|v| v.as_str()));
    if let Some(m) = model {
        o.insert("model".into(), Value::from(m));
    }
    if let Some(u) = req.get("user").and_then(|v| v.as_str()) {
        o.insert("user_id".into(), Value::from(u));
    }

    let tools = tool_names(&resp);
    if let Some(first) = tools.first() {
        o.insert("tool_name".into(), Value::from(first.clone()));
    }
    if !tools.is_empty() {
        o.insert(
            "tool_names".into(),
            Value::Array(tools.into_iter().map(Value::from).collect()),
        );
    }
    o
}

fn tool_names(resp: &Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(choices) = resp.get("choices").and_then(|c| c.as_array()) {
        for choice in choices {
            if let Some(calls) = choice
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.as_array())
            {
                for call in calls {
                    if let Some(name) = call
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    names
}

/// JSON body, or an OpenAI-style SSE stream reconstructed enough to extract
/// id / model / tool names.
fn parse_response_body(body: &[u8]) -> Value {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if !v.is_null() {
            return v;
        }
    }
    parse_sse(body)
}

fn parse_sse(body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    let mut id: Option<String> = None;
    let mut model: Option<String> = None;
    let mut tools: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("data:") else {
            continue;
        };
        let data = rest.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        if id.is_none() {
            id = v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string());
        }
        if model.is_none() {
            model = v
                .get("model")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        collect_tool_names(&v, &mut tools);
    }
    let mut o = Map::new();
    if let Some(id) = id {
        o.insert("id".into(), Value::from(id));
    }
    if let Some(model) = model {
        o.insert("model".into(), Value::from(model));
    }
    if !tools.is_empty() {
        let calls: Vec<Value> = tools
            .into_iter()
            .map(|n| serde_json::json!({"function": {"name": n}}))
            .collect();
        o.insert(
            "choices".into(),
            serde_json::json!([{"message": {"tool_calls": calls}}]),
        );
    }
    Value::Object(o)
}

fn collect_tool_names(v: &Value, tools: &mut Vec<String>) {
    let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else {
        return;
    };
    for choice in choices {
        for key in ["message", "delta"] {
            let Some(calls) = choice
                .get(key)
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.as_array())
            else {
                continue;
            };
            for call in calls {
                if let Some(name) = call
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if !name.is_empty() && !tools.iter().any(|t| t == name) {
                        tools.push(name.to_string());
                    }
                }
            }
        }
    }
}

// ── Key handling ──────────────────────────────────────────────────────────────

fn random_key() -> Vec<u8> {
    // Prefer OS entropy; fall back to a time+pid seed on platforms without
    // /dev/urandom. The key is stored locally next to the log — it exists to
    // make accidental mutation detectable and to demonstrate the mechanism,
    // not to defend a chain from an attacker who already owns the filesystem.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            return buf.to_vec();
        }
    }
    let seed = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    // Stretch the weak seed through the HMAC we already depend on.
    hmac_hex(seed.as_bytes(), "compass-record-key")
        .into_bytes()
        .into_iter()
        .take(32)
        .collect()
}

fn resolve_key(cfg: &RecordConfig) -> Result<(Vec<u8>, Option<String>)> {
    match &cfg.hmac_key {
        Some(spec) => {
            let key = crate::evidence::chain::load_key_spec(spec)
                .ok_or_else(|| anyhow!("could not load HMAC key from '{spec}'"))?;
            Ok((key, None))
        }
        None => {
            let key = random_key();
            let b64 = base64::engine::general_purpose::STANDARD.encode(&key);
            let key_path = format!("{}.key", cfg.out);
            std::fs::write(&key_path, &b64)
                .with_context(|| format!("writing key file {key_path}"))?;
            Ok((key, Some(key_path)))
        }
    }
}

// ── Server loop ───────────────────────────────────────────────────────────────

/// Run the recording proxy until interrupted (Ctrl-C).
pub fn run(cfg: RecordConfig) -> Result<()> {
    let up = parse_upstream(&cfg.upstream)?;
    let provider = provider_for(&up.host);

    let (key, generated_key_path) = resolve_key(&cfg)?;
    let mut chain = ChainWriter::new(key);
    if let Ok(existing) = std::fs::read_to_string(&cfg.out) {
        chain.resume_from(&existing);
    }
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.out)
        .with_context(|| format!("opening output {}", cfg.out))?;

    let addr = format!("127.0.0.1:{}", cfg.port);
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;

    println!("Aperion Compass recorder");
    println!("  listening   http://{addr}");
    println!("  forwarding  {} (provider: {provider})", cfg.upstream);
    println!("  writing     {} (hash-chained JSONL)", cfg.out);
    if let Some(kp) = &generated_key_path {
        let spec = format!("file:{kp}");
        println!("  hmac key    {kp}  (generated)");
        println!(
            "\nPoint your OpenAI-compatible client's base_url at http://{addr}.\n\
             Later, verify + assess with:\n  \
             compass verify --chain {} --chain-hmac-key {spec}\n  \
             compass ingest --chain {} --chain-hmac-key {spec} --generic {}\n",
            cfg.out, cfg.out, cfg.out
        );
    }
    println!("Press Ctrl-C to stop.\n");

    for stream in listener.incoming() {
        let mut client = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut headers_sent = false;
        if let Err(e) = handle_connection(
            &mut client,
            &up,
            provider,
            &mut chain,
            &mut out,
            &mut headers_sent,
        ) {
            eprintln!("  ! exchange error: {e:#}");
            if !headers_sent {
                let _ = client.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    }
    Ok(())
}

fn handle_connection(
    client: &mut TcpStream,
    up: &Upstream,
    provider: &str,
    chain: &mut ChainWriter,
    out: &mut std::fs::File,
    headers_sent: &mut bool,
) -> Result<()> {
    let req = recv_request(client)?;

    // Health check for convenience.
    if req.method == "GET" && req.path == "/healthz" {
        client.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )?;
        *headers_sent = true;
        return Ok(());
    }

    let started = Instant::now();
    let resp = forward_and_tee(up, &req, client, headers_sent)?;
    let latency_ms = started.elapsed().as_millis();

    // Only record calls that look like model invocations (have a JSON body).
    if req.method == "POST" && !req.body.is_empty() {
        let payload = payload_for_exchange(
            provider,
            &req.body,
            &resp.body,
            resp.status_code,
            latency_ms,
        );
        let entry = chain.seal(payload);
        writeln!(out, "{}", serde_json::to_string(&entry)?)?;
        out.flush()?;
        let tool = entry
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        println!(
            "  · seq {} {} {} tool={}",
            entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            resp.status_code,
            entry.get("model").and_then(|v| v.as_str()).unwrap_or("?"),
            tool
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{chain, CheckStatus};

    #[test]
    fn parse_http_and_https() {
        let u = parse_upstream("http://localhost:4000/v1").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 4000);
        assert_eq!(u.host_header, "localhost:4000");
        assert!(!u.tls);

        let s = parse_upstream("https://api.openai.com").unwrap();
        assert_eq!(s.host, "api.openai.com");
        assert_eq!(s.port, 443);
        assert!(s.tls);

        let s2 = parse_upstream("https://api.openai.com:8443/v1").unwrap();
        assert_eq!(s2.port, 8443);

        let d = parse_upstream("http://example.com").unwrap();
        assert_eq!(d.port, 80);
        assert!(parse_upstream("ftp://example.com").is_err());
    }

    #[test]
    fn chain_writer_produces_verifiable_chain() {
        let key = b"compass-record-test-key-32-bytes!".to_vec();
        let mut w = ChainWriter::new(key.clone());
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..3 {
            let mut p = Map::new();
            p.insert("tool_name".into(), Value::from(format!("op_{i}")));
            let e = w.seal(p);
            writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
        }
        f.flush().unwrap();
        let spec = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(&key)
        );
        let o = chain::verify(f.path().to_str().unwrap(), Some(&spec));
        assert_eq!(o.status, CheckStatus::Pass, "summary={}", o.summary);
    }

    #[test]
    fn resume_continues_sequence() {
        let key = b"compass-record-test-key-32-bytes!".to_vec();
        let mut w = ChainWriter::new(key.clone());
        let e1 = w.seal(Map::new());
        let line = serde_json::to_string(&e1).unwrap();

        let mut w2 = ChainWriter::new(key);
        w2.resume_from(&line);
        let e2 = w2.seal(Map::new());
        assert_eq!(e2.get("seq").unwrap().as_u64().unwrap(), 2);
        assert_eq!(
            e2.get("prev_hash").unwrap().as_str().unwrap(),
            e1.get("entry_hmac").unwrap().as_str().unwrap()
        );
    }

    #[test]
    fn payload_extracts_model_and_tools() {
        let req = br#"{"model":"gpt-4o","user":"alice","messages":[]}"#;
        let resp = br#"{"id":"cmpl-9","model":"gpt-4o-2024",
          "choices":[{"message":{"tool_calls":[{"function":{"name":"delete_row"}}]}}]}"#;
        let p = payload_for_exchange("openai", req, resp, 200, 42);
        assert_eq!(p.get("request_id").unwrap(), "cmpl-9");
        assert_eq!(p.get("model").unwrap(), "gpt-4o-2024");
        assert_eq!(p.get("user_id").unwrap(), "alice");
        assert_eq!(p.get("tool_name").unwrap(), "delete_row");
    }

    #[test]
    fn payload_extracts_model_and_tools_from_sse() {
        let req = br#"{"model":"gpt-4o","stream":true,"messages":[]}"#;
        let resp =
            b"data: {\"id\":\"cmpl-sse\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{}}]}\n\n\
data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"send_wire\"}}]}}]}\n\n\
data: [DONE]\n\n";
        let p = payload_for_exchange("openai", req, resp, 200, 12);
        assert_eq!(p.get("request_id").unwrap(), "cmpl-sse");
        assert_eq!(p.get("model").unwrap(), "gpt-4o");
        assert_eq!(p.get("tool_name").unwrap(), "send_wire");
    }
}
