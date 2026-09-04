# Recording live traffic (`compass record`)

No logs to export? Capture them as you go. `compass record` runs a localhost
reverse proxy that speaks the OpenAI-compatible HTTP API. Point your app's
`base_url` at it, and every call is forwarded to your real model endpoint while
Compass writes one tamper-evident, hash-chained record per call. Run it for a
week or two, then assess against real traffic.

## Start it

```bash
# Local gateway / model server
compass record --upstream http://localhost:4000 --port 8788 --out compass-record.jsonl

# Hosted API (TLS is terminated by Compass)
compass record --upstream https://api.openai.com --port 8788 --out compass-record.jsonl
```

- `--upstream` — where to forward (`http://` or `https://`)
- `--port` — where your app connects (default 8788)
- `--out` — the JSONL file it writes (default `compass-record.jsonl`)
- `--hmac-key` — optional; when omitted, a key is generated and written to
  `<out>.key`

Point your client at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8788/v1", api_key="…")
```

Your API key and headers pass straight through to the upstream. Compass reads
the request and response to record the model, user, and tool calls — it does
not alter them. Streaming (`stream: true`) is passed through as chunks arrive;
Compass still seals a copy into the chain.

## What it writes

Each proxied call appends a sealed entry:

```json
{"seq":1,"prev_hash":"genesis","type":"llm_call","timestamp":"…","provider":"openai",
 "status_code":200,"model":"gpt-4o","request_id":"chatcmpl-…","user_id":"u-42",
 "tool_name":"send_wire_transfer","tool_names":["send_wire_transfer"],"entry_hmac":"<hex>"}
```

That one file is both the audit chain *and* the request log, so it powers three
checks at once:

```bash
compass verify --chain compass-record.jsonl --chain-hmac-key file:compass-record.jsonl.key

compass ingest \
  --chain   compass-record.jsonl --chain-hmac-key file:compass-record.jsonl.key \
  --generic compass-record.jsonl
compass report
```

Restarting the recorder against the same `--out` continues the chain rather
than forking it.

## Supported upstreams

Any OpenAI-compatible endpoint:

- Hosted: OpenAI, Azure OpenAI, Anthropic-compatible gateways
- Local model servers: Ollama (`:11434/v1`), vLLM, LM Studio, LocalAI
- Gateways: LiteLLM (`:4000`), your own proxy

HTTPS uses rustls with Mozilla's webpki roots. If a corporate proxy intercepts
TLS with a custom CA that isn't in that set, put LiteLLM (or similar) in
front and point Compass at the local http port.

## Privacy

`compass record` talks to exactly two things: the client on localhost and the
`--upstream` you name. It never contacts Aperion. The chain and key are written
locally. Request/response bodies are parsed only to extract the fields above;
the full bodies are not stored.
