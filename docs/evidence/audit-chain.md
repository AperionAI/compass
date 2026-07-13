# Audit chain (tamper-evidence)

The `audit_chain_integrity` check verifies a tamper-evident, hash-chained log:
each entry carries a `seq`, a `prev_hash` linking to the previous entry, and an
`entry_hmac` (HMAC-SHA256 over the canonical entry). If any entry is mutated,
reordered, dropped, or duplicated, verification fails.

## Chain format

One JSON object per line (JSONL), or a JSON array:

```json
{"seq":1,"prev_hash":"genesis","payload":{"…"},"entry_hmac":"<hex>"}
{"seq":2,"prev_hash":"<entry_hmac of seq 1>","payload":{"…"},"entry_hmac":"<hex>"}
```

Rules Compass enforces:

- `seq` is a strictly increasing integer with no gaps or duplicates.
- `prev_hash` of seq 1 is the literal `genesis`; every later entry's
  `prev_hash` equals the previous entry's `entry_hmac`.
- `entry_hmac = HMAC_SHA256(key, canonical(entry_without_entry_hmac))`, where
  `canonical` recursively sorts object keys and serialises compactly.

This is byte-compatible with Smartflow's audit chain and with the standalone
`audit-verifier`, so a Smartflow export verifies directly.

## Supplying the HMAC key

```bash
compass verify --chain audit.jsonl --chain-hmac-key file:audit.key
# or: base64:<v> | hex:<v> | env:AUDIT_KEY | a bare value
```

Register it on an assessment so `report` re-verifies it every run:

```bash
compass ingest --chain audit.jsonl --chain-hmac-key file:audit.key
```

Without a key, Compass still checks linkage and sequencing and reports a
**Warn** (structure intact, signatures unverified). A failed HMAC is a **Fail**
and forces a non-zero exit — a tampered audit trail should break the build.

## If you're exporting from Smartflow

Smartflow writes this chain natively. Export the audit collection to JSONL and
pass the issuer HMAC key. The verdicts Compass produces match what Smartflow
enforces at runtime.

## If you don't have a chain yet

`compass record` writes one for you from live traffic — every call it proxies
is sealed into a chain it can later verify. See [record.md](record.md).
