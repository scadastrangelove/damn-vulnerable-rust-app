# HTTP surfaces

The vulnerable and fixed comparison surfaces are intentionally present at the
same time. A future student release may hide the fixed routes and the oracle.

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/v1/artifacts/{id}` | Unscoped artifact lookup |
| GET | `/v1/fixed/artifacts/{id}` | Tenant-scoped lookup |
| POST | `/v1/parse` | Fast parser with stale-offset bug and no body limit |
| POST | `/v1/fixed/parse` | Reference parser with a 64 KiB body limit |
| POST | `/v1/bundles/{job_id}` | Bundle extraction with traversal bug, acknowledgement-gated |
| POST | `/v1/fixed/bundles/{job_id}` | Lexically validates relative bundle paths and limits the body to 1 MiB |
| POST | `/v1/post-process` | Shell-based processing, acknowledgement-gated |
| POST | `/v1/fixed/post-process` | Direct executable with separate arguments |
| POST | `/v1/fetch` | Attacker-controlled URL fetch, SSRF-lab-gated |
| POST | `/v1/fixed/fetch` | Exact-origin allowlist, no redirects, bounded response |
| GET | `/v1/debug/config` | Emits the full configuration to logs when enabled |

Artifact routes require an `x-tenant` header. The post-processing route expects:

```json
{"artifact_name":"report.zip"}
```

Parser routes consume the raw request body as the compact DVRA binary format.

## DVRA bundle format

The compact training format starts with `DVB1`, followed by a one-byte entry
count. Each entry contains a one-byte UTF-8 path length, the path bytes, a
big-endian two-byte content length, and the content bytes.

The fixed route rejects absolute paths and every path component except ordinary
relative segments. Its containment argument assumes the extraction tree is
created by the trusted runtime and does not already contain attacker-controlled
symlinks.


## URL fetch body

Both fetch routes accept:

```json
{"url":"http://metadata:8081/redirect-to-credentials"}
```

The fake metadata hostname exists only inside the `ssrf-lab` Compose profile.
The vulnerable client follows the redirect and buffers the complete body. The
fixed client checks the exact origin against configuration before connecting,
disables redirects, applies a timeout, and enforces `max_response_bytes`.
