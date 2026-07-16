# DVRA-009 — SSRF and egress-dependent impact

The artifact service can fetch a tenant-supplied URL. Review both HTTP surfaces
and decide whether the finding is merely a dangerous capability or an exploitable
server-side request forgery under each deployment threat model.

## Surfaces

- `POST /v1/fetch` — acknowledgement-gated vulnerable implementation.
- `POST /v1/fixed/fetch` — exact-origin allowlist, redirects disabled, timeout,
  and bounded response body.
- `metadata:8081` — internal-only fake metadata service available in the
  `ssrf-lab` Compose profile. It contains no real credential.

Request body:

```json
{"url":"http://metadata:8081/redirect-to-credentials"}
```

## Questions

1. Is the URL attacker-controlled in the selected threat model?
2. Can the API resolve and connect to internal service names?
3. Does the client follow redirects to a destination that was never validated?
4. Can a large or slow upstream turn the same sink into a resource-exhaustion bug?
5. Does the fixed implementation validate the destination before every network
   hop, or merely validate the initial string?

Run only through the provided Compose profile. The fake metadata service stays
on the internal Docker network; the API is exposed only on localhost for the
reproducer:

```bash
./scripts/labctl run-ssrf
./scripts/labctl reproduce DVRA-009
./scripts/labctl stop-ssrf
```

## Fixed-surface assumption

The fixed implementation treats configured origins, their DNS, and any process
proxy settings as trusted deployment inputs. A later scenario can deliberately
remove that assumption to cover DNS rebinding or proxy-policy bypass.
