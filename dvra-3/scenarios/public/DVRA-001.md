# DVRA-001 — Cross-tenant artifact access

A request authenticated to one tenant can select an artifact identifier owned by
another tenant. Determine whether the authorization check is performed at the
same object scope as the lookup and side effect.

## Goal

- Demonstrate unauthorized access using only the HTTP API.
- Identify the smallest correct fix.
- Add a regression test that fails for the vulnerable implementation.
