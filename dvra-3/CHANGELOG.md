# Changelog

## 0.2.0-alpha.2

- Added DVRA-009: acknowledgement-gated SSRF through an attacker-controlled URL.
- Added an internal-only fake metadata service with inert credential markers and
  a redirect endpoint.
- Added `dvra-fetch` with vulnerable redirect-following behavior and a fixed
  exact-origin allowlist, redirect denial, timeout, and response-size ceiling.
- Added egress-dependent threat-model variants, handler/policy tests, Docker
  profile containment, a reproducer, and offline layout invariants.

## 0.2.0-alpha.1

- Added DVRA-008: acknowledgement-gated bundle extraction path traversal with a
  deterministic cross-job overwrite fixture.
- Added `dvra-bundle`, a compact archive-like parser with vulnerable and lexical
  containment implementations.
- Added fixed and vulnerable HTTP extraction routes with contrasting body limits.
- Added handler-level regression tests for IDOR, filesystem gate enforcement,
  and fixed traversal rejection.
- Strengthened the offline validator to check workspace manifests, scenario
  fixtures, route/gate invariants, storage confinement, and container controls.
- Added the offline validator to GitHub Actions.

## 0.1.0

- Initial DVRA MVP with IDOR, command injection, differential-parser panic,
  panic-safety unsoundness, incorrect `Sync`, reachability decoys, and secret
  logging scenarios.
