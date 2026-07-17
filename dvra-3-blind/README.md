# DVRA-3-Blind

A **no-hints evaluation variant** of [`dvra-3`](../dvra-3): the same deliberately
vulnerable Axum artifact-processing service, with all *benchmark
self-documentation* removed so a security tool must find the bugs from
**behavior**, not from labels.

> Deliberately vulnerable. Run only in a disposable environment; do not attach
> real secrets, mount home directories, or expose the Docker socket.

## Why

Most vuln benchmarks are self-documenting: `*_vulnerable`/`*_fixed` siblings,
`/v1/fixed/*` comparison routes, `#[cfg(test)]` modules shipping working exploits,
`// DVRA-NNN:` comments, and a published oracle. That structure inflates a
scanner's *apparent* recall. DVRA-3-Blind removes those crutches so measured
recall reflects *behavioral* detection.

## What changed (behavior preserved)

- Giveaway names -> neutral production names (`parse_vulnerable`->`parse_records`,
  `get_unscoped`->`find_artifact`, `RacyCounter`->`SharedCounter`,
  `PanicCell`->`SlotCell`, `unreachable_legacy_export`->`legacy_export`, ...).
- Paired `*_fixed`/`*_reference` siblings + `/v1/fixed/*` routes/handlers removed
  -> a single production path per feature (no safe sibling to diff, no
  control-flow-divergence tell).
- Exploit-demonstrating `#[cfg(test)]` modules, `// DVRA-NNN` comments, and
  `instructor-oracle/`/`scenarios/`/`fuzz/` excluded; lab-mode gate string
  `"vulnerable"` -> `"enabled"`.

Every planted defect is still present and reachable. `cargo build --workspace`
compiles (apps included).

## Scoring

Defects map 1:1 to `dvra-3`'s gold (`../dvra-3/instructor-oracle/scenarios.yaml`).
The neutral -> original mapping is the `RENAME` table in
[`../tools/make-blind/make_blind.py`](../tools/make-blind/make_blind.py). Evaluate
blind (source only), then score against the oracle.

## Reproducing

Generated, not hand-forked, so it tracks upstream:

```sh
python3 tools/make-blind/make_blind.py dvra-3 dvra-3-blind
diff -qr dvra-3-blind /tmp/regen   # after regenerating to /tmp/regen: empty
```

## Reference result

The rust-in-peace static pipeline (`/vuln-scan` + `/triage`) recalled **9/9** gold
scenarios from this blind tree purely from behavior (plus one extra
unbounded-response-body candidate in `fetch_url`), matching its recall on the
labeled tree — on these textbook classes the naming/sibling crutches were not
load-bearing for recall.
