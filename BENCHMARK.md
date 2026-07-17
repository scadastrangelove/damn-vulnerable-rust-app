# Benchmark oracle

DVRA is published as a benchmark, not only as a challenge repository. The
planted defects, decoys, reachability labels, threat-model notes, and expected
tool signals are intentionally available in the repository.

Gold-label locations:

- `dvra-1/instructor-oracle/MANIFEST.toml` — machine-readable finding map.
- `dvra-1/instructor-oracle/ANSWER_KEY.md` — reviewer-oriented answer key.
- `dvra-2/instructor-oracle/scenarios.yaml` — scenario truth table.
- `dvra-3/instructor-oracle/scenarios.yaml` — scenario truth table.

The learner-facing scenario files remain separate from the oracle files so tools
can be evaluated in two modes:

1. **Blind/challenge mode:** run a tool or reviewer against source plus public
   scenario prompts only.
2. **Benchmark mode:** compare reported findings against the oracle files.

For classroom challenge use, distribute a branch or archive that omits
`instructor-oracle/`. For benchmark publication, keep the oracles visible so
results can be reproduced and scored.

## Blind variant

`dvra-3-blind/` is a stronger form of challenge mode: beyond omitting the oracle,
it also removes the *in-source* self-documentation — the `*_vulnerable`/`*_fixed`
naming, paired comparison routes, exploit-demonstrating `#[cfg(test)]` modules,
and `// DVRA-NNN` comments — so a tool must find the bugs from behavior alone. It
is generated from `dvra-3` by `tools/make-blind/make_blind.py` (reproducible:
`diff -qr` against a fresh regeneration is empty). Score it against
`dvra-3/instructor-oracle/scenarios.yaml`; the neutral→original identifier
mapping is the `RENAME` table in the generator.
