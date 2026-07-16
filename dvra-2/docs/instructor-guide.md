# Instructor Guide

DVRA is designed to teach evidence-based vulnerability classification. The
exercise should reward proving the full application-risk chain, not merely
finding scary-looking Rust.

## Suggested Flow

1. Give learners only the public repository.
2. Ask them to classify each scenario on the five truth axes:
   `defect`, `built`, `reachable`, `attacker_controlled`, and `impactful`.
3. Require evidence for each axis: code references, route or call graph,
   configuration authority, test output, fuzzing, Loom, Miri, or container
   execution.
4. Compare submissions against the benchmark oracle in
   `instructor-oracle/scenarios.yaml`.

## Benchmark Gold Labels

The public benchmark includes the gold labels needed for tool evaluation:

- final truth table;
- scoring rules;
- expected false-positive and false-negative rationale.

For challenge-style classroom use, instructors can distribute a branch or bundle
without `instructor-oracle/` until grading.

## Review Rubric

For each scenario, a strong answer should include:

- the relevant threat model;
- the exact entry point or explanation that no production entry point exists;
- whether the code is selected by the current build;
- the source of attacker control;
- the concrete impact or reason impact is absent;
- the command or tool output used as evidence.

## Tool Versioning

Tool expectations are not timeless. Record the versions used by the course:

```yaml
tools:
  rustc: 1.86.0
  miri: nightly-2025-04-03
  loom: 0.7.x
  cargo-fuzz: pinned by course image
  docker: pinned by course runner
```

Avoid saying a class of bug is "not found by static analysis" without naming
the exact analyzer and version.
