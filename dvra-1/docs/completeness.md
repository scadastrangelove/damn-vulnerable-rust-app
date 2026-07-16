# DVRA-1 completeness

This document defines the acceptance checklist for `dvra-1`.

## Intended scope

`dvra-1` is complete when it provides a compact benchmark for Rust security
code review with:

- a canonical learner-facing crate under `source/`;
- private instructor truth under `instructor-oracle/`;
- learner-safe public scenario metadata;
- repeatable learner bundle packaging;
- default and optional verification commands;
- an audit gate that catches accidental spoiler leakage.

## Current coverage

The instructor oracle tracks 22 review cases across these themes:

- data-access and authorization review;
- filesystem path handling;
- parser and normalization disagreements;
- allocation and availability hazards;
- unsafe invariants;
- panic safety;
- concurrency promises;
- optional FFI boundary review;
- threat-model-dependent command execution and hashing;
- build-script supply-chain triage;
- false-positive and reachability discipline.

## Deliberate non-goals

- `dvra-1` is not a live web service.
- It does not need a multi-service or multi-crate application architecture.
- Optional fuzz, Miri, sanitizer, and FFI gates are not part of the default
  quick test because they depend on host tooling.
- UB-bearing demonstrations are kept out of the ordinary test gate when they
  can abort on allocator/runtime differences.

## Completion gate

Run:

```sh
./tools/dvra1 test
./tools/dvra1 audit
./tools/dvra1 package-learner
```

The audit proves the repository shape and public/private split. The package
command proves that a distributable learner archive can be built without
shipping instructor truth.
