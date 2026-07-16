# DVRA-004 — Panic safety

A safe public API is implemented with `MaybeUninit`. Analyze ownership and drop
behavior when a caller-provided closure unwinds.

## Goal

- State the type invariant.
- Use Miri to validate the suspected undefined behavior.
- Produce a panic-safe implementation.
