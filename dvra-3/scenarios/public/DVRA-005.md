# DVRA-005 — Incorrect Sync

A small counter wraps `UnsafeCell` and manually implements `Sync`.

## Goal

- Explain why the safety justification is invalid.
- Use Loom to find an execution that violates the expected result or access rules.
- Replace the implementation with an appropriate synchronization primitive.
