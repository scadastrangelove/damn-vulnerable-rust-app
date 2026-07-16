# DVRA-003 — Parser differential

The parser has a validation pass and a normalization pass. Normal unit tests do
not cover the problematic byte sequence.

## Goal

- Build a structure-aware fuzz target.
- Minimize the crashing input.
- Explain the violated cross-pass invariant.
- Fix the implementation and retain the minimized input as regression corpus.
