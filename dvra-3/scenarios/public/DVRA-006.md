# DVRA-006 — Reachability and false positives

The configuration crate includes two command-related helpers. One is genuinely
unsafe but is not connected to a production entry point. The other accepts
untrusted text but avoids the shell.

## Goal

For each finding, report separately:

- local defect status;
- build inclusion;
- reachability;
- attacker control;
- application impact.
