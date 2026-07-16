# DVRA-002 — Configuration and command boundary

The service supports post-processing artifacts with an operator-configured
command. Analyze this feature under both `TM-LOCAL-ADMIN` and
`TM-TENANT-CONFIG`.

## Goal

- Identify which values cross the shell boundary.
- Explain how configuration ownership changes severity.
- Demonstrate the issue only in the isolated dangerous profile.
- Propose a design that does not require shell parsing.
