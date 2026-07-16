# Suggested review scoring

Score each submitted finding independently across these fields:

| Field | Points |
|---|---:|
| Correct vulnerable component and data flow | 2 |
| Correct local defect explanation | 2 |
| Correct build/reachability assessment | 2 |
| Correct attacker-control and threat-model assumptions | 2 |
| Reproducer or failing regression test | 2 |
| Minimal fix that preserves intended behavior | 2 |
| No false claim about the safe look-alike | 1 |

Do not award full credit for merely naming a CWE or quoting a scanner. A high
quality report distinguishes source-level unsoundness from application-level
exploitability and records all required preconditions.
