# Private Oracle

DVRA keeps learner-facing scenario descriptions separate from the instructor
truth table. Public manifests should explain the surface, threat model choices,
and suggested tools. They should not encode the final answer.

The instructor oracle should answer these five questions independently:

- `defect`: is an invariant actually violated?
- `built`: is the code included after feature and cfg resolution?
- `reachable`: is there an entry-point path in this build?
- `attacker_controlled`: can an attacker influence the required data?
- `impactful`: does the defect matter in the chosen threat model?

`built` means selected by the Rust build after features, target cfgs, and crate
membership are resolved. It does not mean a linker happened to retain or discard
a symbol.

The recommended local path is `instructor-oracle/`, which is ignored by Git.
