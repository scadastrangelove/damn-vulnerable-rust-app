# DVRA design

## Application story

DVRA is a small multi-tenant artifact-processing service. Tenants upload or
select artifacts, request parsing, and configure a post-processing hook. The
same plausible domain supports authorization bugs, parser bugs, configuration
trust questions, filesystem and command boundaries, async execution, unsafe
optimizations, and dependency analysis.

## Threat models

### TM-LOCAL-ADMIN

- The configuration file is writable only by a trusted local administrator.
- Tenants can submit artifact names and artifact contents.
- Debug logs are available only to the same administrator.

Under this model, the shell template is intentionally dangerous but may be an
accepted administrative capability. Artifact names are still attacker input, so
concatenating them into the shell command remains a vulnerability.

### TM-TENANT-CONFIG

- A tenant can update its own post-processing template through a control plane.
- The worker runs with access to artifacts of multiple tenants.
- Logs are available to support staff and a central aggregation service.

Under this model, the same post-processing mechanism becomes direct remote code
execution, and debug printing of the configuration becomes a secret disclosure.

### TM-AIRGAPPED-TRAINING

- The API binds to loopback.
- The container has no useful credentials, no Docker socket, no host home mount,
  and no route to cloud metadata or the public internet.
- The optional fake metadata service contains only the marker
  `DVRA_FAKE_METADATA_TOKEN`.

### TM-NO-INTERNAL-EGRESS

- Tenants control the fetch URL, but the metadata service profile is absent.
- DVRA-009 remains a reachable defect/capability, while the demonstrated fake
  credential disclosure is not achievable.

### TM-INTERNAL-METADATA

- The API and fake metadata service share the isolated `lab` network.
- Tenants control the fetch URL, redirects are followed, and the marker token is
  disclosed. Under this model DVRA-009 is impactful.

### TM-TRUSTED-CONFIG-URL

- The same fetch helper may be called with a URL writable only by a trusted
  operator. The sink is dangerous, but attacker control is absent until another
  control-plane path changes that assumption.

## Scenario truth model

Private course oracles can record each scenario with the five truth axes:

```yaml
truth:
  defect: null
  built: null
  reachable: null
  attacker_controlled: null
  impactful: null
```

A static tool can be correct about `defect` while still over-reporting
application risk because `reachable` or `attacker_controlled` is false.

## Profiles

- `safe-default`: application runs, while command, filesystem, and SSRF labs reject execution.
- `vulnerable`: command/filesystem execution requires `DVRA_LAB_MODE=vulnerable`
  plus acknowledgement.
- `ssrf-lab`: URL fetching requires `DVRA_SSRF_LAB_MODE=fake-metadata-only`,
  starts only the inert metadata service, and uses an internal Docker network.
- `fixed`: fixed endpoints are available alongside vulnerable endpoints so
  reviewers can compare implementations.

## Historical and compiler-specific cases

Old standard-library CVEs and `cve-rs` should not be regular workspace members.
They require pinned toolchains and can produce memory corruption or toolchain
specific behavior. Each future lab must have its own container, network disabled
by default, resource limits, and a reproducible expected result.

## Filesystem containment

DVRA-008 uses `/tmp/dvra/storage/job-{id}` as the intended extraction root. The
reproducer escapes one level and overwrites another job file under the shared
storage tree. The endpoint is guarded by the same explicit dangerous-lab
acknowledgement as command injection. The comparison implementation provides a
lexical path-component check; the current threat model assumes tenants cannot
pre-populate the destination with symlinks. A later scenario will challenge that
assumption directly.


## SSRF containment

The fake metadata service is not published to the host and starts only under the
`ssrf-lab` Compose profile. It is attached only to the internal `lab` network.
The API also joins a localhost-only `ingress` bridge so the host reproducer can
reach `127.0.0.1:3000`; that bridge disables IP masquerading. The vulnerable
route additionally requires the scenario-specific SSRF gate plus explicit
acknowledgement. The fixed comparison assumes that DNS and proxy configuration
for allowlisted origins are controlled by the operator; DNS rebinding is
reserved for a later scenario.
