# Security policy

DVRA is intentionally insecure. Do not report documented training scenarios as
security vulnerabilities in this repository.

Report only issues that affect the containment model itself, such as:

- the default profile executing a dangerous scenario without acknowledgement;
- a container gaining access to host secrets, the Docker socket, or external
  networks contrary to the documented configuration;
- a reproducer modifying files outside the repository or disposable `/tmp`;
- a dangerous filesystem route running without the two-variable acknowledgement gate;
- the SSRF route running without its distinct fake-metadata-only gate;
- an undocumented vulnerability in the fixed comparison implementation;
- a dependency or build-script compromise unrelated to an intentional fixture.

Do not run exploit demonstrations against systems you do not own or have explicit
permission to test.


## DVRA-009 fake metadata credentials

`DVRAFAKEACCESSKEY`, `dvra-fake-secret-not-a-real-credential`, and
`DVRA_FAKE_METADATA_TOKEN` are inert training markers. The metadata service is
not host-published and is attached only to the internal `lab` network. The API
also joins a localhost-only `ingress` bridge so the reproducer can reach
`127.0.0.1:3000`; that bridge disables IP masquerading. Never replace these
markers with real credentials or attach the lab to a production network.
