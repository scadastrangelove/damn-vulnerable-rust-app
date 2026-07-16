# Verification

Use these commands from the repository root.

## Rust gates

```sh
cargo run -p dvra-labctl -- doctor
cargo run -p dvra-labctl -- audit
cargo fmt --all -- --check
cargo test --workspace --locked
cargo test -p dvra-unsafe-cache --features loom-model --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --locked
```

## Local scenario reproducers

```sh
cargo run -p dvra-labctl -- list
cargo run -p dvra-labctl -- reproduce DVRA-001
cargo run -p dvra-labctl -- reproduce DVRA-004
cargo run -p dvra-labctl -- reproduce DVRA-006
cargo run -p dvra-labctl -- reproduce DVRA-009
cargo run -p dvra-labctl -- reproduce DVRA-014
```

`DVRA-006` and `DVRA-009` intentionally report panics internally; the tests pass
because those panics are the expected finding.

## Container gates

Run `cargo run -p dvra-labctl -- doctor` first. Its Docker checks are
time-bounded, so an unhealthy builder is reported instead of hanging the lab
session.

```sh
docker compose -f infrastructure/compose.yaml --profile labs config
docker compose -f infrastructure/compose.yaml --profile labs build api lab-worker mock-metadata
docker compose -f infrastructure/compose.yaml --profile labs run --rm lab-worker
docker compose -f infrastructure/compose.yaml --profile labs build dvra-miri-008 dvra-miri-013
docker compose -f infrastructure/compose.yaml --profile labs run --rm dvra-miri-008
docker compose -f infrastructure/compose.yaml --profile labs run --rm dvra-miri-013
```

The Miri image vendors Cargo dependencies at image build time and sets
`CARGO_NET_OFFLINE=true`, so the runtime reproducer is expected to work with
`network_mode: none`.

If the host has Docker but not the Compose plugin, use the equivalent direct
commands:

```sh
docker build -f infrastructure/containers/Dockerfile -t dvra-runtime:local .
docker run --rm --read-only \
  --tmpfs /tmp/dvra:rw,noexec,nosuid,nodev,size=64m \
  --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 256m --cpus 0.5 \
  -e DVRA_LAB_MODE=isolated \
  dvra-runtime:local \
  dvra-worker process /opt/dvra/configs/tenant-vulnerable.yaml \
  /opt/dvra/scenarios/fixtures/parser/basic.dvra /tmp/dvra/work

docker build -f infrastructure/containers/miri.Dockerfile -t dvra-miri:local .
docker run --rm --read-only \
  --tmpfs /tmp/dvra:rw,nosuid,nodev,size=512m \
  --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 1g --cpus 1.0 \
  dvra-miri:local sh tools/miri-reproduce.sh DVRA-008
docker run --rm --read-only \
  --tmpfs /tmp/dvra:rw,nosuid,nodev,size=512m \
  --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 1g --cpus 1.0 \
  dvra-miri:local sh tools/miri-reproduce.sh DVRA-013
```

If even a tiny Docker build hangs, for example:

```sh
DOCKER_BUILDKIT=0 docker build -t dvra-docker-smoke - <<'EOF'
FROM scratch
LABEL org.dvra.smoke=true
EOF
```

then the Docker builder is unhealthy independently of DVRA. In that state,
`docker compose config` can still validate YAML, but image execution is not
verified.
