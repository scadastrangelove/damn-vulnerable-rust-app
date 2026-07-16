FROM rust:1.86-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --locked --release \
    -p dvra-api \
    -p dvra-worker \
    -p dvra-labctl \
    -p dvra-mock-metadata-service

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --create-home --home-dir /nonexistent dvra
WORKDIR /opt/dvra
COPY --from=builder /workspace/target/release/dvra-api /usr/local/bin/dvra-api
COPY --from=builder /workspace/target/release/dvra-worker /usr/local/bin/dvra-worker
COPY --from=builder /workspace/target/release/dvra-labctl /usr/local/bin/dvra-labctl
COPY --from=builder /workspace/target/release/dvra-mock-metadata-service /usr/local/bin/dvra-mock-metadata-service
COPY --from=builder /workspace/configs ./configs
COPY --from=builder /workspace/scenarios ./scenarios
USER 10001:10001
