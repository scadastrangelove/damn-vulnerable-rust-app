FROM rust:1.86-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home-dir /home/dvra dvra

WORKDIR /workspace
COPY --chown=dvra:dvra . .

RUN mkdir -p .cargo \
    && cargo vendor --manifest-path source/Cargo.toml vendor > .cargo/config.toml \
    && chown -R dvra:dvra .cargo vendor

USER 10001:10001

ENV CARGO_HOME=/tmp/cargo
ENV CARGO_TARGET_DIR=/tmp/dvra-target
ENV CARGO_NET_OFFLINE=true
ENV DVRA1_DIST=/tmp/dvra-dist

ENTRYPOINT ["./tools/dvra1"]
CMD ["test"]
