FROM rust:1.86-bookworm

RUN rustup toolchain install nightly-2025-04-03 \
    --profile minimal \
    --component miri \
    --component rust-src
WORKDIR /workspace
COPY . .
RUN mkdir -p .cargo /opt/dvra \
    && MIRI_SYSROOT=/opt/dvra/miri-sysroot cargo +nightly-2025-04-03 miri setup \
    && cargo vendor /opt/dvra/vendor > .cargo/config.toml
RUN useradd --system --uid 10001 --create-home --home-dir /nonexistent dvra \
    && chown -R dvra:dvra /workspace /opt/dvra
USER 10001:10001
ENV CARGO_HOME=/tmp/dvra/cargo-home
ENV CARGO_NET_OFFLINE=true
ENV CARGO_TARGET_DIR=/tmp/dvra/target
ENV HOME=/tmp/dvra/home
ENV MIRI_SYSROOT=/opt/dvra/miri-sysroot
