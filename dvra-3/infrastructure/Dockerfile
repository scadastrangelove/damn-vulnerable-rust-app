FROM rust:1.85-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dvra-api -p dvra-metadata-service

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home dvra
WORKDIR /app
COPY --from=builder /src/target/release/dvra-api /usr/local/bin/dvra-api
COPY --from=builder /src/target/release/dvra-metadata-service /usr/local/bin/dvra-metadata-service
COPY config/dvra-container.toml /app/config/dvra.toml
USER 10001:10001
ENV RUST_LOG=dvra=info
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/dvra-api"]
