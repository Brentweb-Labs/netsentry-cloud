FROM rust:1.94-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/services/cloud/api-gateway ./src/services/cloud/api-gateway
RUN cargo build --release --locked -p netsentry-gateway

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 gateway
COPY --from=builder /app/target/release/netsentry-gateway /usr/local/bin/netsentry-gateway
USER gateway
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["netsentry-gateway"]
