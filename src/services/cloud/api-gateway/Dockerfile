FROM rust:1.94-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release -p idps-api-gateway

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 api-gateway

WORKDIR /app

COPY --from=builder /app/target/release/idps-api-gateway /usr/local/bin/idps-api-gateway

RUN chmod +x /usr/local/bin/idps-api-gateway

USER api-gateway

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["idps-api-gateway"]
