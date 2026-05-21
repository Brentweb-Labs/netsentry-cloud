FROM rust:1.94-bookworm AS chef
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG BUILD_MODE=debug
COPY --from=planner /app/recipe.json recipe.json
RUN if [ "$BUILD_MODE" = "release" ]; then \
      cargo chef cook --release --recipe-path recipe.json; \
    else \
      cargo chef cook --recipe-path recipe.json; \
    fi
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --release -p idps-log-processor; \
    else \
      cargo build -p idps-log-processor; \
    fi

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG BUILD_MODE=debug
COPY --from=builder /app/target/${BUILD_MODE}/idps-log-processor /usr/local/bin/

RUN mkdir -p /app/logs

ENV RUST_LOG=info
ENV MONGODB_URI=mongodb://mongo:27017/idps
ENV VPS_URL=http://packet-analyzer:8090
ENV RASPI_URL=http://api-gateway:8080

EXPOSE 8095

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD test -f /app/logs/eve.json || exit 1

CMD ["idps-log-processor"]
