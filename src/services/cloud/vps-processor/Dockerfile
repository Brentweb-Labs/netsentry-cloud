FROM rust:1.94-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

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
      cargo build --release -p vps-processor; \
    else \
      cargo build -p vps-processor; \
    fi
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false appuser

ARG BUILD_MODE=debug
COPY --from=builder /app/target/${BUILD_MODE}/vps-processor /usr/local/bin/

RUN mkdir -p /var/log/vps-processor && chown appuser:appuser /var/log/vps-processor

USER appuser

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

CMD ["vps-processor"]
