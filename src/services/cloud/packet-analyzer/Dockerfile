FROM rust:1.94-bookworm AS builder

WORKDIR /app

# Copy entire workspace for simpler build
COPY . .

# Build the packet analyzer
RUN cargo build --release -p idps-packet-analyzer

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 processor

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/idps-packet-analyzer /usr/local/bin/idps-packet-analyzer

# Set permissions
RUN chmod +x /usr/local/bin/idps-packet-analyzer

# Create data directories
RUN mkdir -p /var/log/packet-analyzer && \
    chown -R processor:processor /var/log/packet-analyzer

USER processor

EXPOSE 8090

CMD ["idps-packet-analyzer", "--port", "8090"]
