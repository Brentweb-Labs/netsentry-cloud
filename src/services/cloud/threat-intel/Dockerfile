# Build stage
FROM rust:1.94-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy entire workspace
COPY . .

# Build the application
RUN cargo build --release -p idps-threat-intel

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false threatintel

# Copy binary from builder
COPY --from=builder /app/target/release/idps-threat-intel /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/idps-threat-intel

# Switch to non-root user
USER threatintel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8092/health || exit 1

# Expose port
EXPOSE 8092

# Run the application
CMD ["idps-threat-intel"]
