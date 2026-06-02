#!/bin/bash
# =============================================================================
# NetSentry Cloud — Interactive Environment Setup
# Generates a .env file with secure secrets for your deployment.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

generate_secret() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 32
    else
        date +%s%N | sha256sum | base64 | head -c 44
    fi
}

# ── Guard: don't overwrite an existing .env without confirmation ──────────────
if [ -f "$ENV_FILE" ]; then
    log_warn "Environment file already exists at $ENV_FILE"
    read -r -p "Overwrite? (y/N): " reply
    echo
    if [[ ! $reply =~ ^[Yy]$ ]]; then
        log_info "Keeping existing .env file"
        exit 0
    fi
fi

echo "=============================================="
echo "  NetSentry Cloud — Environment Setup"
echo "=============================================="
echo ""

# ── Secrets (auto-generated) ──────────────────────────────────────────────────
JWT_SECRET=$(generate_secret)
log_info "Generated JWT_SECRET"

read -r -p "MongoDB root password (leave blank to generate): " MONGO_ROOT_PASSWORD
if [ -z "$MONGO_ROOT_PASSWORD" ]; then
    MONGO_ROOT_PASSWORD=$(generate_secret | tr -d '=+/' | head -c 32)
    log_info "Generated MONGO_ROOT_PASSWORD"
fi

# ── Admin credentials ─────────────────────────────────────────────────────────
read -r -p "Admin username [admin]: " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

read -r -s -p "Admin password: " ADMIN_PASSWORD
echo
if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD=$(generate_secret | tr -d '=+/' | head -c 24)
    log_warn "No password entered — generated: $ADMIN_PASSWORD"
    log_warn "Save this! It won't be shown again."
fi

# ── Domain & access ───────────────────────────────────────────────────────────
read -r -p "Your cloud domain (e.g. netsentry.example.com): " DOMAIN
while [ -z "$DOMAIN" ]; do
    log_error "Domain is required."
    read -r -p "Your cloud domain: " DOMAIN
done

read -r -p "Your management IP for dashboard allowlist (e.g. 203.0.113.42): " ALLOWED_IP
while [ -z "$ALLOWED_IP" ]; do
    log_error "Management IP is required."
    read -r -p "Your management IP: " ALLOWED_IP
done

# ── Optional: Stripe ──────────────────────────────────────────────────────────
read -r -p "Stripe secret key (skip to leave empty): " STRIPE_SECRET_KEY
read -r -p "Stripe price ID (skip to leave empty): " STRIPE_PRICE_ID
read -r -p "Stripe webhook secret (skip to leave empty): " STRIPE_WEBHOOK_SECRET

# ── Optional: SMTP ────────────────────────────────────────────────────────────
read -r -p "SMTP host (skip to leave empty): " SMTP_HOST
read -r -p "SMTP username (skip to leave empty): " SMTP_USERNAME

# ── Optional: Twilio ─────────────────────────────────────────────────────────
read -r -p "Twilio Account SID (skip to leave empty): " TWILIO_ACCOUNT_SID

# ── Write .env ────────────────────────────────────────────────────────────────
cat > "$ENV_FILE" << EOF
# =============================================================================
# NetSentry Cloud Environment Configuration
# Generated: $(date -u)
# =============================================================================

# DOMAIN & ACCESS
DOMAIN=${DOMAIN}
ALLOWED_IP=${ALLOWED_IP}/32

# DATABASE
MONGO_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}

# AUTHENTICATION
JWT_SECRET=${JWT_SECRET}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
TENANT_ID=default

# SENSOR CONNECTIVITY
# Update this to your sensor's WireGuard IP once sensors are deployed.
SENSOR_ENDPOINT=http://10.10.0.2:8080

# INTERNAL SERVICES
THREAT_INTEL_URL=http://threat-intel:8094
LOG_LEVEL=info

# DETECTION SETTINGS
AUTO_BLOCK_ENABLED=false

# STRIPE BILLING (optional)
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-}
STRIPE_PRICE_ID=${STRIPE_PRICE_ID:-}
STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET:-}

# SMTP EMAIL ALERTS (optional)
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=587
SMTP_USERNAME=${SMTP_USERNAME:-}
SMTP_PASSWORD=
SMTP_FROM=alerts@netsentry.io

# TWILIO SMS ALERTS (optional)
TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID:-}
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=

# LOGGING
RUST_LOG=info
EOF

chmod 600 "$ENV_FILE"

echo ""
log_info "Environment file written to $ENV_FILE"
log_info "Review and fill in any remaining blanks (SMTP_PASSWORD, TWILIO_AUTH_TOKEN, etc.)"
echo ""
log_info "Pre-flight checklist:"
echo "  1. Ensure the external 'proxy' Docker network exists:"
echo "       docker network create proxy"
echo "  2. Ensure Traefik is running in a separate stack."
echo "  3. DNS A record for ${DOMAIN} → this server's public IP."
echo "  4. WireGuard interface wg0 is running on this server."
echo ""
log_info "To start the cloud stack:"
echo "  docker compose -f docker-compose.yml up -d"
echo ""
log_info "To check logs:"
echo "  docker compose -f docker-compose.yml logs -f"
