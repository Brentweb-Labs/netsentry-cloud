#!/bin/bash
# =============================================================================
# NetSentry Install Script - Auto-generates environment configuration
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Generate a secure random JWT secret
generate_jwt_secret() {
    if command -v openssl &> /dev/null; then
        openssl rand -base64 32
    else
        # Fallback: use date + random from /dev/urandom
        date +%s | sha256sum | base64 | head -c 43
    fi
}

# Generate bcrypt hash for password
hash_password() {
    local password="$1"
    if command -v htpasswd &> /dev/null; then
        htpasswd -nbBC 10 "" "$password" | cut -d: -f2
    elif command -v python3 &> /dev/null; then
        python3 -c "import bcrypt; print(bcrypt.hashpw(b'$password', bcrypt.gensalt()).decode())"
    else
        log_warn "Cannot hash password - bcrypt not available. Using plaintext (not recommended)."
        echo "$password"
    fi
}

# Check if .env exists
if [ -f "$ENV_FILE" ]; then
    log_warn "Environment file already exists at $ENV_FILE"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing .env file"
        exit 0
    fi
fi

echo "=============================================="
echo "  NetSentry Environment Configuration"
echo "=============================================="
echo ""

# Generate JWT secret
JWT_SECRET=$(generate_jwt_secret)
log_info "Generated JWT_SECRET"

# Get admin credentials
read -p "Admin username [admin]: " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

read -s -p "Admin password: " ADMIN_PASSWORD
echo
if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD="changeme"
    log_warn "Using default password (changeme)"
fi

# Hash password for comparison in Rust
ADMIN_PASSWORD_HASH="$ADMIN_PASSWORD"
if command -v python3 &> /dev/null; then
    ADMIN_PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$ADMIN_PASSWORD', bcrypt.gensalt()).decode())" 2>/dev/null) || ADMIN_PASSWORD_HASH="$ADMIN_PASSWORD"
fi

# Get MongoDB credentials
read -p "MongoDB root password [SecurePassword123!]: " MONGO_ROOT_PASSWORD
MONGO_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD:-SecurePassword123!}

# Get domain
read -p "Domain for Traefik [idps.brentweb.eu]: " DOMAIN
DOMAIN=${DOMAIN:-idps.brentweb.eu}

# Get your IP for IP whitelist
read -p "Your IP for dashboard access [109.133.17.150]: " ALLOWED_IP
ALLOWED_IP=${ALLOWED_IP:-109.133.17.150}

# Stripe (optional)
read -p "Stripe secret key (skip to leave empty): " STRIPE_SECRET_KEY
read -p "Stripe price ID (skip to leave empty): " STRIPE_PRICE_ID

# SMTP for alerts (optional)
read -p "SMTP host (skip to leave empty): " SMTP_HOST
read -p "SMTP username (skip to leave empty): " SMTP_USERNAME

# Twilio for SMS alerts (optional)
read -p "Twilio Account SID (skip to leave empty): " TWILIO_ACCOUNT_SID

# Generate the .env file
cat > "$ENV_FILE" << EOF
# =============================================================================
# NetSentry Environment Configuration
# Generated: $(date)
# =============================================================================

# =============================================================================
# DATABASE
# =============================================================================
MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
MONGODB_URI=mongodb://admin:${MONGO_ROOT_PASSWORD}@mongodb:27017/idps_database?authSource=admin

# =============================================================================
# AUTHENTICATION
# =============================================================================
JWT_SECRET=$JWT_SECRET
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD_HASH
TENANT_ID=default

# =============================================================================
# TRAEFIK / ROUTING
# =============================================================================
DOMAIN=$DOMAIN
ALLOWED_IP=$ALLOWED_IP

# =============================================================================
# RASPBERRY PI CONNECTIVITY (VPS side)
# =============================================================================
RASPI_ENDPOINT=http://10.10.0.2:8080

# =============================================================================
# SERVICES
# =============================================================================
THREAT_INTEL_URL=http://threat-intel:8094
LOG_LEVEL=info

# =============================================================================
# STRIPE BILLING (optional)
# =============================================================================
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-}
STRIPE_PRICE_ID=${STRIPE_PRICE_ID:-}
STRIPE_WEBHOHOOK_SECRET=

# =============================================================================
# SMTP EMAIL ALERTS (optional)
# =============================================================================
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=587
SMTP_USERNAME=${SMTP_USERNAME:-}
SMTP_PASSWORD=
SMTP_FROM=alerts@netsentry.io

# =============================================================================
# TWILIO SMS ALERTS (optional)
# =============================================================================
TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID:-}
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=

# =============================================================================
# LOGGING
# =============================================================================
RUST_LOG=info

# =============================================================================
# DETECTION SETTINGS
# =============================================================================
AUTO_BLOCK_ENABLED=false
EOF

chmod 600 "$ENV_FILE"

log_info "Environment file created at $ENV_FILE"
log_info "Please review and update any sensitive values"
echo ""
log_info "To start services:"
echo "  cd $SCRIPT_DIR"
echo "  docker compose -f docker-compose.vps.yml up -d"
echo ""
log_info "To check logs:"
echo "  docker compose -f docker-compose.vps.yml logs -f"
