# NetSentry Cloud

Multi-tenant cloud for [NetSentry sensors](https://github.com/Brentweb-Labs/netsentry-sensor): it ingests
Suricata alerts and telemetry, detects attacks, and pushes **signed** block/rule commands back to the sensors.

> Proprietary software, all rights reserved (see [LICENSE](LICENSE); placeholder pending a licensing decision).

## Install

Requirements: a Linux host with Docker (the installer can install it), a DNS name pointing at the host,
and ports 80/443 open (Caddy obtains TLS certificates automatically).

```sh
git clone https://github.com/Brentweb-Labs/netsentry-cloud.git && cd netsentry-cloud
./install.sh
```

The installer asks for your domain and admin e-mail, generates all secrets into `.env` (mode 600), builds and
starts the stack, then prints the admin login and a first sensor enrollment token. Non-interactive:
`./install.sh --yes --domain cloud.example.com --admin-email you@example.com`. Use `--domain localhost` for a
local trial (self-signed certificate).

| URL | What |
|---|---|
| `https://DOMAIN/` | Operator dashboard: overview, alerts, blocked IPs, sensors, settings |
| `https://DOMAIN/console/` | Admin console (tenants, users, sites, sensors, enrollment tokens) |
| `https://DOMAIN/grafana/` | Grafana (user `admin`, password `GRAFANA_ADMIN_PASSWORD` in `.env`) |

## Enrolling a sensor

Create a token in the dashboard (Sensors > Enroll a sensor), the console, or via the API
(`POST /api/enrollment-tokens`), then on the sensor host:

```sh
curl -fsSL https://raw.githubusercontent.com/Brentweb-Labs/netsentry-sensor/main/install.sh | \
  sudo NETSENTRY_CLOUD_URL=https://DOMAIN NETSENTRY_ENROLL_TOKEN=nse_... sh
```

Tokens are tenant-scoped, expire (default 24 h) and have a use limit (default 1). They are stored only as hashes.

## Architecture

```
sensors --HTTPS/WSS--> Caddy (auto TLS) --+--> api-gateway (Rust, axum)  data plane: enroll, ingest, detect, block
                                          +--> console-api (NestJS)      control plane: tenants, users, sensors, tokens
                                          +--> dashboard / console (Angular, nginx)
                                          +--> grafana
        api-gateway, console-api --> MongoDB 8   (one database, every record carries tenant_id / sensor_id)
        api-gateway              --> Redis       (rate limiting)      Prometheus scrapes api-gateway:/metrics
```

- **Tenancy.** Users sign in to console-api and receive an HS256 JWT (`sub, email, role, tenantId`). The gateway
  verifies the same secret. Every query is scoped to the token's tenant; sensors are bound to a tenant at enrollment.
  Roles: `platform_admin`, `tenant_admin`, `operator`, `viewer` (viewers are read-only; settings need an admin).
- **Gateway modules** (`src/services/cloud/api-gateway/src`): `routes` (HTTP), `auth`, `signing` (command HMAC),
  `detection`, `prevention`, `threat_intel`, `pipeline` (ingest), `ws`, `store`, `settings`.
- **Detection:** Suricata alerts (severity 1 to 4), per-tenant brute-force windows on monitored HTTP paths, attack
  patterns in HTTP requests and streamed packet payloads, and abuse.ch IP lists (Feodo Tracker, SSLBL; refreshed
  every 6 h, override with `THREAT_FEED_URLS`).

### Blocking safety

- **Manual approval is the default.** Detections create *pending* proposals; an operator approves or rejects them.
- Automatic blocking is opt-in per tenant, limited to severity <= `auto_block_max_severity` (default 1, critical),
  and capped at `max_auto_blocks_per_hour` (default 20); beyond the cap it falls back to proposals.
- **Allowlist** (IPs/CIDRs, defaults to RFC 1918/ULA) is never blocked. Loopback, multicast, link-local and
  unspecified addresses are never blockable, even manually.
- **Every block has a TTL** (default 24 h, max 720 h) and is lifted automatically; the sensor is told to unblock.
- Block targets are validated IP literals; rule text is sanitised; no iptables strings are ever sent to sensors.

## Sensor protocol

Authentication is the `X-API-Key` header only (query parameters are ignored). Keys are stored as SHA-256 hashes.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/sensors/enroll` | header `X-Enrollment-Token`; body `{hostname, arch, mode: span\|inline}`; returns `{sensor_id, tenant_id, api_key, command_hmac_secret, ingest_url, ws_url}`. `ingest_url` is a base URL. Rate limited. |
| POST | `/api/traffic`, `/api/traffic/batch` | events `{id?, timestamp?, source_ip, dest_ip, source_port, dest_port, protocol, event_type, payload, threat_level}`; batch max 5000, invalid entries are skipped and counted |
| POST | `/api/telemetry` | free-form object; an `alerts` array is turned into alerts. Tenant/sensor ids in the body are ignored. |
| GET | `/api/prevention/blocked` | `{data: [{ip, reason, severity, expires_at}]}` active blocks of the sensor's tenant |
| WS | `/ws/raspi` | command channel |
| WS | `/ws/packets` | raw packet stream `{src_ip, dst_ip, src_port, dst_port, protocol, payload_hex}`, inspected, not stored |

**Commands** arrive as JSON text frames `{type, payload, ts, sig}` with `type` one of `block_command`
(`id, ip, reason, severity, duration_secs, expires_at, apply_suricata_rule`), `unblock_command` (`id, ip, reason`) and
`rule_update` (`rule_id, action, suricata_rule, description`).
`sig = hex(HMAC-SHA256(command_hmac_secret, type + "." + ts + "." + canonical(payload)))`, where `ts` is integer Unix
seconds (signed as its decimal string) and `canonical` is compact JSON with object keys sorted recursively.
The secret is per sensor. Sensors drop commands older than 60 s or replayed; reconnecting sensors receive their
tenant's active blocks again.

## Configuration

`install.sh` writes `.env`; see [.env.example](.env.example). Gateway variables: `MONGODB_URI`, `JWT_SECRET`
(32+ chars, required), `PUBLIC_URL`, `REDIS_URL`, `THREAT_FEED_URLS` (comma list, `none` disables),
`EVENT_RETENTION_DAYS` (events and alerts expire via TTL index), `CORS_ORIGINS`, `RUST_LOG`.
console-api creates the first `platform_admin` and a default tenant from `ADMIN_EMAIL`/`ADMIN_PASSWORD` on first start.

## Development and tests

```sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                   # unit + router tests
TEST_MONGODB_URI=mongodb://localhost:27017 cargo test    # adds the MongoDB flow and WebSocket tests
(cd src/services/cloud/console-api && npm ci && npm run build && npx jest)
docker compose --env-file .env config -q
BASE_URL=https://localhost INSECURE=1 ADMIN_EMAIL=... ADMIN_PASSWORD=... ./scripts/e2e-smoke.sh   # against a running stack
```

CI (`.github/workflows/ci.yml`) runs all of the above, including the compose end-to-end smoke test.

## Operations notes

- Back up the `mongodb_data` volume. Rotate secrets by editing `.env` and `docker compose up -d`
  (changing `JWT_SECRET` signs everyone out; `MONGO_*` passwords only apply to a fresh data volume).
- The landing site (`src/saas/netsentry-landing`) is not part of the stack.
- Billing, e-mail/SMS alerting and PDF reports from the earlier prototype are not included in this release.
- Earlier commits of this repository contain WireGuard key material. Treat those keys as compromised and rotate them;
  rewriting history is a separate decision.
