# Local Development Setup - Cloud + Sensor

This guide explains how to run both the cloud services and sensor services on your laptop for local development.

## Quick Start

```bash
# Start everything (cloud + sensor)
docker compose -f docker-compose.dev.yml --env-file .env.dev up --build
```

That's it! Both systems will be online and connected.

## What's Running

### Cloud Services (on localhost)
- **API Gateway**: http://localhost:8080
  - Main API endpoint for the sensor to connect to
- **Console API**: http://localhost:8095
  - REST API for console operations
- **Console Frontend**: http://localhost:3000
  - Web UI for managing sensors and viewing alerts
- **Dashboard**: http://localhost:3001
  - VPS monitoring dashboard
- **Threat Intel**: localhost:8094 (internal only)
- **VPS Processor**: localhost:8093 (internal only)
- **MongoDB**: localhost:27017 (cloud database)

### Sensor Services (internal Docker network)
- **Raspi Collector**: localhost:8091
  - Processes packet data and telemetry from sensor
- **Rule Engine**: localhost:8094
  - Manages Suricata IDS/IPS rules
- **Telemetry Service**: localhost:8096
  - Collects hardware metrics
- **Node Exporter**: localhost:9100
  - Prometheus metrics
- **Suricata**: Internal (network traffic IDS/IPS)
- **Network Filter**: Internal (packet filtering)
- **Packet Processor**: Internal (packet capture)
- **MongoDB Edge**: Internal (sensor database)
- **Redis Edge**: Internal (sensor cache)

## Network Architecture

- **idps-dev**: Cloud services + API gateway, allows cloud ↔ sensor communication
- **sensor-net**: Sensor services, isolated but connected to cloud via api-gateway
- API Gateway is on BOTH networks, acting as the bridge between cloud and sensor

## Key Difference from WireGuard Setup

- **No WireGuard**: Uses Docker bridge networking instead of VPN tunneling
- **Direct Communication**: Services communicate via Docker DNS (e.g., `api-gateway:8080`)
- **Same Machine**: Both cloud and sensor run on your laptop without routing conflicts
- **Full Bidirectional**: Cloud can push rules to sensor, sensor pushes data to cloud

## Environment Variables

Configuration is in `.env.dev`. Key variables:

```
MONGO_ROOT_PASSWORD=DevPassword123!
JWT_SECRET=dev-secret-key-not-secure-do-not-use-in-production
ADMIN_USERNAME=admin
ADMIN_PASSWORD=dev-password-123
API_KEY=dev-sensor-key
DEVICE_ID=dev-sensor-01
REDIS_PASSWORD=RedisSecure123!
```

## Testing the Setup

### Check Cloud API
```bash
curl http://localhost:8080/api/vps/health
```

### Check Console API
```bash
curl http://localhost:8095/health
```

### Check Telemetry
```bash
curl http://localhost:8096/health
```

### View Logs
```bash
# All services
docker compose -f docker-compose.dev.yml --env-file .env.dev logs -f

# Specific service
docker compose -f docker-compose.dev.yml --env-file .env.dev logs -f api-gateway
docker compose -f docker-compose.dev.yml --env-file .env.dev logs -f raspi-collector
```

## Accessing the Web Interface

1. **Console Frontend**: http://localhost:3000
   - Login with admin/dev-password-123
   - View connected sensors
   - Manage detection rules

2. **Dashboard**: http://localhost:3001
   - View VPS metrics and alerts

## Stopping Everything

```bash
docker compose -f docker-compose.dev.yml --env-file .env.dev down
```

Or with volume cleanup:
```bash
docker compose -f docker-compose.dev.yml --env-file .env.dev down -v
```

## Rebuilding Services

If you change code in either cloud or sensor:

```bash
# Rebuild and restart
docker compose -f docker-compose.dev.yml --env-file .env.dev up --build
```

## Troubleshooting

### Services won't start
- Check logs: `docker compose -f docker-compose.dev.yml --env-file .env.dev logs`
- Ensure ports 8080, 8095, 3000, 3001 are available
- Ensure Docker has enough resources (at least 4GB RAM recommended)

### Sensor can't connect to cloud
- Check `raspi-collector` logs: raspi-collector should show WebSocket connection attempts
- Verify `VPS_ENDPOINT` in `.env.dev` is set to `http://api-gateway:8080`
- Both api-gateway and raspi-collector must be healthy

### Database issues
- MongoDB won't start: Check docker-compose logs
- Ensure `./data` directory exists and is writable
- Try: `docker compose -f docker-compose.dev.yml down -v` to reset databases

### Port conflicts
If ports are in use, modify `.env.dev` to change mappings or use `docker compose -f docker-compose.dev.yml --env-file .env.dev down` to free up ports.

## Performance Tips

- **Allocate Resources**: Docker needs at least 4GB RAM, 2 CPU cores
- **SSD Storage**: Better performance for MongoDB/Redis
- **Disable Unnecessary Services**: Comment out services you don't need in docker-compose.dev.yml
- **Use Limits**: Already configured in docker-compose.dev.yml

## For Production (VPS with WireGuard)

Use the original `docker-compose.yml` and WireGuard tunnel setup documented in the main README.
