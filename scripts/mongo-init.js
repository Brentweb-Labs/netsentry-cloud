// MongoDB initialisation script — runs once on first container start.
// Creates the application user and collection indexes for multi-tenant support.

// Create app user with readWrite access to idps_database
db.getSiblingDB('idps_database').createUser({
  user: 'idps_app',
  pwd: process.env.MONGO_APP_PASSWORD || 'AppSecure123!',
  roles: [{ role: 'readWrite', db: 'idps_database' }],
});

const idb = db.getSiblingDB('idps_database');

// ===== MULTI-TENANT INDEXES =====
// All event collections now include tenant_id for isolation

// Events collection - traffic events with tenant isolation
idb.events.createIndex({ tenant_id: 1, processed_at: 1 });
idb.events.createIndex({ tenant_id: 1, event_type: 1 });
idb.events.createIndex({ tenant_id: 1, sensor_id: 1 });
idb.events.createIndex({ tenant_id: 1, site_id: 1 });
idb.events.createIndex({ event_type: 1 });
idb.events.createIndex({ processed_at: 1 });

// Blocked IPs - tenant-scoped
idb.blocked_ips.createIndex({ tenant_id: 1, ip: 1, active: 1 });
idb.blocked_ips.createIndex({ tenant_id: 1, expires_at_dt: 1 });
idb.blocked_ips.createIndex({ ip: 1, active: 1 });

// Detection events - tenant-scoped
idb.detection_events.createIndex({ tenant_id: 1, timestamp: 1 });
idb.detection_events.createIndex({ tenant_id: 1, sensor_id: 1 });
idb.detection_events.createIndex({ timestamp: 1 });

// Suricata alerts - tenant-scoped
idb.suricata_alerts.createIndex({ tenant_id: 1, received_at: 1 });
idb.suricata_alerts.createIndex({ tenant_id: 1, sensor_id: 1 });
idb.suricata_alerts.createIndex({ received_at: 1 });

// Telemetry - tenant-scoped
idb.telemetry.createIndex({ tenant_id: 1, device_id: 1, received_at: 1 });
idb.telemetry.createIndex({ tenant_id: 1, received_at: 1 });
idb.telemetry.createIndex({ device_id: 1, received_at: 1 });

// Tenant indexes
idb.tenants.createIndex({ tenant_id: 1 }, { unique: true });
idb.tenants.createIndex({ organisationId: 1 });
idb.tenants.createIndex({ status: 1 });

// Site indexes
idb.sites.createIndex({ tenant_id: 1, site_id: 1 }, { unique: true });
idb.sites.createIndex({ tenantId: 1 });

// Sensor indexes
idb.sensors.createIndex({ tenant_id: 1, sensor_id: 1 }, { unique: true });
idb.sensors.createIndex({ tenantId: 1 });
idb.sensors.createIndex({ apiKey: 1 });

// Reports - tenant-scoped
idb.reports.createIndex({ tenant_id: 1, period_start: -1 });
idb.reports.createIndex({ tenant_id: 1, created_at: -1 });

// Alert rules - tenant-scoped
idb.alert_rules.createIndex({ tenant_id: 1 });
idb.alert_rules.createIndex({ tenant_id: 1, rule_type: 1 });

// Security rules - tenant-scoped
idb.security_rules.createIndex({ tenant_id: 1, created_at: -1 });
idb.security_rules.createIndex({ tenant_id: 1, active: 1 });

// Seed the default single-tenant document used until multi-tenant onboarding is live.
const existing = idb.tenants.findOne({ tenant_id: 'default' });
if (!existing) {
  idb.tenants.insertOne({
    tenant_id: 'default',
    name: 'Default',
    plan: 'starter',
    status: 'active',
    created_at: new Date(),
    updated_at: new Date(),
  });
}

print('MongoDB multi-tenant initialization complete.');
