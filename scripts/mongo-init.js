// MongoDB initialisation script — runs once on first container start.
// Creates the application user and collection indexes, then seeds the default tenant.

db.getSiblingDB('idps_database').createUser({
  user: 'idps_app',
  pwd: process.env.MONGO_APP_PASSWORD || 'AppSecure123!',
  roles: [{ role: 'readWrite', db: 'idps_database' }],
});

const idb = db.getSiblingDB('idps_database');

idb.events.createIndex({ processed_at: 1 });
idb.events.createIndex({ event_type: 1 });
idb.blocked_ips.createIndex({ ip: 1, active: 1 });
idb.blocked_ips.createIndex({ expires_at_dt: 1 });
idb.detection_events.createIndex({ timestamp: 1 });
idb.suricata_alerts.createIndex({ received_at: 1 });
idb.telemetry.createIndex({ device_id: 1, received_at: 1 });
idb.tenants.createIndex({ tenant_id: 1 }, { unique: true });
idb.reports.createIndex({ tenant_id: 1, period_start: -1 });
idb.alert_rules.createIndex({ tenant_id: 1 });

// Seed the default single-tenant document used until multi-tenant onboarding is live.
const existing = idb.tenants.findOne({ tenant_id: 'default' });
if (!existing) {
  idb.tenants.insertOne({
    tenant_id: 'default',
    name: 'Default',
    plan: 'cloud',
    stripe_customer_id: null,
    stripe_subscription_id: null,
    node_count: 1,
    created_at: new Date(),
    active: true,
  });
}
