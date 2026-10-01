// Runs once on first start of the MongoDB container (empty data directory).
// Creates the least-privilege application user used by the gateway and console-api.
// Collection indexes are created by the gateway on start-up.
const appPassword = process.env.MONGO_APP_PASSWORD;
if (!appPassword) {
  throw new Error('MONGO_APP_PASSWORD is not set');
}
db.getSiblingDB('idps_database').createUser({
  user: 'idps_app',
  pwd: appPassword,
  roles: [{ role: 'readWrite', db: 'idps_database' }],
});
