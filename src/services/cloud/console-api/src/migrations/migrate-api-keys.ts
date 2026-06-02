import { connect } from 'mongoose';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/netsentry';

async function migrateApiKeys() {
  const connection = await connect(MONGO_URI);
  const db = connection.connection.db;

  if (!db) {
    throw new Error('Failed to connect to MongoDB');
  }

  try {
    // Migrate tenants with old-style apiKeys (string array) to new format
    const result = await db.collection('tenants').updateMany(
      { apiKeys: { $exists: true, $type: 'array' } },
      [
        {
          $set: {
            apiKeys: {
              $map: {
                input: '$apiKeys',
                as: 'key',
                in: {
                  _id: { $oid: '000000000000000000000000' },
                  key: '$$key',
                  name: 'Migrated API Key',
                  createdAt: new Date(),
                  lastUsed: null,
                },
              },
            },
          },
        },
      ],
    );

    console.log(`Migrated ${result.modifiedCount} tenants with API keys`);

    // Add missing fields to users
    const userResult = await db.collection('users').updateMany(
      {},
      [
        {
          $set: {
            status: { $ifNull: ['$status', 'active'] },
            lastLogin: { $ifNull: ['$lastLogin', null] },
          },
        },
      ],
    );

    console.log(`Migrated ${userResult.modifiedCount} users with new fields`);
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  } finally {
    await connection.disconnect();
  }
}

migrateApiKeys()
  .then(() => {
    console.log('Migration completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Migration failed:', error);
    process.exit(1);
  });
