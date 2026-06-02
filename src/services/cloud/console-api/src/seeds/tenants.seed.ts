import { connect } from 'mongoose';
import * as crypto from 'crypto';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/netsentry';

interface TenantDoc {
  name: string;
  plan: string;
  status: string;
  contactEmail: string;
  sensorCount: number;
  maxSensors: number;
  apiKeys: Array<{
    key: string;
    name: string;
    createdAt: Date;
    lastUsed: Date | null;
  }>;
}

interface UserDoc {
  email: string;
  name: string;
  role: string;
  tenantId: string;
  status: string;
  passwordHash: string;
  lastLogin: Date;
  createdAt: Date;
  updatedAt: Date;
}

async function seedTenants() {
  const connection = await connect(MONGO_URI);
  const db = connection.connection.db;

  if (!db) {
    throw new Error('Failed to connect to MongoDB');
  }

  try {
    // Create test tenants
    const tenants: TenantDoc[] = [
      {
        name: 'Acme Corporation',
        plan: 'pro',
        status: 'active',
        contactEmail: 'contact@acme.com',
        sensorCount: 5,
        maxSensors: 10,
        apiKeys: [
          {
            key: `nsk_${crypto.randomBytes(24).toString('hex')}`,
            name: 'Production API Key',
            createdAt: new Date(),
            lastUsed: new Date(Date.now() - 86400000),
          },
        ],
      },
      {
        name: 'Beta Startup',
        plan: 'starter',
        status: 'active',
        contactEmail: 'contact@beta.com',
        sensorCount: 0,
        maxSensors: 5,
        apiKeys: [],
      },
    ];

    const tenantResult = await db.collection('tenants').insertMany(tenants);
    const tenantIds = Object.values(tenantResult.insertedIds);
    console.log(`Created ${tenantResult.insertedCount} tenants`);

    // Create test users for each tenant
    const users: UserDoc[] = [];
    for (let i = 0; i < tenantIds.length; i++) {
      users.push(
        {
          email: `admin@tenant${i}.com`,
          name: `Admin User ${i}`,
          role: 'tenant_admin',
          tenantId: tenantIds[i].toString(),
          status: 'active',
          passwordHash: crypto.randomBytes(32).toString('hex'),
          lastLogin: new Date(Date.now() - 3600000),
          createdAt: new Date(Date.now() - 86400000 * 30),
          updatedAt: new Date(),
        },
        {
          email: `operator@tenant${i}.com`,
          name: `Operator User ${i}`,
          role: 'operator',
          tenantId: tenantIds[i].toString(),
          status: 'active',
          passwordHash: crypto.randomBytes(32).toString('hex'),
          lastLogin: new Date(Date.now() - 7200000),
          createdAt: new Date(Date.now() - 86400000 * 7),
          updatedAt: new Date(),
        },
      );
    }

    const userResult = await db.collection('users').insertMany(users);
    console.log(`Created ${userResult.insertedCount} users`);
  } catch (error) {
    console.error('Seeding failed:', error);
    throw error;
  } finally {
    await connection.disconnect();
  }
}

seedTenants()
  .then(() => {
    console.log('Seeding completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Seeding failed:', error);
    process.exit(1);
  });
