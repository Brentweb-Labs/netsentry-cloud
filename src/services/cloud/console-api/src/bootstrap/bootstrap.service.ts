import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { Tenant, TenantDocument } from '../schemas/tenant.schema';
import { User, UserDocument } from '../schemas/user.schema';

/**
 * First-run provisioning: when no platform admin exists, create a default
 * tenant and an admin from ADMIN_EMAIL / ADMIN_PASSWORD (install.sh sets both).
 * Idempotent; the password is only used when the admin is first created.
 */
@Injectable()
export class BootstrapService implements OnApplicationBootstrap {
  private readonly log = new Logger(BootstrapService.name);

  constructor(
    @InjectModel(Tenant.name) private tenants: Model<TenantDocument>,
    @InjectModel(User.name) private users: Model<UserDocument>,
    private config: ConfigService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const email = this.config.get<string>('ADMIN_EMAIL');
    const password = this.config.get<string>('ADMIN_PASSWORD');
    if (!email || !password) {
      this.log.warn('ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping admin bootstrap');
      return;
    }
    if (await this.users.exists({ role: 'platform_admin' })) return;

    const tenant = await this.tenants.create({
      name: this.config.get<string>('DEFAULT_TENANT_NAME') ?? 'Default',
      plan: 'enterprise',
      status: 'active',
      contactEmail: email,
      maxSensors: 1000,
    });
    await this.users.create({
      email,
      name: 'Administrator',
      role: 'platform_admin',
      tenantId: tenant.id as string,
      status: 'active',
      passwordHash: await bcrypt.hash(password, 12),
    });
    this.log.log(`Created default tenant ${tenant.id} and platform admin ${email}`);
  }
}
