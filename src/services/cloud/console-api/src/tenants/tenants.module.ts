import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { TenantsController } from './tenants.controller';
import { TenantsService } from './tenants.service';
import { Tenant, TenantSchema } from '../schemas/tenant.schema';
import { User, UserSchema } from '../schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Tenant.name, schema: TenantSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [TenantsController],
  providers: [TenantsService],
})
export class TenantsModule {}
