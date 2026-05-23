import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { TenantsModule } from './tenants/tenants.module';
import { SitesModule } from './sites/sites.module';
import { SystemModule } from './system/system.module';
import { BillingModule } from './billing/billing.module';
import { SensorsModule } from './sensors/sensors.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        uri: config.get<string>('MONGODB_URI') ?? 'mongodb://localhost:27017/idps_database',
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    TenantsModule,
    SitesModule,
    SystemModule,
    BillingModule,
    SensorsModule,
  ],
})
export class AppModule {}
