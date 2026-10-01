import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { TenantsModule } from './tenants/tenants.module';
import { SitesModule } from './sites/sites.module';
import { SystemModule } from './system/system.module';
import { BillingModule } from './billing/billing.module';
import { SensorsModule } from './sensors/sensors.module';
import { EnrollmentModule } from './enrollment/enrollment.module';
import { BootstrapModule } from './bootstrap/bootstrap.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        uri: config.getOrThrow<string>('MONGODB_URI'),
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    TenantsModule,
    SitesModule,
    SystemModule,
    BillingModule,
    SensorsModule,
    EnrollmentModule,
    BootstrapModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
