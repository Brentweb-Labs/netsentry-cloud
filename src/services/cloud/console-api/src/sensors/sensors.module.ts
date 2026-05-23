import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { SensorsController } from './sensors.controller';
import { SensorsService } from './sensors.service';
import { Sensor, SensorSchema } from '../schemas/sensor.schema';
import { Tenant, TenantSchema } from '../schemas/tenant.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Sensor.name, schema: SensorSchema },
      { name: Tenant.name, schema: TenantSchema },
    ]),
  ],
  controllers: [SensorsController],
  providers: [SensorsService],
  exports: [SensorsService],
})
export class SensorsModule {}
