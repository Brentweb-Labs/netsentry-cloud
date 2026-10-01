import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type SensorDocument = Sensor & Document;

@Schema({ timestamps: true, collection: 'sensors' })
export class Sensor {
  @Prop({ required: true, unique: true })
  sensorId: string;

  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  tenantId: string;

  @Prop()
  siteId: string;

  /** SHA-256 (hex) of the sensor API key; the key itself is shown once and never stored. */
  @Prop({ required: true })
  apiKeyHash: string;

  /** Secret used to HMAC-sign commands the gateway sends to this sensor. */
  @Prop({ required: true })
  commandHmacSecret: string;

  @Prop()
  hostname: string;

  @Prop()
  arch: string;

  @Prop({ enum: ['span', 'inline'] })
  mode: string;

  @Prop({ default: 'pending', enum: ['pending', 'active', 'inactive', 'revoked'] })
  status: string;

  @Prop()
  lastConnectedAt: Date;

  @Prop()
  publicIp: string;

  @Prop()
  location: string;

  @Prop({ type: Object })
  hardwareInfo: {
    model: string;
    os: string;
    suricataVersion: string;
  };

  @Prop({ default: true })
  autoBlockEnabled: boolean;

  @Prop()
  expiresAt: Date;

  @Prop({ type: Object })
  config: {
    autoBlockEnabled: boolean;
    blockDurationHours: number;
    minThreatLevel: number;
    whitelist: string[];
    monitoredPaths: string[];
  };

  @Prop({ default: 0 })
  eventsCount: number;

  @Prop({ default: 0 })
  alertsCount: number;
}

export const SensorSchema = SchemaFactory.createForClass(Sensor);

SensorSchema.index({ tenantId: 1 });
SensorSchema.index({ apiKeyHash: 1 });
SensorSchema.index({ status: 1 });
