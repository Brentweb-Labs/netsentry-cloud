import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type TenantDocument = Tenant & Document;

@Schema({ _id: true })
export class ApiKey {
  @Prop({ required: true })
  key: string;

  @Prop({ required: true })
  name: string;

  @Prop({ default: () => new Date() })
  createdAt: Date;

  @Prop({ nullable: true })
  lastUsed: Date | null;
}

export const ApiKeySchema = SchemaFactory.createForClass(ApiKey);

@Schema({ _id: true })
export class WireGuardConfig {
  @Prop()
  interfaceName: string;

  @Prop()
  privateKey: string;

  @Prop()
  publicKey: string;

  @Prop()
  serverPublicKey: string;

  @Prop()
  subnet: string;

  @Prop()
  peerEndpoint: string;

  @Prop()
  peerPublicKey: string;

  @Prop({ default: [] })
  allowedIPs: string[];

  @Prop({ default: 'active', enum: ['active', 'inactive', 'pending'] })
  status: string;

  @Prop({ default: () => new Date() })
  createdAt: Date;

  @Prop({ default: () => new Date() })
  updatedAt: Date;
}

export const WireGuardConfigSchema = SchemaFactory.createForClass(WireGuardConfig);

@Schema({ timestamps: true, collection: 'tenants' })
export class Tenant {
  @Prop({ required: true })
  name: string;

  @Prop({ default: 'starter', enum: ['starter', 'pro', 'enterprise'] })
  plan: string;

  @Prop({ default: 'active', enum: ['active', 'suspended', 'pending'] })
  status: string;

  @Prop()
  contactEmail: string;

  @Prop({ type: [ApiKeySchema], default: [] })
  apiKeys: ApiKey[];

  @Prop({ default: 0 })
  sensorCount: number;

  @Prop({ default: 1 })
  maxSensors: number;

  @Prop()
  stripeCustomerId: string;

  @Prop()
  stripeSubscriptionId: string;

  // Multi-tenant WireGuard configuration
  @Prop({ type: WireGuardConfigSchema })
  wireguardConfig: WireGuardConfig;

  // Optional: dedicated MongoDB database name for this tenant
  @Prop()
  mongodbDatabase: string;

  // Organization ID for grouping multiple tenants
  @Prop()
  organisationId: string;
}

export const TenantSchema = SchemaFactory.createForClass(Tenant);
