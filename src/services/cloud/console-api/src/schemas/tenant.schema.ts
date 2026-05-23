import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type TenantDocument = Tenant & Document;

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

  @Prop({ type: [String], default: [] })
  apiKeys: string[];

  @Prop({ default: 0 })
  sensorCount: number;

  @Prop({ default: 1 })
  maxSensors: number;

  @Prop()
  stripeCustomerId: string;

  @Prop()
  stripeSubscriptionId: string;
}

export const TenantSchema = SchemaFactory.createForClass(Tenant);
