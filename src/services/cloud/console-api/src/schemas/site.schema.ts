import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type SiteDocument = Site & Document;

@Schema({ _id: true })
export class SiteWireGuardConfig {
  @Prop()
  subnet: string;

  @Prop()
  peerEndpoint: string;

  @Prop()
  peerPublicKey: string;

  @Prop({ default: [] })
  allowedIPs: string[];

  @Prop({ default: 'inherit', enum: ['inherit', 'custom', 'disabled'] })
  mode: string;

  @Prop()
  updatedAt: Date;
}

export const SiteWireGuardConfigSchema = SchemaFactory.createForClass(SiteWireGuardConfig);

@Schema({ timestamps: true, collection: 'sites' })
export class Site {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  tenantId: string;

  @Prop()
  location: string;

  @Prop({ default: 'active', enum: ['active', 'inactive', 'maintenance'] })
  status: string;

  @Prop({ type: [Object], default: [] })
  sensors: Record<string, unknown>[];

  // Per-site WireGuard configuration override
  // Allows sites to have different subnets than their parent tenant
  @Prop({ type: SiteWireGuardConfigSchema })
  wireguardConfig: SiteWireGuardConfig;

  // Site-specific MongoDB collection prefix (optional)
  @Prop()
  mongodbCollectionPrefix: string;

  // Site description for admin reference
  @Prop()
  description: string;
}

export const SiteSchema = SchemaFactory.createForClass(Site);
