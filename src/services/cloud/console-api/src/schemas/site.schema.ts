import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type SiteDocument = Site & Document;

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
}

export const SiteSchema = SchemaFactory.createForClass(Site);
