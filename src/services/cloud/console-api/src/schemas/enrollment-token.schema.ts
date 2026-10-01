import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type EnrollmentTokenDocument = EnrollmentToken & Document;

/**
 * Sensor enrollment token. Field names are snake_case on purpose: the Rust
 * gateway consumes this collection (`enrollment_tokens`) directly.
 */
@Schema({ collection: 'enrollment_tokens', versionKey: false })
export class EnrollmentToken {
  @Prop({ required: true, index: true })
  tenant_id: string;

  /** SHA-256 (hex) of the token; the token is shown once at creation. */
  @Prop({ required: true, unique: true })
  token_hash: string;

  /** First characters of the token, for display only. */
  @Prop({ required: true })
  token_prefix: string;

  @Prop({ default: '' })
  label: string;

  @Prop()
  created_by: string;

  @Prop({ default: () => new Date() })
  created_at: Date;

  @Prop({ required: true })
  expires_at: Date;

  @Prop({ required: true, default: 1 })
  max_uses: number;

  @Prop({ required: true, default: 0 })
  uses: number;

  @Prop({ default: false })
  revoked: boolean;

  @Prop()
  last_used_at: Date;
}

export const EnrollmentTokenSchema = SchemaFactory.createForClass(EnrollmentToken);
