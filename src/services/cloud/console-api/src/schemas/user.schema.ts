import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true, collection: 'users' })
export class User {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop()
  name: string;

  @Prop({ required: true })
  passwordHash: string;

  @Prop({ default: 'viewer', enum: ['tenant_admin', 'operator', 'viewer'] })
  role: string;

  @Prop()
  tenantId: string;

  @Prop({ default: 'active', enum: ['active', 'invited', 'deactivated'] })
  status: string;

  @Prop({ nullable: true })
  lastLogin: Date | null;
}

export const UserSchema = SchemaFactory.createForClass(User);
