import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true, collection: 'users' })
export class User {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  passwordHash: string;

  @Prop({ default: 'admin', enum: ['superadmin', 'admin', 'viewer'] })
  role: string;

  @Prop()
  tenantId: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
