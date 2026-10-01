import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { EnrollmentToken, EnrollmentTokenDocument } from '../schemas/enrollment-token.schema';
import { CreateEnrollmentTokenDto } from './dto/create-enrollment-token.dto';
import { AuthUser } from '../auth/jwt.strategy';

export function generateToken(): string {
  return `nse_${crypto.randomBytes(24).toString('hex')}`;
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Platform admins may target any tenant; everyone else only their own. */
export function resolveTenant(user: AuthUser, requested?: string): string {
  if (requested && requested !== user.tenantId) {
    if (user.role !== 'platform_admin') {
      throw new ForbiddenException('Cannot manage another tenant');
    }
    return requested;
  }
  return user.tenantId;
}

@Injectable()
export class EnrollmentService {
  constructor(@InjectModel(EnrollmentToken.name) private model: Model<EnrollmentTokenDocument>) {}

  async create(user: AuthUser, dto: CreateEnrollmentTokenDto) {
    const tenantId = resolveTenant(user, dto.tenantId);
    const token = generateToken();
    const ttl = dto.ttlHours ?? 24;
    const doc = await this.model.create({
      tenant_id: tenantId,
      token_hash: hashToken(token),
      token_prefix: token.slice(0, 10),
      label: dto.label ?? '',
      created_by: user.email,
      expires_at: new Date(Date.now() + ttl * 3600 * 1000),
      max_uses: dto.maxUses ?? 1,
      uses: 0,
      revoked: false,
    });
    return {
      id: doc.id as string,
      token, // shown once
      tenant_id: tenantId,
      expires_at: doc.expires_at,
      max_uses: doc.max_uses,
    };
  }

  async list(user: AuthUser) {
    const rows = await this.model
      .find({ tenant_id: user.tenantId })
      .sort({ created_at: -1 })
      .limit(100)
      .select('-token_hash')
      .lean()
      .exec();
    return rows.map(({ _id, ...rest }) => ({ id: String(_id), ...rest }));
  }

  async revoke(user: AuthUser, id: string) {
    const filter = user.role === 'platform_admin' ? { _id: id } : { _id: id, tenant_id: user.tenantId };
    const res = await this.model.findOneAndUpdate(filter, { revoked: true }, { new: true }).exec();
    if (!res) throw new NotFoundException('Enrollment token not found');
    return { revoked: true, id };
  }
}
