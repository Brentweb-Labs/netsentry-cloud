import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { Tenant, TenantDocument } from '../schemas/tenant.schema';
import { User, UserDocument } from '../schemas/user.schema';
import { CreateTenantDto } from './dto/create-tenant.dto';

@Injectable()
export class TenantsService {
  constructor(
    @InjectModel(Tenant.name) private tenantModel: Model<TenantDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  findAll() {
    return this.tenantModel.find().exec();
  }

  async findOne(id: string) {
    const tenant = await this.tenantModel.findById(id).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return tenant;
  }

  create(dto: CreateTenantDto) {
    return new this.tenantModel(dto).save();
  }

  async update(id: string, dto: Partial<CreateTenantDto>) {
    const tenant = await this.tenantModel.findByIdAndUpdate(id, dto, { new: true }).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return tenant;
  }

  async remove(id: string) {
    const tenant = await this.tenantModel.findByIdAndDelete(id).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return { deleted: true };
  }

  getUsers(tenantId: string) {
    return this.userModel.find({ tenantId }).select('-passwordHash').exec();
  }

  async generateApiKey(tenantId: string) {
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    const key = `nsk_${crypto.randomBytes(24).toString('hex')}`;
    tenant.apiKeys.push(key);
    await tenant.save();
    return { api_key: key };
  }
}
