import { Injectable, NotFoundException, BadRequestException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { Tenant, TenantDocument, WireGuardConfig } from '../schemas/tenant.schema';
import { User, UserDocument } from '../schemas/user.schema';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { InviteUserDto } from './dto/invite-user.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { ApiKeyResponseDto, CreateApiKeyResponseDto } from './dto/api-key-response.dto';
import { CreateWireGuardConfigDto, SensorConfigResponseDto } from './dto/wireguard-config.dto';

@Injectable()
export class TenantsService {
  // Track used subnets for multi-tenant WireGuard (10.1.0.0/24 - 10.254.0.0/24)
  private usedSubnets: Set<number> = new Set();

  constructor(
    @InjectModel(Tenant.name) private tenantModel: Model<TenantDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  private mapTenant(tenant: any) {
    if (!tenant) return null;
    const { _id, __v, ...rest } = tenant;
    return { ...rest, id: _id?.toString?.() || _id };
  }

  private mapUser(user: any): UserResponseDto {
    return {
      id: user._id?.toString?.() || user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      last_login: user.lastLogin || null,
      created_at: user.createdAt,
    };
  }

  async findAll() {
    const tenants = await this.tenantModel.find().lean().exec();
    return tenants.map(t => this.mapTenant(t));
  }

  async findOne(id: string) {
    this.validateId(id);
    const tenant = await this.tenantModel.findById(id).lean().exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return this.mapTenant(tenant);
  }

  async create(dto: CreateTenantDto) {
    const tenant = await new this.tenantModel(dto).save();
    return this.mapTenant(tenant.toObject());
  }

  async update(id: string, dto: Partial<CreateTenantDto>) {
    this.validateId(id);
    const tenant = await this.tenantModel.findByIdAndUpdate(id, dto, { new: true }).lean().exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return this.mapTenant(tenant);
  }

  async remove(id: string) {
    this.validateId(id);
    const tenant = await this.tenantModel.findByIdAndDelete(id).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return { deleted: true };
  }

  async getUsers(tenantId: string): Promise<UserResponseDto[]> {
    this.validateId(tenantId);
    const users = await this.userModel.find({ tenantId }).select('-passwordHash').lean().exec();
    return users.map(u => this.mapUser(u));
  }

  async inviteUser(tenantId: string, dto: InviteUserDto): Promise<UserResponseDto> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    const existing = await this.userModel.findOne({ email: dto.email, tenantId }).exec();
    if (existing) throw new ConflictException('User already exists in this tenant');

    const user = await this.userModel.create({
      email: dto.email,
      name: dto.name,
      role: dto.role,
      tenantId,
      status: 'invited',
      passwordHash: crypto.randomBytes(1).toString('hex'),
    });

    return this.mapUser(user);
  }

  async deactivateUser(tenantId: string, userId: string): Promise<void> {
    this.validateId(tenantId);
    this.validateId(userId);
    const user = await this.userModel.findOneAndUpdate(
      { _id: userId, tenantId },
      { status: 'deactivated' },
      { new: true }
    ).exec();
    if (!user) throw new NotFoundException('User not found in this tenant');
  }

  async getApiKeys(tenantId: string): Promise<ApiKeyResponseDto[]> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).lean().exec();
    if (!tenant) throw new NotFoundException('Tenant not found');
    return (tenant.apiKeys || []).map((ak: any) => ({
      id: ak._id?.toString?.() || ak._id,
      name: ak.name,
      prefix: ak.key.substring(0, 10),
      created_at: ak.createdAt,
      last_used: ak.lastUsed || null,
    }));
  }

  async generateApiKey(tenantId: string, name: string): Promise<CreateApiKeyResponseDto> {
    this.validateId(tenantId);
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      throw new BadRequestException('API key name is required');
    }

    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    const key = `nsk_${crypto.randomBytes(24).toString('hex')}`;
    const apiKey = { key, name, createdAt: new Date(), lastUsed: null };
    tenant.apiKeys.push(apiKey as any);
    await tenant.save();

    const savedKey = tenant.apiKeys[tenant.apiKeys.length - 1];
    return {
      id: (savedKey as any)._id?.toString?.() || (savedKey as any)._id,
      name: savedKey.name,
      key,
      prefix: key.substring(0, 10),
      created_at: savedKey.createdAt,
      last_used: savedKey.lastUsed || null,
    };
  }

  async revokeApiKey(tenantId: string, keyId: string): Promise<void> {
    this.validateId(tenantId);
    this.validateId(keyId);
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    const initialLength = tenant.apiKeys.length;
    tenant.apiKeys = tenant.apiKeys.filter((ak: any) => ak._id?.toString?.() !== keyId);

    if (tenant.apiKeys.length === initialLength) {
      throw new NotFoundException('API key not found');
    }

    await tenant.save();
  }

  private validateId(id: string): void {
    if (!id || typeof id !== 'string') {
      throw new BadRequestException('Invalid ID: tenantId must be a string');
    }
  }

  // ===== WireGuard Multi-Tenant Configuration =====

  /**
   * Generate a new WireGuard key pair
   */
  private generateKeyPair(): { privateKey: string; publicKey: string } {
    // Generate random 32-byte key
    const privateKeyBytes = crypto.randomBytes(32);
    const privateKey = privateKeyBytes.toString('base64');

    // For WireGuard, public key is derived by hashing the private key
    // Using a simple approach for compatibility
    const publicKey = crypto.createHash('sha256').update(privateKeyBytes).digest('base64').slice(0, 44);

    return { privateKey, publicKey };
  }

  /**
   * Get next available subnet number (10.1.x.0/24 - 10.254.x.0/24)
   */
  private getNextSubnetNumber(): number {
    for (let i = 1; i <= 254; i++) {
      if (!this.usedSubnets.has(i)) {
        this.usedSubnets.add(i);
        return i;
      }
    }
    // If all used, reuse from beginning (after clearing old ones)
    this.usedSubnets.clear();
    this.usedSubnets.add(1);
    return 1;
  }

  /**
   * Create WireGuard configuration for a tenant
   */
  async createWireGuardConfig(tenantId: string, dto: CreateWireGuardConfigDto): Promise<any> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    // Check if config already exists
    if (tenant.wireguardConfig) {
      throw new ConflictException('WireGuard config already exists for this tenant');
    }

    // Generate key pairs (server and client)
    const serverKeys = this.generateKeyPair();
    const clientKeys = this.generateKeyPair();

    // Determine subnet
    let subnet: string;
    if (dto.customSubnet) {
      // Validate custom subnet format (must be 10.x.0.0/24)
      const subnetMatch = dto.customSubnet.match(/^10\.(\d+)\.0\.0\/24$/);
      if (!subnetMatch) {
        throw new BadRequestException('Custom subnet must be in format 10.x.0.0/24 (x: 1-254)');
      }
      const num = parseInt(subnetMatch[1], 10);
      if (num < 1 || num > 254) {
        throw new BadRequestException('Subnet second octet must be between 1 and 254');
      }
      subnet = dto.customSubnet;
      this.usedSubnets.add(num);
    } else {
      const subnetNum = this.getNextSubnetNumber();
      subnet = `10.${subnetNum}.0.0/24`;
    }

    const config: WireGuardConfig = {
      interfaceName: `wg-tenant-${tenantId.substring(0, 8)}`,
      privateKey: clientKeys.privateKey,
      publicKey: clientKeys.publicKey,
      serverPublicKey: serverKeys.publicKey,
      subnet,
      peerEndpoint: process.env.WG_PEER_ENDPOINT || '10.10.0.1:51820',
      peerPublicKey: serverKeys.publicKey,
      allowedIPs: ['0.0.0.0/0'],
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    tenant.wireguardConfig = config as any;
    await tenant.save();

    return {
      interfaceName: config.interfaceName,
      subnet: config.subnet,
      peerEndpoint: config.peerEndpoint,
      peerPublicKey: config.peerPublicKey,
      allowedIPs: config.allowedIPs,
      status: config.status,
    };
  }

  /**
   * Get WireGuard configuration for a tenant (without private key)
   */
  async getWireGuardConfig(tenantId: string): Promise<any> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).lean().exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    if (!tenant.wireguardConfig) {
      return null;
    }

    return {
      interfaceName: tenant.wireguardConfig.interfaceName,
      subnet: tenant.wireguardConfig.subnet,
      peerEndpoint: tenant.wireguardConfig.peerEndpoint,
      peerPublicKey: tenant.wireguardConfig.peerPublicKey,
      allowedIPs: tenant.wireguardConfig.allowedIPs,
      status: tenant.wireguardConfig.status,
      createdAt: tenant.wireguardConfig.createdAt,
    };
  }

  /**
   * Get sensor configuration (includes private key for sensor device)
   */
  async getSensorConfig(tenantId: string): Promise<SensorConfigResponseDto> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).lean().exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    if (!tenant.wireguardConfig) {
      throw new NotFoundException('WireGuard config not found for this tenant');
    }

    const wg = tenant.wireguardConfig;
    // Sensor gets address .2 in the subnet
    const address = wg.subnet.replace('/24', '/2');

    return {
      privateKey: wg.privateKey,
      address,
      endpoint: wg.peerEndpoint,
      peerPublicKey: wg.serverPublicKey,
      allowedIPs: wg.allowedIPs,
      dns: ['1.1.1.1', '8.8.8.8'],
      persistentKeepalive: 25,
    };
  }

  /**
   * Delete WireGuard configuration for a tenant
   */
  async deleteWireGuardConfig(tenantId: string): Promise<void> {
    this.validateId(tenantId);
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (!tenant) throw new NotFoundException('Tenant not found');

    if (tenant.wireguardConfig) {
      // Release subnet number
      const subnetMatch = tenant.wireguardConfig.subnet.match(/^10\.(\d+)\.0\.0\/24$/);
      if (subnetMatch) {
        this.usedSubnets.delete(parseInt(subnetMatch[1], 10));
      }
      tenant.wireguardConfig = undefined as any;
      await tenant.save();
    }
  }
}
