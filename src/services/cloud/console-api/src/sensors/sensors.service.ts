import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { Sensor, SensorDocument } from '../schemas/sensor.schema';
import { Tenant, TenantDocument } from '../schemas/tenant.schema';
import { CreateSensorDto, UpdateSensorDto } from './dto/sensor.dto';

@Injectable()
export class SensorsService {
  constructor(
    @InjectModel(Sensor.name) private sensorModel: Model<SensorDocument>,
    @InjectModel(Tenant.name) private tenantModel: Model<TenantDocument>,
  ) {}

  async findAll(tenantId: string) {
    return this.sensorModel.find({ tenantId })
      .select('-apiKey')
      .sort({ createdAt: -1 })
      .exec();
  }

  async findOne(sensorId: string, tenantId: string) {
    const sensor = await this.sensorModel.findOne({ sensorId, tenantId })
      .select('-apiKey')
      .exec();
    if (!sensor) throw new NotFoundException('Sensor not found');
    return sensor;
  }

  async findOneByApiKey(apiKey: string): Promise<SensorDocument | null> {
    return this.sensorModel.findOne({ apiKey, status: { $ne: 'revoked' } }).exec();
  }

  async create(dto: CreateSensorDto): Promise<{ sensorId: string; apiKey: string }> {
    // Check sensor limit for tenant
    const tenant = await this.tenantModel.findById(dto.tenantId).exec();
    let currentCount = 0;
    if (tenant) {
      currentCount = await this.sensorModel.countDocuments({
        tenantId: dto.tenantId,
        status: { $ne: 'revoked' }
      }).exec();

      if (currentCount >= tenant.maxSensors) {
        throw new BadRequestException(
          `Sensor limit reached. Your plan includes ${tenant.maxSensors} sensors. Upgrade to add more.`
        );
      }
    }

    const sensorId = crypto.randomUUID();
    const apiKey = `nss_${crypto.randomBytes(24).toString('hex')}`;

    const sensor = new this.sensorModel({
      sensorId,
      name: dto.name,
      tenantId: dto.tenantId,
      siteId: dto.siteId,
      location: dto.location,
      hardwareInfo: dto.hardwareInfo,
      apiKey,
      status: 'pending',
      autoBlockEnabled: true,
      config: {
        autoBlockEnabled: true,
        blockDurationHours: 24,
        minThreatLevel: 1,
        whitelist: [],
        monitoredPaths: [],
      },
      eventsCount: 0,
      alertsCount: 0,
    });

    await sensor.save();

    // Update tenant sensor count
    if (tenant) {
      tenant.sensorCount = currentCount + 1;
      await tenant.save();
    }

    return { sensorId, apiKey };
  }

  async update(sensorId: string, tenantId: string, dto: UpdateSensorDto) {
    const sensor = await this.sensorModel.findOneAndUpdate(
      { sensorId, tenantId },
      dto,
      { new: true }
    ).select('-apiKey').exec();

    if (!sensor) throw new NotFoundException('Sensor not found');
    return sensor;
  }

  async revoke(sensorId: string, tenantId: string) {
    const sensor = await this.sensorModel.findOneAndUpdate(
      { sensorId, tenantId },
      { status: 'revoked' },
      { new: true }
    ).select('-apiKey').exec();

    if (!sensor) throw new NotFoundException('Sensor not found');

    // Update tenant sensor count
    const tenant = await this.tenantModel.findById(tenantId).exec();
    if (tenant && tenant.sensorCount > 0) {
      tenant.sensorCount -= 1;
      await tenant.save();
    }

    return { revoked: true, sensorId };
  }

  async regenerateKey(sensorId: string, tenantId: string): Promise<{ apiKey: string }> {
    const sensor = await this.sensorModel.findOne({ sensorId, tenantId }).exec();
    if (!sensor) throw new NotFoundException('Sensor not found');

    const newApiKey = `nss_${crypto.randomBytes(24).toString('hex')}`;
    sensor.apiKey = newApiKey;
    await sensor.save();

    return { apiKey: newApiKey };
  }

  async updateLastConnected(sensorId: string, publicIp?: string) {
    return this.sensorModel.findOneAndUpdate(
      { sensorId },
      {
        lastConnectedAt: new Date(),
        status: 'active',
        ...(publicIp && { publicIp }),
      },
      { new: true }
    ).exec();
  }

  async incrementEventsCount(sensorId: string) {
    return this.sensorModel.findOneAndUpdate(
      { sensorId },
      { $inc: { eventsCount: 1 } }
    ).exec();
  }

  async incrementAlertsCount(sensorId: string) {
    return this.sensorModel.findOneAndUpdate(
      { sensorId },
      { $inc: { alertsCount: 1 } }
    ).exec();
  }

  async getSensorCount(tenantId: string): Promise<number> {
    return this.sensorModel.countDocuments({
      tenantId,
      status: { $ne: 'revoked' }
    }).exec();
  }

  async findAllByTenant(tenantId: string): Promise<SensorDocument[]> {
    return this.sensorModel.find({
      tenantId,
      status: { $ne: 'revoked' }
    }).exec();
  }
}
