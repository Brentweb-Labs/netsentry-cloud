import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Site, SiteDocument } from '../schemas/site.schema';
import { CreateSiteDto } from './dto/create-site.dto';

@Injectable()
export class SitesService {
  constructor(@InjectModel(Site.name) private siteModel: Model<SiteDocument>) {}

  private mapSite(site: any) {
    if (!site) return null;
    const { _id, __v, ...rest } = site;
    return { ...rest, id: _id?.toString?.() || _id };
  }

  async findAll(tenantId?: string) {
    const sites = await this.siteModel.find(tenantId ? { tenantId } : {}).lean().exec();
    return sites.map(s => this.mapSite(s));
  }

  async create(dto: CreateSiteDto, tenantId: string) {
    const site = await new this.siteModel({
      name: dto.name,
      tenantId,
      location: dto.location,
      status: dto.status,
    }).save();
    return this.mapSite(site.toObject());
  }

  async findOne(id: string, tenantId?: string) {
    const site = await this.siteModel.findOne({ _id: id, ...(tenantId ? { tenantId } : {}) }).lean().exec();
    if (!site) throw new NotFoundException('Site not found');
    return this.mapSite(site);
  }

  async update(id: string, dto: Partial<CreateSiteDto>, tenantId?: string) {
    const { name, location, status } = dto;
    const site = await this.siteModel
      .findOneAndUpdate({ _id: id, ...(tenantId ? { tenantId } : {}) }, { name, location, status }, { new: true })
      .lean()
      .exec();
    if (!site) throw new NotFoundException('Site not found');
    return this.mapSite(site);
  }

  async remove(id: string, tenantId?: string) {
    const site = await this.siteModel.findOneAndDelete({ _id: id, ...(tenantId ? { tenantId } : {}) }).exec();
    if (!site) throw new NotFoundException('Site not found');
    return { deleted: true };
  }

  async getSensors(id: string, tenantId?: string) {
    const site = await this.findOne(id, tenantId);
    return site.sensors;
  }
}
