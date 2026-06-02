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

  async create(dto: CreateSiteDto) {
    const site = await new this.siteModel(dto).save();
    return this.mapSite(site.toObject());
  }

  async findOne(id: string) {
    const site = await this.siteModel.findById(id).lean().exec();
    if (!site) throw new NotFoundException('Site not found');
    return this.mapSite(site);
  }

  async update(id: string, dto: Partial<CreateSiteDto>) {
    const site = await this.siteModel.findByIdAndUpdate(id, dto, { new: true }).lean().exec();
    if (!site) throw new NotFoundException('Site not found');
    return this.mapSite(site);
  }

  async remove(id: string) {
    const site = await this.siteModel.findByIdAndDelete(id).exec();
    if (!site) throw new NotFoundException('Site not found');
    return { deleted: true };
  }

  async getSensors(id: string) {
    const site = await this.findOne(id);
    return site.sensors;
  }
}
