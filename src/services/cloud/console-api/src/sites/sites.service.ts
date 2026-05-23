import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Site, SiteDocument } from '../schemas/site.schema';
import { CreateSiteDto } from './dto/create-site.dto';

@Injectable()
export class SitesService {
  constructor(@InjectModel(Site.name) private siteModel: Model<SiteDocument>) {}

  findAll(tenantId?: string) {
    return this.siteModel.find(tenantId ? { tenantId } : {}).exec();
  }

  create(dto: CreateSiteDto) {
    return new this.siteModel(dto).save();
  }

  async findOne(id: string) {
    const site = await this.siteModel.findById(id).exec();
    if (!site) throw new NotFoundException('Site not found');
    return site;
  }

  async update(id: string, dto: Partial<CreateSiteDto>) {
    const site = await this.siteModel.findByIdAndUpdate(id, dto, { new: true }).exec();
    if (!site) throw new NotFoundException('Site not found');
    return site;
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
