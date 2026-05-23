import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { SitesController } from './sites.controller';
import { SitesService } from './sites.service';
import { Site, SiteSchema } from '../schemas/site.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: Site.name, schema: SiteSchema }])],
  controllers: [SitesController],
  providers: [SitesService],
})
export class SitesModule {}
