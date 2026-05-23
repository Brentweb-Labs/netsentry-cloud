import { Controller, Get, Post, Put, Delete, Body, Param, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { SitesService } from './sites.service';
import { CreateSiteDto } from './dto/create-site.dto';

@UseGuards(JwtAuthGuard)
@Controller('api/console/sites')
export class SitesController {
  constructor(private sitesService: SitesService) {}

  @Get()
  findAll(@Query('tenantId') tenantId?: string) {
    return this.sitesService.findAll(tenantId);
  }

  @Post()
  create(@Body() dto: CreateSiteDto) {
    return this.sitesService.create(dto);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.sitesService.findOne(id);
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() dto: Partial<CreateSiteDto>) {
    return this.sitesService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.sitesService.remove(id);
  }

  @Get(':id/sensors')
  getSensors(@Param('id') id: string) {
    return this.sitesService.getSensors(id);
  }
}
