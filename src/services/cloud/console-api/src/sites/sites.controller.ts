import { Controller, Get, Post, Put, Delete, Body, Param, Query, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { AuthUser } from '../auth/jwt.strategy';
import { SitesService } from './sites.service';
import { CreateSiteDto } from './dto/create-site.dto';

type Req = { user: AuthUser };

/** Platform admins may pass ?tenantId=; everyone else is pinned to their own tenant. */
function scope(req: Req, requested?: string): string | undefined {
  return req.user.role === 'platform_admin' ? requested : req.user.tenantId;
}

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('api/console/sites')
export class SitesController {
  constructor(private sitesService: SitesService) {}

  @Get()
  findAll(@Request() req: Req, @Query('tenantId') tenantId?: string) {
    return this.sitesService.findAll(scope(req, tenantId));
  }

  @Roles('platform_admin', 'tenant_admin')
  @Post()
  create(@Request() req: Req, @Body() dto: CreateSiteDto) {
    return this.sitesService.create(dto, scope(req, dto.tenant_id) ?? req.user.tenantId);
  }

  @Get(':id')
  findOne(@Request() req: Req, @Param('id') id: string) {
    return this.sitesService.findOne(id, scope(req));
  }

  @Roles('platform_admin', 'tenant_admin')
  @Put(':id')
  update(@Request() req: Req, @Param('id') id: string, @Body() dto: Partial<CreateSiteDto>) {
    return this.sitesService.update(id, dto, scope(req));
  }

  @Roles('platform_admin', 'tenant_admin')
  @Delete(':id')
  remove(@Request() req: Req, @Param('id') id: string) {
    return this.sitesService.remove(id, scope(req));
  }

  @Get(':id/sensors')
  getSensors(@Request() req: Req, @Param('id') id: string) {
    return this.sitesService.getSensors(id, scope(req));
  }
}
