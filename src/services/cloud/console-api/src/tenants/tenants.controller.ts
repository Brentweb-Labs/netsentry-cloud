import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/create-tenant.dto';

@UseGuards(JwtAuthGuard)
@Controller('api/console/tenants')
export class TenantsController {
  constructor(private tenantsService: TenantsService) {}

  @Get()
  findAll() {
    return this.tenantsService.findAll();
  }

  @Post()
  create(@Body() dto: CreateTenantDto) {
    return this.tenantsService.create(dto);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.tenantsService.findOne(id);
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() dto: Partial<CreateTenantDto>) {
    return this.tenantsService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.tenantsService.remove(id);
  }

  @Get(':id/users')
  getUsers(@Param('id') id: string) {
    return this.tenantsService.getUsers(id);
  }

  @Post(':id/api-keys')
  generateApiKey(@Param('id') id: string) {
    return this.tenantsService.generateApiKey(id);
  }
}
