import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TenantsService } from './tenants.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { CreateApiKeyDto } from './dto/create-api-key.dto';
import { InviteUserDto } from './dto/invite-user.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { ApiKeyResponseDto, CreateApiKeyResponseDto } from './dto/api-key-response.dto';
import { CreateWireGuardConfigDto, SensorConfigResponseDto } from './dto/wireguard-config.dto';

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
  getUsers(@Param('id') id: string): Promise<UserResponseDto[]> {
    return this.tenantsService.getUsers(id);
  }

  @Post(':id/users')
  inviteUser(@Param('id') id: string, @Body() dto: InviteUserDto): Promise<UserResponseDto> {
    return this.tenantsService.inviteUser(id, dto);
  }

  @Delete(':id/users/:userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deactivateUser(@Param('id') id: string, @Param('userId') userId: string): Promise<void> {
    return this.tenantsService.deactivateUser(id, userId);
  }

  @Get(':id/api-keys')
  getApiKeys(@Param('id') id: string): Promise<ApiKeyResponseDto[]> {
    return this.tenantsService.getApiKeys(id);
  }

  @Post(':id/api-keys')
  generateApiKey(@Param('id') id: string, @Body() dto: CreateApiKeyDto): Promise<CreateApiKeyResponseDto> {
    return this.tenantsService.generateApiKey(id, dto.name);
  }

  @Delete(':id/api-keys/:keyId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeApiKey(@Param('id') id: string, @Param('keyId') keyId: string): Promise<void> {
    return this.tenantsService.revokeApiKey(id, keyId);
  }

  // ===== WireGuard Multi-Tenant Configuration =====

  @Post(':id/wireguard-config')
  createWireGuardConfig(@Param('id') id: string, @Body() dto: CreateWireGuardConfigDto) {
    return this.tenantsService.createWireGuardConfig(id, dto);
  }

  @Get(':id/wireguard-config')
  getWireGuardConfig(@Param('id') id: string) {
    return this.tenantsService.getWireGuardConfig(id);
  }

  @Get(':id/wireguard-config/sensor')
  getSensorConfig(@Param('id') id: string): Promise<SensorConfigResponseDto> {
    return this.tenantsService.getSensorConfig(id);
  }

  @Delete(':id/wireguard-config')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteWireGuardConfig(@Param('id') id: string): Promise<void> {
    return this.tenantsService.deleteWireGuardConfig(id);
  }
}
