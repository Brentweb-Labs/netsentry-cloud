import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { SensorsService } from './sensors.service';
import { CreateSensorDto, UpdateSensorDto } from './dto/sensor.dto';

interface AuthenticatedRequest {
  user: {
    tenantId: string;
  };
}

@UseGuards(JwtAuthGuard)
@Controller('api/sensors')
export class SensorsController {
  constructor(private sensorsService: SensorsService) {}

  @Get()
  findAll(@Request() req: AuthenticatedRequest) {
    return this.sensorsService.findAll(req.user.tenantId);
  }

  @Post()
  create(@Request() req: AuthenticatedRequest, @Body() dto: CreateSensorDto) {
    return this.sensorsService.create({
      ...dto,
      tenantId: req.user.tenantId,
    });
  }

  @Get(':id')
  findOne(@Param('id') id: string, @Request() req: AuthenticatedRequest) {
    return this.sensorsService.findOne(id, req.user.tenantId);
  }

  @Put(':id')
  update(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
    @Body() dto: UpdateSensorDto,
  ) {
    return this.sensorsService.update(id, req.user.tenantId, dto);
  }

  @Delete(':id')
  revoke(@Param('id') id: string, @Request() req: AuthenticatedRequest) {
    return this.sensorsService.revoke(id, req.user.tenantId);
  }

  @Post(':id/regenerate-key')
  regenerateKey(@Param('id') id: string, @Request() req: AuthenticatedRequest) {
    return this.sensorsService.regenerateKey(id, req.user.tenantId);
  }
}
