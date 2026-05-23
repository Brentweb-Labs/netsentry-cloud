import { Controller, Get, UseGuards, Headers } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { SystemService } from './system.service';

@UseGuards(JwtAuthGuard)
@Controller('api/console/system')
export class SystemController {
  constructor(private systemService: SystemService) {}

  @Get('services')
  getServices(@Headers('authorization') auth: string) {
    return this.systemService.getServices(auth);
  }

  @Get('logs')
  getLogs(@Headers('authorization') auth: string) {
    return this.systemService.getLogs(auth);
  }
}
