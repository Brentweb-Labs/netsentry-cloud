import { Body, Controller, Delete, Get, Param, Post, Request, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { AuthUser } from '../auth/jwt.strategy';
import { EnrollmentService } from './enrollment.service';
import { CreateEnrollmentTokenDto } from './dto/create-enrollment-token.dto';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('platform_admin', 'tenant_admin')
@Controller('api/enrollment-tokens')
export class EnrollmentController {
  constructor(private service: EnrollmentService) {}

  @Post()
  create(@Request() req: { user: AuthUser }, @Body() dto: CreateEnrollmentTokenDto) {
    return this.service.create(req.user, dto);
  }

  @Get()
  list(@Request() req: { user: AuthUser }) {
    return this.service.list(req.user);
  }

  @Delete(':id')
  revoke(@Request() req: { user: AuthUser }, @Param('id') id: string) {
    return this.service.revoke(req.user, id);
  }
}
