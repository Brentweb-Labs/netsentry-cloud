import { Controller, Get, Post, UseGuards, Headers } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { BillingService } from './billing.service';

@UseGuards(JwtAuthGuard)
@Controller('api/console/billing')
export class BillingController {
  constructor(private billingService: BillingService) {}

  @Get('subscription')
  getSubscription(@Headers('authorization') auth: string) {
    return this.billingService.getSubscription(auth);
  }

  @Get('invoices')
  getInvoices(@Headers('authorization') auth: string) {
    return this.billingService.getInvoices(auth);
  }

  @Post('portal')
  createPortalSession(@Headers('authorization') auth: string) {
    return this.billingService.createPortalSession(auth);
  }
}
