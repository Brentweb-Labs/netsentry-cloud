import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { BillingController } from './billing.controller';
import { BillingService } from './billing.service';

@Module({
  imports: [HttpModule],
  controllers: [BillingController],
  providers: [BillingService],
})
export class BillingModule {}
