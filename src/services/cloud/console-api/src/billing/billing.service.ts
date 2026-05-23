import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class BillingService {
  private rustApiUrl: string;

  constructor(
    private httpService: HttpService,
    private config: ConfigService,
  ) {
    this.rustApiUrl = config.get<string>('RUST_API_URL') ?? 'http://api-gateway:8080';
  }

  private async proxy(path: string, authHeader: string, method = 'GET', body?: unknown) {
    const res = await firstValueFrom(
      this.httpService.request({
        method,
        url: `${this.rustApiUrl}${path}`,
        headers: { Authorization: authHeader },
        data: body,
      }),
    );
    return res.data;
  }

  getSubscription(auth: string) {
    return this.proxy('/api/billing/subscription', auth);
  }

  getInvoices(auth: string) {
    return this.proxy('/api/billing/invoices', auth);
  }

  createPortalSession(auth: string) {
    return this.proxy('/api/billing/portal', auth, 'POST');
  }
}
