import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class SystemService {
  private rustApiUrl: string;

  constructor(
    private httpService: HttpService,
    private config: ConfigService,
  ) {
    this.rustApiUrl = config.get<string>('RUST_API_URL') ?? 'http://api-gateway:8080';
  }

  async getServices(authHeader: string) {
    try {
      const res = await firstValueFrom(
        this.httpService.get(`${this.rustApiUrl}/api/system/services`, {
          headers: { Authorization: authHeader },
        }),
      );
      return res.data;
    } catch {
      return { status: 'unavailable', services: [] };
    }
  }

  async getLogs(authHeader: string) {
    try {
      const res = await firstValueFrom(
        this.httpService.get(`${this.rustApiUrl}/api/system/logs`, {
          headers: { Authorization: authHeader },
        }),
      );
      return res.data;
    } catch {
      return { logs: [] };
    }
  }
}
