import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Sensor {
  sensorId: string;
  name: string;
  tenantId: string;
  siteId?: string;
  status: 'pending' | 'active' | 'inactive' | 'revoked';
  lastConnectedAt?: string;
  publicIp?: string;
  location?: string;
  hardwareInfo?: {
    model: string;
    os: string;
    suricataVersion: string;
  };
  autoBlockEnabled: boolean;
  config?: {
    autoBlockEnabled: boolean;
    blockDurationHours: number;
    minThreatLevel: number;
    whitelist: string[];
    monitoredPaths: string[];
  };
  eventsCount: number;
  alertsCount: number;
  createdAt: string;
}

export interface CreateSensorRequest {
  name: string;
  siteId?: string;
  location?: string;
  hardwareInfo?: {
    model: string;
    os: string;
    suricataVersion: string;
  };
}

export interface SensorRegistrationResponse {
  sensorId: string;
  apiKey: string;
  name: string;
  status: string;
}

const BASE = '/api/sensors';

@Injectable({ providedIn: 'root' })
export class Sensors {
  private http = inject(HttpClient);

  list(): Observable<Sensor[]> {
    return this.http.get<Sensor[]>(BASE);
  }

  get(id: string): Observable<Sensor> {
    return this.http.get<Sensor>(`${BASE}/${id}`);
  }

  create(data: CreateSensorRequest): Observable<SensorRegistrationResponse> {
    return this.http.post<SensorRegistrationResponse>(BASE, data);
  }

  update(id: string, data: Partial<Sensor>): Observable<Sensor> {
    return this.http.put<Sensor>(`${BASE}/${id}`, data);
  }

  revoke(id: string): Observable<{ revoked: boolean; sensorId: string }> {
    return this.http.delete<{ revoked: boolean; sensorId: string }>(`${BASE}/${id}`);
  }

  regenerateKey(id: string): Observable<{ apiKey: string }> {
    return this.http.post<{ apiKey: string }>(`${BASE}/${id}/regenerate-key`, {});
  }
}
