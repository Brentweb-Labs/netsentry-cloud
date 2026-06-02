import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export type SiteStatus = 'online' | 'degraded' | 'offline' | 'unknown';

export interface Site {
  _id?: string; id?: string; name: string; location: string; tenant_id: string;
  status: SiteStatus; sensor_count: number; active_sensors: number;
  alerts_last_24h: number; created_at: string; updated_at: string;
}

export interface Sensor {
  id: string; site_id: string; hostname: string; ip_address: string;
  wireguard_status: 'connected' | 'disconnected';
  last_seen: string; firmware_version: string; uptime_percentage: number;
}

const BASE = '/api/console/sites';

@Injectable({ providedIn: 'root' })
export class Sites {
  private http = inject(HttpClient);

  list(): Observable<Site[]>                                          { return this.http.get<Site[]>(BASE); }
  get(id: string): Observable<Site>                                  { return this.http.get<Site>(`${BASE}/${id}`); }
  create(b: Pick<Site,'name'|'location'|'tenant_id'>): Observable<Site> { return this.http.post<Site>(BASE, b); }
  update(id: string, b: Partial<Site>): Observable<Site>             { return this.http.put<Site>(`${BASE}/${id}`, b); }
  remove(id: string): Observable<void>                               { return this.http.delete<void>(`${BASE}/${id}`); }
  sensors(siteId: string): Observable<Sensor[]>                      { return this.http.get<Sensor[]>(`${BASE}/${siteId}/sensors`); }
}
