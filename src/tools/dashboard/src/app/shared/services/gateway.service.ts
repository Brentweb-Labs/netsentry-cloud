import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface Alert {
  id: string;
  ts: string;
  sensor_id: string;
  src_ip?: string;
  dest_ip?: string;
  offender_ip?: string;
  signature: string;
  category: string;
  severity: number;
  severity_label: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  decision: string;
}

export interface Block {
  id: string;
  ip: string;
  reason: string;
  severity: number;
  source: string;
  status: 'pending' | 'active' | 'expired' | 'rejected' | 'removed';
  auto: boolean;
  created_at: string;
  expires_at: string;
  sensor_id?: string;
}

export interface Sensor {
  sensorId: string;
  name: string;
  hostname?: string;
  arch?: string;
  mode?: 'span' | 'inline';
  status: string;
  online: boolean;
  lastConnectedAt?: string;
  createdAt?: string;
}

export interface Overview {
  events_24h: number;
  alerts_24h: number;
  alerts_by_severity: Record<'critical' | 'high' | 'medium' | 'low', number>;
  blocked: { active: number; pending: number };
  sensors: { total: number; online: number };
  top_sources: { key: string; count: number }[];
  alerts_per_hour: { key: string; count: number }[];
  threat_feed: { entries: number; last_refresh: string | null; sources_ok: number; sources_total: number };
}

export interface Settings {
  block_mode: 'manual' | 'auto';
  allowlist: string[];
  block_ttl_hours: number;
  auto_block_max_severity: number;
  propose_max_severity: number;
  max_auto_blocks_per_hour: number;
  brute_force_threshold: number;
  brute_force_window_secs: number;
  monitored_paths: string[];
  threat_intel_enabled: boolean;
}

export interface EnrollmentToken {
  id: string;
  token: string;
  expires_at: string;
  max_uses: number;
}

@Injectable({ providedIn: 'root' })
export class GatewayApi {
  private http = inject(HttpClient);
  private v1 = `${environment.apiUrl}/v1`;

  overview(): Observable<Overview> {
    return this.http.get<Overview>(`${this.v1}/overview`);
  }

  alerts(opts: { page: number; limit: number; severity?: number; ip?: string }) {
    let params = new HttpParams().set('page', opts.page).set('limit', opts.limit);
    if (opts.severity) params = params.set('severity', opts.severity);
    if (opts.ip) params = params.set('ip', opts.ip);
    return this.http.get<{ items: Alert[]; total: number; page: number; limit: number }>(`${this.v1}/alerts`, {
      params,
    });
  }

  blocked(status: string): Observable<{ items: Block[] }> {
    return this.http.get<{ items: Block[] }>(`${this.v1}/blocked`, { params: { status } });
  }

  createBlock(body: { ip: string; reason?: string; duration_hours?: number }): Observable<Block> {
    return this.http.post<Block>(`${this.v1}/blocked`, body);
  }

  approve(id: string): Observable<Block> {
    return this.http.post<Block>(`${this.v1}/blocked/${id}/approve`, {});
  }

  reject(id: string): Observable<Block> {
    return this.http.post<Block>(`${this.v1}/blocked/${id}/reject`, {});
  }

  remove(id: string): Observable<Block> {
    return this.http.delete<Block>(`${this.v1}/blocked/${id}`);
  }

  sensors(): Observable<{ items: Sensor[] }> {
    return this.http.get<{ items: Sensor[] }>(`${this.v1}/sensors`);
  }

  settings(): Observable<Settings> {
    return this.http.get<Settings>(`${this.v1}/settings`);
  }

  saveSettings(s: Settings): Observable<Settings> {
    return this.http.put<Settings>(`${this.v1}/settings`, s);
  }

  createEnrollmentToken(): Observable<EnrollmentToken> {
    return this.http.post<EnrollmentToken>(`${environment.apiUrl}/enrollment-tokens`, {
      label: 'dashboard',
      ttlHours: 24,
      maxUses: 1,
    });
  }
}
