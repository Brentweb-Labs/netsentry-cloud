import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export type ServiceStatus = 'running' | 'stopped' | 'error' | 'starting';

export interface ServiceInfo {
  name: string; display_name: string; status: ServiceStatus;
  version: string; uptime_seconds: number;
  cpu_percent: number; memory_mb: number; memory_limit_mb: number;
}

export interface LogEntry {
  timestamp: string; level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';
  service: string; message: string;
}

const BASE = '/api/console/system';

@Injectable({ providedIn: 'root' })
export class SystemService {
  private http = inject(HttpClient);

  services(): Observable<ServiceInfo[]>    { return this.http.get<ServiceInfo[]>(`${BASE}/services`); }
  restart(name: string): Observable<void>  { return this.http.post<void>(`${BASE}/services/${name}/restart`, {}); }
  logs(service: string, level?: string): Observable<LogEntry[]> {
    const params: Record<string,string> = { service };
    if (level) params['level'] = level;
    return this.http.get<LogEntry[]>(`${BASE}/logs`, { params });
  }
}
