import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface AlertStatistics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  by_type: { [key: string]: number };
}

export interface SuricataStatus {
  id: string;
  name: string;
  status: string;
  state: string;
  running: boolean;
  image: string;
  created: string;
  stats: {
    cpu_usage: number;
    memory_usage: number;
    network_throughput: number;
    events_processed: number;
    recent_events: number;
  };
}

export interface ThreatIntel {
  malicious_ips: string[];
  suspicious_domains: string[];
  vulnerabilities: Vulnerability[];
  total_alerts: number;
  unique_ips_count: number;
  unique_domains_count: number;
}

export interface Vulnerability {
  id: string;
  severity: string;
  description: string;
}

export interface NetworkTopology {
  active_nodes: number;
  total_connections: number;
  monitored_ports: number;
  blocked_ips: number;
  total_events: number;
  unique_ips: string[];
}

export interface SystemMetrics {
  cpu_current: number;
  cpu_trend: string;
  memory_current: number;
  memory_trend: string;
  alerts_per_hour: number;
  alerts_trend: string;
  network_throughput_current: number;
  network_trend: string;
  events_processed: number;
  recent_events: number;
  dns_requests: number;
  http_requests: number;
}

export interface BlockedIp {
  ip: string;
  reason: string;
  threat_level: number;
  blocked_at: string;
  expires_at: string;
  source: string;
  dns_names: string[];
  associated_domains: string[];
}

export interface DetectionSettings {
  brute_force_threshold: number;
  brute_force_window_seconds: number;
  block_duration_hours: number;
  monitored_paths: string[];
  auto_block_enabled: boolean;
  dns_enrichment_enabled: boolean;
  whitelist: string[];
  min_alert_level: number;
  updated_at: string;
}

export interface AutoBlockSettings {
  enabled: boolean;
  block_duration_hours: number;
  min_threat_level: number;
  whitelist: string[];
  updated_at: string;
}

export interface DetectionEvent {
  id: string;
  src_ip: string;
  detected_pattern: string;
  path: string;
  request_count: number;
  window_seconds: number;
  triggered_block: boolean;
  timestamp: string;
  dns_names: string[];
}

export interface ConnectionStatus {
  status: string;
  uptime_duration: number;
  uptime_percentage: number;
  last_connected: string | null;
  last_disconnected: string | null;
  total_checks: number;
  successful_checks: number;
  failed_checks: number;
  average_response_time: number;
  response_time_last_check: number;
  consecutive_failures: number;
  longest_uptime: number;
  shortest_downtime: number;
}

export interface SuricataEvent {
  timestamp: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  alert?: {
    signature: string;
    category: string;
    severity: number;
  };
  http?: {
    hostname: string;
    url: string;
    method: string;
    user_agent?: string;
  };
  dns?: {
    query: string;
    type: string;
  };
  tls?: {
    subject: string;
    issuer: string;
  };
}

export interface PreventionStats {
  total_blocked: number;
  active_blocks: number;
  expired_blocks: number;
  auto_blocks: number;
  manual_blocks: number;
}

@Injectable({ providedIn: 'root' })
export class Idps {
  private http = inject(HttpClient);
  private base = '/api';

  // Status & Metrics
  getSuricataStatus(): Observable<SuricataStatus> {
    return this.http.get<SuricataStatus>(`${this.base}/status`);
  }

  getAlertStatistics(): Observable<AlertStatistics> {
    return this.http.get<AlertStatistics>(`${this.base}/alerts/statistics`);
  }

  getThreatIntel(): Observable<ThreatIntel> {
    return this.http.get<ThreatIntel>(`${this.base}/threat-intel`);
  }

  getNetworkTopology(): Observable<NetworkTopology> {
    return this.http.get<NetworkTopology>(`${this.base}/network/topology`);
  }

  getSystemMetrics(): Observable<SystemMetrics> {
    return this.http.get<SystemMetrics>(`${this.base}/metrics`);
  }

  getConnectionStatus(): Observable<ConnectionStatus> {
    return this.http.get<ConnectionStatus>(`${this.base}/vps/connection-status`);
  }

  // Events
  getEvents(page: number = 1, limit: number = 50, eventType?: string, search?: string): Observable<{ data: { events: SuricataEvent[]; page: number; total_pages: number; has_next: boolean; has_prev: boolean } }> {
    let params = `page=${page}&limit=${limit}`;
    if (eventType) params += `&event_type=${eventType}`;
    if (search) params += `&search=${search}`;
    return this.http.get<{ data: { events: SuricataEvent[]; page: number; total_pages: number; has_next: boolean; has_prev: boolean } }>(`${this.base}/events?${params}`);
  }

  getDetectionEvents(page: number = 1, limit: number = 50): Observable<{ data: DetectionEvent[] }> {
    return this.http.get<{ data: DetectionEvent[] }>(`${this.base}/detection/events?page=${page}&limit=${limit}`);
  }

  // Prevention
  getBlockedIps(): Observable<{ data: BlockedIp[] }> {
    return this.http.get<{ data: BlockedIp[] }>(`${this.base}/prevention/blocked`);
  }

  blockIp(ip: string, reason: string, durationHours: number = 24): Observable<{ success: boolean; message: string }> {
    return this.http.post<{ success: boolean; message: string }>(`${this.base}/prevention/block`, { ip, reason, duration_hours: durationHours });
  }

  unblockIp(ip: string): Observable<{ success: boolean }> {
    return this.http.post<{ success: boolean }>(`${this.base}/prevention/unblock`, { ip });
  }

  getPreventionStats(): Observable<PreventionStats> {
    return this.http.get<PreventionStats>(`${this.base}/prevention/stats`);
  }

  // Settings
  getDetectionSettings(): Observable<DetectionSettings> {
    return this.http.get<DetectionSettings>(`${this.base}/settings/detection`);
  }

  updateDetectionSettings(settings: Partial<DetectionSettings>): Observable<DetectionSettings> {
    return this.http.put<DetectionSettings>(`${this.base}/settings/detection`, settings);
  }

  getAutoBlockSettings(): Observable<AutoBlockSettings> {
    return this.http.get<AutoBlockSettings>(`${this.base}/settings/auto-block`);
  }

  setAutoBlock(enabled: boolean): Observable<AutoBlockSettings> {
    return this.http.post<AutoBlockSettings>(`${this.base}/settings/auto-block`, { enabled });
  }

  // Debug
  getEdgeDebug(): Observable<any> {
    return this.http.get<any>(`${this.base}/debug/edge`);
  }

  refreshRules(): Observable<{ success: boolean }> {
    return this.http.post<{ success: boolean }>(`${this.base}/debug/refresh-rules`, {});
  }

  getRaspiDebug(): Observable<any> {
    return this.http.get<any>(`${this.base}/debug/raspi`);
  }
}
