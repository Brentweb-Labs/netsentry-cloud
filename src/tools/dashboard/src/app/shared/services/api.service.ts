import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface ApiResponse<T> {
  success: boolean;
  data: T;
}

// Real Suricata Event structures from eve.json
export interface SuricataEvent {
  timestamp: string;
  flow_id?: number;
  in_iface?: string;
  event_type: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: AlertInfo;
  dns?: DnsInfo;
  http?: HttpInfo;
  tls?: TlsInfo;
  fileinfo?: FileInfo;
  pkt_src?: string;
  ip_v?: number;
}

export interface AlertInfo {
  action?: string;
  gid?: number;
  signature_id?: number;
  rev?: number;
  signature?: string;
  category?: string;
  severity?: number;
}

export interface DnsInfo {
  version?: number;
  type?: string;
  tx_id?: number;
  queries?: DnsQuery[];
}

export interface DnsQuery {
  rrname?: string;
  rrtype?: string;
}

export interface HttpInfo {
  hostname?: string;
  url?: string;
  http_user_agent?: string;
  http_method?: string;
  protocol?: string;
  status?: number;
}

export interface TlsInfo {
  version?: string;
  cipher?: string;
}

export interface FileInfo {
  filename?: string;
  size?: number;
  state?: string;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
  event_type?: string;
}

export interface PaginatedEvents {
  events: SuricataEvent[];
  pagination: PaginationInfo;
}

export interface PaginationInfo {
  total_count: number;
  current_page: number;
  per_page: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface AlertStatistics {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  by_type: { [key: string]: number };
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
  status: string; // "connected", "disconnected", "degraded", "unreachable", "unknown"
  uptime_duration: number; // seconds
  uptime_percentage: number; // 0-100
  last_connected: string | null;
  last_disconnected: string | null;
  total_checks: number;
  successful_checks: number;
  failed_checks: number;
  average_response_time: number; // milliseconds
  response_time_last_check: number; // milliseconds
  consecutive_failures: number;
  longest_uptime: number; // seconds
  shortest_downtime: number; // seconds
}

export interface PaginatedDetectionEvents {
  events: DetectionEvent[];
  pagination: {
    total_count: number;
    current_page: number;
    per_page: number;
    total_pages: number;
  };
}

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private readonly apiUrl = environment.apiUrl;
  private readonly logProcessorUrl = environment.logProcessorUrl;
  private readonly networkFilterUrl = environment.networkFilterUrl;

  constructor(private http: HttpClient) {}

  // Suricata System Status
  getSuricataStatus(): Observable<ApiResponse<SuricataStatus>> {
    return this.http.get<ApiResponse<SuricataStatus>>(`${this.apiUrl}/status`);
  }

  // Real Suricata Events from eve.json
  getSuricataEvents(params?: PaginationParams): Observable<ApiResponse<PaginatedEvents>> {
    let httpParams = new HttpParams();
    if (params) {
      if (params.page) httpParams = httpParams.set('page', params.page.toString());
      if (params.limit) httpParams = httpParams.set('limit', params.limit.toString());
      if (params.event_type) httpParams = httpParams.set('event_type', params.event_type);
    }
    return this.http.get<ApiResponse<PaginatedEvents>>(`${this.apiUrl}/events`, { params: httpParams });
  }

  // Alert Statistics from real Suricata data
  getAlertStatistics(): Observable<ApiResponse<AlertStatistics>> {
    return this.http.get<ApiResponse<AlertStatistics>>(`${this.apiUrl}/alerts/statistics`);
  }

  // Threat Intelligence from real data analysis
  getThreatIntel(): Observable<ApiResponse<ThreatIntel>> {
    return this.http.get<ApiResponse<ThreatIntel>>(`${this.apiUrl}/threat-intel`);
  }

  // Network Topology from real event data
  getNetworkTopology(): Observable<ApiResponse<NetworkTopology>> {
    return this.http.get<ApiResponse<NetworkTopology>>(`${this.apiUrl}/network/topology`);
  }

  // System Metrics from real Suricata activity
  getMetrics(): Observable<ApiResponse<SystemMetrics>> {
    return this.http.get<ApiResponse<SystemMetrics>>(`${this.apiUrl}/metrics`);
  }

  // Get raw eve.json logs
  getEveJsonLogs(): Observable<string> {
    return this.http.get(`${this.apiUrl}/logs/eve.json`, { responseType: 'text' });
  }

  // Suricata Control Commands
  startSuricata(): Observable<any> {
    return this.http.post(`${this.apiUrl}/suricata/start`, {});
  }

  stopSuricata(): Observable<any> {
    return this.http.post(`${this.apiUrl}/suricata/stop`, {});
  }

  restartSuricata(): Observable<any> {
    return this.http.post(`${this.apiUrl}/suricata/restart`, {});
  }

  executeSuricataCommand(command: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/suricata/exec`, { command });
  }

  // Log Processor Service
  getLogProcessorStatus(): Observable<any> {
    return this.http.get(`${this.logProcessorUrl}/health`);
  }

  // Health Check
  healthCheck(): Observable<ApiResponse<any>> {
    return this.http.get<ApiResponse<any>>(`${this.apiUrl}/health`);
  }

  // Prevention API methods
  blockIp(ip: string, reason: string, durationHours?: number): Observable<any> {
    return this.http.post(`${this.networkFilterUrl}/block`, { 
      ip, 
      reason, 
      threat_level: 3,
      duration_hours: durationHours || 24,
      source: 'manual_dashboard'
    });
  }

  unblockIp(ip: string, reason?: string): Observable<any> {
    return this.http.post(`${this.networkFilterUrl}/unblock`, { 
      ip, 
      reason: reason || 'manual_unblock' 
    });
  }

  getBlockedIps(): Observable<BlockedIp[]> {
    return this.http.get<BlockedIp[]>(`${this.networkFilterUrl}/blocked`);
  }

  getPreventionStats(): Observable<any> {
    return this.http.get(`${this.networkFilterUrl}/stats`);
  }

  // Detection Settings
  getDetectionSettings(): Observable<DetectionSettings> {
    return this.http.get<DetectionSettings>(`${this.apiUrl}/settings/detection`);
  }

  updateDetectionSettings(settings: DetectionSettings): Observable<DetectionSettings> {
    return this.http.put<DetectionSettings>(`${this.apiUrl}/settings/detection`, settings);
  }

  // Detection Events
  getDetectionEvents(params?: { page?: number; limit?: number }): Observable<PaginatedDetectionEvents> {
    let httpParams = new HttpParams();
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.limit) httpParams = httpParams.set('limit', params.limit.toString());
    return this.http.get<PaginatedDetectionEvents>(`${this.apiUrl}/detection/events`, { params: httpParams });
  }

  getActiveDetectionEvents(): Observable<DetectionEvent[]> {
    return this.http.get<DetectionEvent[]>(`${this.apiUrl}/detection/active`);
  }

  // Raspi-VPS Connection Status
  getConnectionStatus(): Observable<ApiResponse<ConnectionStatus>> {
    return this.http.get<ApiResponse<ConnectionStatus>>(`${this.apiUrl}/connection/raspi-vps`);
  }

  // Edge device debug state (proxied via api-gateway to raspi-collector)
  getEdgeDebug(): Observable<any> {
    return this.http.get(`${this.apiUrl}/debug/edge`);
  }

  // Auto-block settings
  getAutoBlockSettings(): Observable<AutoBlockSettings> {
    return this.http.get<AutoBlockSettings>(`${this.apiUrl}/settings/auto-block`);
  }

  updateAutoBlockSettings(settings: Partial<AutoBlockSettings>): Observable<AutoBlockSettings> {
    return this.http.put<AutoBlockSettings>(`${this.apiUrl}/settings/auto-block`, settings);
  }

  enableAutoBlock(durationHours?: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/settings/auto-block/enable`, {
      reason: 'Enabled via dashboard',
      duration_hours: durationHours
    });
  }

  disableAutoBlock(): Observable<any> {
    return this.http.post(`${this.apiUrl}/settings/auto-block/disable`, {
      reason: 'Disabled via dashboard'
    });
  }
}
