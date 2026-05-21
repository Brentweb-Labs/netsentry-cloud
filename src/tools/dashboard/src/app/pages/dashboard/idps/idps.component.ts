import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Subscription } from 'rxjs';
import { ApiService } from '../../../shared/services/api.service';
import { WebsocketService, RealtimeSuricataAlert, RealtimeMetrics } from '../../../shared/services/websocket.service';
import {
  SuricataStatus,
  AlertStatistics,
  ThreatIntel,
  NetworkTopology,
  SystemMetrics,
  SuricataEvent,
  ApiResponse,
  PaginatedEvents,
  BlockedIp,
  DetectionEvent,
  DetectionSettings,
  AutoBlockSettings,
  ConnectionStatus
} from '../../../shared/services/api.service';

type Tab = 'overview' | 'events' | 'prevention' | 'settings' | 'debug';
type ToastType = 'success' | 'error' | 'info';

@Component({
  selector: 'app-idps',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './idps.component.html',
  styleUrls: ['./idps.component.css']
})
export class IdpsComponent implements OnInit, OnDestroy {
  // Active tab
  activeTab: Tab = 'overview';
  readonly tabs: Tab[] = ['overview', 'events', 'prevention', 'settings', 'debug'];

  // Toast notification
  toast: { message: string; type: ToastType; visible: boolean } = {
    message: '', type: 'info', visible: false
  };
  private toastTimer: any = null;

  // Suricata data
  suricataStatus: SuricataStatus | null = null;
  alertStats: AlertStatistics | null = null;
  threatIntel: ThreatIntel | null = null;
  networkTopology: NetworkTopology | null = null;
  systemMetrics: SystemMetrics | null = null;
  recentEvents: SuricataEvent[] = [];
  realtimeAlerts: RealtimeSuricataAlert[] = [];
  realtimeMetrics: RealtimeMetrics | null = null;

  // Raspi-VPS Connection
  connectionStatus: ConnectionStatus | null = null;

  // Prevention
  blockedIps: BlockedIp[] = [];
  preventionStats: any = null;
  blockForm = { ip: '', reason: '', durationHours: 24 };
  blockLoading = false;
  unblockLoading = new Set<string>();

  // Detection events
  detectionEvents: DetectionEvent[] = [];
  detectionEventsLoading = false;

  // Events table filter + search
  eventTypeFilter: string = '';
  eventSearch: string = '';

  // Debug tab state
  edgeDebug: any = null;
  edgeDebugLoading = false;
  edgeDebugError = '';

  // Settings
  detectionSettings: DetectionSettings | null = null;
  autoBlockSettings: AutoBlockSettings | null = null;
  settingsForm: Partial<DetectionSettings> = {};
  settingsSaving = false;
  autoBlockToggling = false;
  newMonitoredPath = '';
  newWhitelistEntry = '';

  // Loading states
  loading = {
    status: true,
    alerts: true,
    threat: true,
    network: true,
    metrics: true,
    events: true,
    connection: true,
    settings: true
  };

  isWebSocketConnected = false;

  private subscriptions = new Subscription();
  private refreshIntervals: any[] = [];

  constructor(
    private apiService: ApiService,
    private http: HttpClient,
    private wsService: WebsocketService
  ) {}

  ngOnInit(): void {
    this.loadSuricataData();
    this.loadConnectionStatus();
    this.loadBlockedIps();
    this.loadPreventionStats();
    this.loadDetectionEvents();
    this.loadSettings();
    this.setupRealtimeListeners();
    this.setupRefreshInterval();
  }

  ngOnDestroy(): void {
    this.subscriptions.unsubscribe();
    this.refreshIntervals.forEach(id => clearInterval(id));
    this.refreshIntervals = [];
    if (this.toastTimer) clearTimeout(this.toastTimer);
  }

  // ─── Toast ────────────────────────────────────────────────────────────────────

  showToast(message: string, type: ToastType = 'info', durationMs = 3500): void {
    if (this.toastTimer) clearTimeout(this.toastTimer);
    this.toast = { message, type, visible: true };
    this.toastTimer = setTimeout(() => { this.toast.visible = false; }, durationMs);
  }

  // ─── Data loading ─────────────────────────────────────────────────────────────

  private loadSuricataData(): void {
    this.loadSuricataStatus();
    this.loadAlertStatistics();
    this.loadThreatIntelligence();
    this.loadNetworkTopology();
    this.loadSystemMetrics();
    this.loadRecentEvents();
  }

  private loadSuricataStatus(): void {
    this.loading.status = true;
    this.subscriptions.add(
      this.apiService.getSuricataStatus().subscribe({
        next: (r) => { this.suricataStatus = r.data; this.loading.status = false; },
        error: () => { this.loading.status = false; }
      })
    );
  }

  private loadAlertStatistics(): void {
    this.loading.alerts = true;
    this.subscriptions.add(
      this.apiService.getAlertStatistics().subscribe({
        next: (r) => { this.alertStats = r.data; this.loading.alerts = false; },
        error: () => { this.loading.alerts = false; }
      })
    );
  }

  private loadThreatIntelligence(): void {
    this.loading.threat = true;
    this.subscriptions.add(
      this.apiService.getThreatIntel().subscribe({
        next: (r) => { this.threatIntel = r.data; this.loading.threat = false; },
        error: () => { this.loading.threat = false; }
      })
    );
  }

  private loadNetworkTopology(): void {
    this.loading.network = true;
    this.subscriptions.add(
      this.apiService.getNetworkTopology().subscribe({
        next: (r) => { this.networkTopology = r.data; this.loading.network = false; },
        error: () => { this.loading.network = false; }
      })
    );
  }

  private loadSystemMetrics(): void {
    this.loading.metrics = true;
    this.subscriptions.add(
      this.apiService.getMetrics().subscribe({
        next: (r) => { this.systemMetrics = r.data; this.loading.metrics = false; },
        error: () => { this.loading.metrics = false; }
      })
    );
  }

  private loadRecentEvents(): void {
    this.loading.events = true;
    this.subscriptions.add(
      this.apiService.getSuricataEvents().subscribe({
        next: (r: ApiResponse<PaginatedEvents>) => {
          this.recentEvents = r.data.events;
          this.loading.events = false;
        },
        error: () => { this.loading.events = false; }
      })
    );
  }

  private loadConnectionStatus(): void {
    this.loading.connection = true;
    this.subscriptions.add(
      this.apiService.getConnectionStatus().subscribe({
        next: (r) => { this.connectionStatus = r.data; this.loading.connection = false; },
        error: () => { this.loading.connection = false; }
      })
    );
  }

  private loadBlockedIps(): void {
    this.subscriptions.add(
      this.apiService.getBlockedIps().subscribe({
        next: (response: any) => {
          this.blockedIps = Array.isArray(response)
            ? response
            : (response?.data || response?.blocked_ips || []);
        },
        error: () => { this.blockedIps = []; }
      })
    );
  }

  loadDetectionEvents(): void {
    this.detectionEventsLoading = true;
    this.subscriptions.add(
      this.apiService.getActiveDetectionEvents().subscribe({
        next: (events) => { this.detectionEvents = events; this.detectionEventsLoading = false; },
        error: () => { this.detectionEventsLoading = false; }
      })
    );
  }

  private loadPreventionStats(): void {
    this.subscriptions.add(
      this.apiService.getPreventionStats().subscribe({
        next: (r: any) => { this.preventionStats = r?.data ?? r ?? {}; },
        error: () => { this.preventionStats = {}; }
      })
    );
  }

  private loadSettings(): void {
    this.loading.settings = true;
    this.subscriptions.add(
      this.apiService.getDetectionSettings().subscribe({
        next: (settings) => {
          this.detectionSettings = settings;
          this.settingsForm = { ...settings };
          this.loading.settings = false;
        },
        error: () => { this.loading.settings = false; }
      })
    );
    this.subscriptions.add(
      this.apiService.getAutoBlockSettings().subscribe({
        next: (settings) => { this.autoBlockSettings = settings; },
        error: () => {}
      })
    );
  }

  // ─── Real-time ────────────────────────────────────────────────────────────────

  private setupRealtimeListeners(): void {
    this.subscriptions.add(
      this.wsService.connectionStatus$.subscribe(connected => {
        this.isWebSocketConnected = connected;
      })
    );
    this.subscriptions.add(
      this.wsService.realtimeAlerts$.subscribe(alert => {
        this.realtimeAlerts.unshift(alert);
        if (this.realtimeAlerts.length > 20) this.realtimeAlerts.pop();
        this.loadAlertStatistics();
      })
    );
    this.subscriptions.add(
      this.wsService.realtimeMetrics$.subscribe(metrics => {
        this.realtimeMetrics = metrics;
        if (this.systemMetrics) {
          this.systemMetrics.cpu_current = metrics.cpu_usage;
          this.systemMetrics.memory_current = metrics.memory_usage;
          this.systemMetrics.network_throughput_current = metrics.network_throughput;
          this.systemMetrics.alerts_per_hour = metrics.alerts_per_minute * 60;
        }
      })
    );
    this.subscriptions.add(
      this.wsService.raspiVpsConnection$.subscribe(status => {
        this.connectionStatus = status;
      })
    );
  }

  private setupRefreshInterval(): void {
    this.refreshIntervals.push(setInterval(() => {
      if (!this.isWebSocketConnected) {
        this.loadSystemMetrics();
        this.loadAlertStatistics();
      }
    }, 30000));
    this.refreshIntervals.push(setInterval(() => this.loadNetworkTopology(), 120000));
    this.refreshIntervals.push(setInterval(() => this.loadBlockedIps(), 60000));
    this.refreshIntervals.push(setInterval(() => this.loadDetectionEvents(), 30000));
    this.refreshIntervals.push(setInterval(() => {
      if (!this.isWebSocketConnected) this.loadConnectionStatus();
    }, 15000));
  }

  // ─── Suricata control ─────────────────────────────────────────────────────────

  startSuricata(): void {
    this.subscriptions.add(
      this.apiService.startSuricata().subscribe({
        next: () => { this.showToast('Suricata started', 'success'); this.loadSuricataStatus(); },
        error: () => this.showToast('Failed to start Suricata', 'error')
      })
    );
  }

  stopSuricata(): void {
    this.subscriptions.add(
      this.apiService.stopSuricata().subscribe({
        next: () => { this.showToast('Suricata stopped', 'info'); this.loadSuricataStatus(); },
        error: () => this.showToast('Failed to stop Suricata', 'error')
      })
    );
  }

  restartSuricata(): void {
    this.subscriptions.add(
      this.apiService.restartSuricata().subscribe({
        next: () => { this.showToast('Suricata restarting…', 'info'); this.loadSuricataStatus(); },
        error: () => this.showToast('Failed to restart Suricata', 'error')
      })
    );
  }

  // ─── Prevention ───────────────────────────────────────────────────────────────

  blockIp(): void {
    const normalized = this.normalizeBlockTarget(this.blockForm.ip);
    if (!normalized || !this.blockForm.reason) {
      this.showToast('Enter a valid IP address or CIDR range and a reason', 'error');
      return;
    }
    this.blockLoading = true;
    this.subscriptions.add(
      this.apiService.blockIp(normalized, this.blockForm.reason, this.blockForm.durationHours).subscribe({
        next: () => {
          this.showToast(`${normalized} blocked — command sent to edge device`, 'success');
          this.blockForm = { ip: '', reason: '', durationHours: 24 };
          this.blockLoading = false;
          this.loadBlockedIps();
          this.loadPreventionStats();
        },
        error: (err: any) => {
          this.showToast(`Failed to block IP: ${err?.error?.error || err?.message || 'Unknown error'}`, 'error');
          this.blockLoading = false;
        }
      })
    );
  }

  unblockIp(ip: string): void {
    this.unblockLoading.add(ip);
    this.subscriptions.add(
      this.apiService.unblockIp(ip, 'Manual unblock via dashboard').subscribe({
        next: () => {
          this.showToast(`${ip} unblocked`, 'success');
          this.unblockLoading.delete(ip);
          this.loadBlockedIps();
          this.loadPreventionStats();
        },
        error: (err: any) => {
          this.showToast(`Failed to unblock ${ip}: ${err?.error?.error || 'Unknown error'}`, 'error');
          this.unblockLoading.delete(ip);
        }
      })
    );
  }

  blockIpFromEvent(event: SuricataEvent): void {
    const normalized = this.normalizeBlockTarget(event.src_ip || '');
    if (!normalized) return;
    const reason = `Alert: ${event.alert?.signature || 'Unknown'}`;
    this.subscriptions.add(
      this.apiService.blockIp(normalized, reason, 24).subscribe({
        next: () => {
          this.showToast(`${normalized} blocked from event`, 'success');
          this.loadBlockedIps();
        },
        error: () => this.showToast(`Failed to block ${normalized}`, 'error')
      })
    );
  }

  // ─── Auto-block ───────────────────────────────────────────────────────────────

  toggleAutoBlock(): void {
    if (!this.autoBlockSettings) return;
    this.autoBlockToggling = true;
    const action$ = this.autoBlockSettings.enabled
      ? this.apiService.disableAutoBlock()
      : this.apiService.enableAutoBlock(this.autoBlockSettings.block_duration_hours);

    this.subscriptions.add(
      action$.subscribe({
        next: () => {
          const nowEnabled = !this.autoBlockSettings!.enabled;
          this.autoBlockSettings!.enabled = nowEnabled;
          this.showToast(`Auto-block ${nowEnabled ? 'enabled' : 'disabled'}`, 'success');
          this.autoBlockToggling = false;
          // Sync detection settings view
          if (this.detectionSettings) this.detectionSettings.auto_block_enabled = nowEnabled;
          if (this.settingsForm) this.settingsForm.auto_block_enabled = nowEnabled;
        },
        error: () => {
          this.showToast('Failed to update auto-block setting', 'error');
          this.autoBlockToggling = false;
        }
      })
    );
  }

  // ─── Detection settings ───────────────────────────────────────────────────────

  saveSettings(): void {
    if (!this.settingsForm) return;
    this.settingsSaving = true;
    const payload: DetectionSettings = {
      brute_force_threshold: Number(this.settingsForm.brute_force_threshold) || 20,
      brute_force_window_seconds: Number(this.settingsForm.brute_force_window_seconds) || 60,
      block_duration_hours: Number(this.settingsForm.block_duration_hours) || 1,
      monitored_paths: this.settingsForm.monitored_paths || [],
      auto_block_enabled: this.settingsForm.auto_block_enabled ?? false,
      dns_enrichment_enabled: this.settingsForm.dns_enrichment_enabled ?? true,
      whitelist: this.settingsForm.whitelist || [],
      min_alert_level: Number(this.settingsForm.min_alert_level) || 5,
      updated_at: new Date().toISOString()
    };
    this.subscriptions.add(
      this.apiService.updateDetectionSettings(payload).subscribe({
        next: (saved) => {
          this.detectionSettings = saved;
          this.settingsForm = { ...saved };
          this.showToast('Detection settings saved', 'success');
          this.settingsSaving = false;
        },
        error: () => {
          this.showToast('Failed to save settings', 'error');
          this.settingsSaving = false;
        }
      })
    );
  }

  addMonitoredPath(): void {
    const path = this.newMonitoredPath.trim();
    if (!path || !path.startsWith('/')) {
      this.showToast('Path must start with /', 'error'); return;
    }
    if (!this.settingsForm.monitored_paths) this.settingsForm.monitored_paths = [];
    if (!this.settingsForm.monitored_paths.includes(path)) {
      this.settingsForm.monitored_paths = [...this.settingsForm.monitored_paths, path];
    }
    this.newMonitoredPath = '';
  }

  removeMonitoredPath(path: string): void {
    this.settingsForm.monitored_paths = (this.settingsForm.monitored_paths || []).filter(p => p !== path);
  }

  addWhitelistEntry(): void {
    const entry = this.newWhitelistEntry.trim();
    if (!entry) return;
    if (!this.settingsForm.whitelist) this.settingsForm.whitelist = [];
    if (!this.settingsForm.whitelist.includes(entry)) {
      this.settingsForm.whitelist = [...this.settingsForm.whitelist, entry];
    }
    this.newWhitelistEntry = '';
  }

  removeWhitelistEntry(entry: string): void {
    this.settingsForm.whitelist = (this.settingsForm.whitelist || []).filter(e => e !== entry);
  }

  // ─── Utility ──────────────────────────────────────────────────────────────────

  refreshData(): void {
    this.loadSuricataData();
    this.loadConnectionStatus();
  }

  setTab(tab: Tab): void {
    this.activeTab = tab;
    if (tab === 'debug') this.loadEdgeDebug();
  }

  loadEdgeDebug(): void {
    this.edgeDebugLoading = true;
    this.edgeDebugError = '';
    this.subscriptions.add(
      this.apiService.getEdgeDebug().subscribe({
        next: (data) => { this.edgeDebug = data; this.edgeDebugLoading = false; },
        error: (err: any) => {
          this.edgeDebugError = err?.error?.error || err?.message || 'Failed to reach edge device';
          this.edgeDebugLoading = false;
        }
      })
    );
  }

  reconnectWebSocket(): void {
    this.wsService.reconnect();
  }

  private normalizeBlockTarget(value: string): string | null {
    const trimmed = (value || '').trim();
    // Accept plain IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return trimmed;
    // Accept CIDR
    if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(trimmed)) return trimmed;
    // Extract IPv4 from URL
    try {
      const url = new URL(trimmed);
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) return url.hostname;
    } catch { /* not a URL */ }
    return null;
  }

  isBlockedIp(ip: string | undefined): boolean {
    return !!ip && this.blockedIps.some(b => b.ip === ip);
  }

  getSeverityColor(severity: number): string {
    if (severity === 1) return 'text-red-600 font-semibold';
    if (severity === 2) return 'text-orange-500 font-semibold';
    if (severity === 3) return 'text-yellow-600';
    return 'text-gray-600';
  }

  getAlertSeverityBadge(severity: string): string {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-blue-100 text-blue-800';
    }
  }

  getEventTypeColor(type: string): string {
    switch (type) {
      case 'alert': return 'bg-red-100 text-red-800';
      case 'dns': return 'bg-blue-100 text-blue-800';
      case 'http': return 'bg-green-100 text-green-800';
      case 'tls': return 'bg-purple-100 text-purple-800';
      case 'fileinfo': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  }

  getThreatLevelBadge(level: number): string {
    if (level >= 8) return 'bg-red-100 text-red-800';
    if (level >= 5) return 'bg-orange-100 text-orange-800';
    return 'bg-yellow-100 text-yellow-800';
  }

  getConnectionStatusColor(): string {
    switch (this.connectionStatus?.status) {
      case 'connected': return 'bg-green-100 text-green-800';
      case 'disconnected': return 'bg-red-100 text-red-800';
      case 'degraded': return 'bg-yellow-100 text-yellow-800';
      case 'unreachable': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  }

  getConnectionDotColor(): string {
    switch (this.connectionStatus?.status) {
      case 'connected': return 'bg-green-500';
      case 'disconnected': return 'bg-red-500';
      case 'degraded': return 'bg-yellow-500';
      case 'unreachable': return 'bg-gray-500';
      default: return 'bg-gray-400';
    }
  }

  getConnectionQuality(): string {
    if (!this.connectionStatus) return 'Unknown';
    if (this.connectionStatus.status === 'unreachable') return 'Pi unreachable';
    const { uptime_percentage, average_response_time, consecutive_failures } = this.connectionStatus;
    if (uptime_percentage >= 99 && average_response_time < 500 && consecutive_failures === 0) return 'Excellent';
    if (uptime_percentage >= 95 && average_response_time < 1000 && consecutive_failures <= 1) return 'Good';
    if (uptime_percentage >= 90 && average_response_time < 2000 && consecutive_failures <= 2) return 'Fair';
    return 'Poor';
  }

  formatUptime(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
  }

  formatResponseTime(ms: number): string {
    if (ms < 1) return '<1ms';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  formatTimestamp(ts: string): string {
    return new Date(ts).toLocaleString();
  }

  hasDnsQuery(event: SuricataEvent): boolean {
    return !!(event.dns?.queries && event.dns.queries.length > 0);
  }

  getDnsRrname(event: SuricataEvent): string {
    return event.dns?.queries?.[0]?.rrname || '';
  }

  hasHttpHostname(event: SuricataEvent): boolean {
    return !!event.http?.hostname;
  }

  getHttpHostname(event: SuricataEvent): string {
    return event.http?.hostname || '';
  }

  get filteredEvents(): SuricataEvent[] {
    let events = this.recentEvents;
    if (this.eventTypeFilter) events = events.filter(e => e.event_type === this.eventTypeFilter);
    const q = this.eventSearch.trim().toLowerCase();
    if (!q) return events;
    return events.filter(e =>
      (e.src_ip || '').includes(q) ||
      (e.dest_ip || '').includes(q) ||
      (e.alert?.signature || '').toLowerCase().includes(q) ||
      (e.alert?.category || '').toLowerCase().includes(q) ||
      (e.http?.hostname || '').toLowerCase().includes(q) ||
      (e.http?.url || '').toLowerCase().includes(q) ||
      (e.dns?.queries?.[0]?.rrname || '').toLowerCase().includes(q) ||
      (e.proto || '').toLowerCase().includes(q)
    );
  }

  getEventHost(event: SuricataEvent): string {
    if (event.http?.hostname) return event.http.hostname;
    if (event.dns?.queries?.[0]?.rrname) return event.dns.queries[0].rrname;
    return '';
  }

  get eventTypes(): string[] {
    return [...new Set(this.recentEvents.map(e => e.event_type).filter(Boolean))].sort();
  }

  getTopSourceIPs(): { address: string; count: number }[] {
    const counts: Record<string, number> = {};
    this.recentEvents.forEach(e => { if (e.src_ip) counts[e.src_ip] = (counts[e.src_ip] || 0) + 1; });
    return Object.entries(counts)
      .map(([address, count]) => ({ address, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  getTopPorts(): string[] {
    const counts: Record<string, number> = {};
    this.recentEvents.forEach(e => {
      if (e.dest_port) counts[String(e.dest_port)] = (counts[String(e.dest_port)] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([p]) => p);
  }

  getEventTypeStats(): { type: string; count: number }[] {
    const counts: Record<string, number> = {};
    this.recentEvents.forEach(e => { if (e.event_type) counts[e.event_type] = (counts[e.event_type] || 0) + 1; });
    return Object.entries(counts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count);
  }
}
