import { Component, inject, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Idps,
  SuricataStatus,
  AlertStatistics,
  ThreatIntel,
  SystemMetrics,
  ConnectionStatus,
  SuricataEvent,
  BlockedIp,
  DetectionEvent,
  DetectionSettings,
  AutoBlockSettings,
  PreventionStats
} from '../../shared/services/idps';

type Tab = 'overview' | 'events' | 'prevention' | 'settings' | 'debug';

@Component({
  selector: 'app-idps',
  standalone: true,
  imports: [CommonModule, FormsModule, DatePipe],
  templateUrl: './idps.html',
  styles: ``,
})
export class IdpsPage implements OnInit, OnDestroy {
  private idps = inject(Idps);

  // Tab management
  activeTab: Tab = 'overview';
  readonly tabs: Tab[] = ['overview', 'events', 'prevention', 'settings', 'debug'];

  // Connection status
  connectionStatus = signal<ConnectionStatus | null>(null);
  isWebSocketConnected = signal(false);

  // Overview data
  suricataStatus = signal<SuricataStatus | null>(null);
  alertStats = signal<AlertStatistics | null>(null);
  threatIntel = signal<ThreatIntel | null>(null);
  systemMetrics = signal<SystemMetrics | null>(null);

  // Events
  events = signal<SuricataEvent[]>([]);
  detectionEvents = signal<DetectionEvent[]>([]);
  eventPage = signal(1);
  eventTypeFilter = signal('');
  eventSearch = signal('');

  // Prevention
  blockedIps = signal<BlockedIp[]>([]);
  preventionStats = signal<PreventionStats | null>(null);
  blockForm = { ip: '', reason: '', durationHours: 24 };
  blockLoading = false;
  unblockLoading = new Set<string>();

  // Settings
  detectionSettings = signal<DetectionSettings | null>(null);
  autoBlockSettings = signal<AutoBlockSettings | null>(null);
  settingsForm: Partial<DetectionSettings> = {};
  settingsSaving = false;
  autoBlockToggling = false;
  newMonitoredPath = '';
  newWhitelistEntry = '';

  // Debug
  edgeDebug = signal<any>(null);
  raspiDebug = signal<any>(null);

  // Loading states
  loading = signal({
    status: true,
    alerts: true,
    threat: true,
    metrics: true,
    events: true,
    connection: true,
    settings: true,
    prevention: true,
    debug: true
  });

  ngOnInit() {
    this.loadOverviewData();
    this.loadDetectionSettings();
  }

  ngOnDestroy() {
    // Cleanup WebSocket if needed
  }

  loadOverviewData() {
    this.loadSuricataStatus();
    this.loadAlertStats();
    this.loadThreatIntel();
    this.loadSystemMetrics();
    this.loadConnectionStatus();
  }

  loadSuricataStatus() {
    this.idps.getSuricataStatus().subscribe({
      next: (data) => { this.suricataStatus.set(data); this.loading.update(l => ({ ...l, status: false })); },
      error: () => this.loading.update(l => ({ ...l, status: false }))
    });
  }

  loadAlertStats() {
    this.idps.getAlertStatistics().subscribe({
      next: (data) => { this.alertStats.set(data); this.loading.update(l => ({ ...l, alerts: false })); },
      error: () => this.loading.update(l => ({ ...l, alerts: false }))
    });
  }

  loadThreatIntel() {
    this.idps.getThreatIntel().subscribe({
      next: (data) => { this.threatIntel.set(data); this.loading.update(l => ({ ...l, threat: false })); },
      error: () => this.loading.update(l => ({ ...l, threat: false }))
    });
  }

  loadSystemMetrics() {
    this.idps.getSystemMetrics().subscribe({
      next: (data) => { this.systemMetrics.set(data); this.loading.update(l => ({ ...l, metrics: false })); },
      error: () => this.loading.update(l => ({ ...l, metrics: false }))
    });
  }

  loadConnectionStatus() {
    this.idps.getConnectionStatus().subscribe({
      next: (data) => { this.connectionStatus.set(data); this.loading.update(l => ({ ...l, connection: false })); },
      error: () => this.loading.update(l => ({ ...l, connection: false }))
    });
  }

  loadEvents(page: number = 1) {
    this.eventPage.set(page);
    this.idps.getEvents(page, 50, this.eventTypeFilter() || undefined, this.eventSearch() || undefined).subscribe({
      next: (r) => { this.events.set(r.data.events); this.loading.update(l => ({ ...l, events: false })); },
      error: () => this.loading.update(l => ({ ...l, events: false }))
    });

    this.idps.getDetectionEvents(page, 50).subscribe({
      next: (r) => { this.detectionEvents.set(r.data); },
    });
  }

  loadPreventionData() {
    this.idps.getBlockedIps().subscribe({
      next: (r) => { this.blockedIps.set(r.data); this.loading.update(l => ({ ...l, prevention: false })); },
      error: () => this.loading.update(l => ({ ...l, prevention: false }))
    });

    this.idps.getPreventionStats().subscribe({
      next: (r) => { this.preventionStats.set(r); },
    });
  }

  loadDetectionSettings() {
    this.idps.getDetectionSettings().subscribe({
      next: (data) => {
        this.detectionSettings.set(data);
        this.settingsForm = { ...data };
        this.loading.update(l => ({ ...l, settings: false }));
      },
      error: () => this.loading.update(l => ({ ...l, settings: false }))
    });

    this.idps.getAutoBlockSettings().subscribe({
      next: (data) => { this.autoBlockSettings.set(data); },
    });
  }

  loadDebugData() {
    this.idps.getEdgeDebug().subscribe({
      next: (data) => { this.edgeDebug.set(data); this.loading.update(l => ({ ...l, debug: false })); },
      error: () => this.loading.update(l => ({ ...l, debug: false }))
    });

    this.idps.getRaspiDebug().subscribe({
      next: (data) => { this.raspiDebug.set(data); },
    });
  }

  // Prevention actions
  blockIp() {
    if (!this.blockForm.ip) return;
    this.blockLoading = true;
    this.idps.blockIp(this.blockForm.ip, this.blockForm.reason, this.blockForm.durationHours).subscribe({
      next: () => {
        this.blockForm = { ip: '', reason: '', durationHours: 24 };
        this.loadPreventionData();
        this.blockLoading = false;
      },
      error: () => { this.blockLoading = false; }
    });
  }

  unblockIp(ip: string) {
    this.unblockLoading.add(ip);
    this.idps.unblockIp(ip).subscribe({
      next: () => {
        this.loadPreventionData();
        this.unblockLoading.delete(ip);
      },
      error: () => { this.unblockLoading.delete(ip); }
    });
  }

  // Settings actions
  saveDetectionSettings() {
    if (!this.settingsForm) return;
    this.settingsSaving = true;
    this.idps.updateDetectionSettings(this.settingsForm).subscribe({
      next: (data) => {
        this.detectionSettings.set(data);
        this.settingsForm = { ...data };
        this.settingsSaving = false;
      },
      error: () => { this.settingsSaving = false; }
    });
  }

  toggleAutoBlock() {
    const current = this.autoBlockSettings()?.enabled ?? false;
    this.autoBlockToggling = true;
    this.idps.setAutoBlock(!current).subscribe({
      next: (data) => {
        this.autoBlockSettings.set(data);
        this.autoBlockToggling = false;
      },
      error: () => { this.autoBlockToggling = false; }
    });
  }

  addMonitoredPath() {
    if (!this.newMonitoredPath) return;
    const current = this.settingsForm.monitored_paths || [];
    if (!current.includes(this.newMonitoredPath)) {
      this.settingsForm = { ...this.settingsForm, monitored_paths: [...current, this.newMonitoredPath] };
    }
    this.newMonitoredPath = '';
  }

  removeMonitoredPath(path: string) {
    const current = this.settingsForm.monitored_paths || [];
    this.settingsForm = { ...this.settingsForm, monitored_paths: current.filter(p => p !== path) };
  }

  addWhitelistEntry() {
    if (!this.newWhitelistEntry) return;
    const current = this.settingsForm.whitelist || [];
    if (!current.includes(this.newWhitelistEntry)) {
      this.settingsForm = { ...this.settingsForm, whitelist: [...current, this.newWhitelistEntry] };
    }
    this.newWhitelistEntry = '';
  }

  removeWhitelistEntry(entry: string) {
    const current = this.settingsForm.whitelist || [];
    this.settingsForm = { ...this.settingsForm, whitelist: current.filter(e => e !== entry) };
  }

  // Debug actions
  refreshRules() {
    this.idps.refreshRules().subscribe({
      next: () => { this.loadDebugData(); }
    });
  }

  // Refresh all data
  refreshData() {
    this.loading.set({
      status: true, alerts: true, threat: true, metrics: true,
      events: true, connection: true, settings: true, prevention: true, debug: true
    });

    if (this.activeTab === 'overview') {
      this.loadOverviewData();
    } else if (this.activeTab === 'events') {
      this.loadEvents(this.eventPage());
    } else if (this.activeTab === 'prevention') {
      this.loadPreventionData();
    } else if (this.activeTab === 'settings') {
      this.loadDetectionSettings();
    } else if (this.activeTab === 'debug') {
      this.loadDebugData();
    }
  }

  // Tab change handler
  onTabChange(tab: Tab) {
    this.activeTab = tab;
    if (tab === 'events' && this.events().length === 0) {
      this.loadEvents();
    } else if (tab === 'prevention' && this.blockedIps().length === 0) {
      this.loadPreventionData();
    } else if (tab === 'debug' && !this.edgeDebug()) {
      this.loadDebugData();
    }
  }
}
