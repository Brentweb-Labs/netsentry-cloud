import { Component, inject, signal, OnInit } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SystemService, ServiceInfo } from '../../../shared/services/system';
import { ConfirmModal } from '../../../shared/components/confirm-modal/confirm-modal';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';

@Component({
  selector: 'app-services',
  imports: [RouterLink, ConfirmModal, StatusBadge],
  templateUrl: './services.html',
  styles: ``,
})
export class Services implements OnInit {
  private svc = inject(SystemService);

  services = signal<ServiceInfo[]>([]);
  loading = signal(true);
  restarting = signal<string | null>(null);
  pendingRestart = signal<string | null>(null);

  ngOnInit() {
    this.svc.services().subscribe({
      next: s => { this.services.set(s); this.loading.set(false); },
      error: () => this.loading.set(false),
    });
  }

  memoryPct(s: ServiceInfo): number {
    return s.memory_limit_mb > 0 ? Math.round((s.memory_mb / s.memory_limit_mb) * 100) : 0;
  }

  formatUptime(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
  }

  promptRestart(name: string) {
    this.pendingRestart.set(name);
    (document.getElementById('restart-modal') as HTMLDialogElement)?.showModal();
  }

  onRestartConfirmed() {
    const name = this.pendingRestart();
    if (!name) return;
    this.restarting.set(name);
    this.svc.restart(name).subscribe({
      next: () => { this.restarting.set(null); this.pendingRestart.set(null); },
      error: () => { this.restarting.set(null); this.pendingRestart.set(null); },
    });
  }

  statusForService(s: ServiceInfo): 'online' | 'degraded' | 'offline' {
    if (s.status === 'running') return 'online';
    if (s.status === 'starting') return 'degraded';
    return 'offline';
  }

  barColor(pct: number): string {
    if (pct >= 90) return 'progress-error';
    if (pct >= 70) return 'progress-warning';
    return 'progress-primary';
  }
}
