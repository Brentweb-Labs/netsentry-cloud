import { Component, inject, signal, OnInit, ElementRef, ViewChild, AfterViewChecked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { SystemService, LogEntry } from '../../../shared/services/system';

const SERVICES = ['all', 'api-gateway', 'threat-intel', 'vps-processor', 'packet-analyzer', 'log-processor'];
const LEVELS = ['ALL', 'DEBUG', 'INFO', 'WARN', 'ERROR'];

@Component({
  selector: 'app-logs',
  imports: [RouterLink, FormsModule],
  templateUrl: './logs.html',
  styles: ``,
})
export class Logs implements OnInit, AfterViewChecked {
  private svc = inject(SystemService);

  @ViewChild('logContainer') logContainer!: ElementRef<HTMLDivElement>;

  entries = signal<LogEntry[]>([]);
  loading = signal(false);
  autoScroll = signal(true);
  selectedService = signal('all');
  selectedLevel = signal('ALL');
  services = SERVICES;
  levels = LEVELS;

  private shouldScroll = false;

  ngOnInit() { this.fetch(); }

  ngAfterViewChecked() {
    if (this.shouldScroll && this.autoScroll() && this.logContainer) {
      this.logContainer.nativeElement.scrollTop = this.logContainer.nativeElement.scrollHeight;
      this.shouldScroll = false;
    }
  }

  fetch() {
    this.loading.set(true);
    const svc = this.selectedService() === 'all' ? '' : this.selectedService();
    const lvl = this.selectedLevel() === 'ALL' ? undefined : this.selectedLevel();
    this.svc.logs(svc, lvl).subscribe({
      next: e => { this.entries.set(e); this.loading.set(false); this.shouldScroll = true; },
      error: () => this.loading.set(false),
    });
  }

  levelClass(level: string): string {
    switch (level) {
      case 'ERROR': return 'badge-error';
      case 'WARN':  return 'badge-warning';
      case 'DEBUG': return 'badge-ghost';
      default:      return 'badge-info';
    }
  }

  formatTs(ts: string): string {
    return new Date(ts).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
}
