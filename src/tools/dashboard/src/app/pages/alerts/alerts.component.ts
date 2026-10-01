import { Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Alert, GatewayApi } from '../../shared/services/gateway.service';
import { SeverityBadgeComponent } from '../../shared/components/common/badge/severity-badge.component';

@Component({
  selector: 'app-alerts',
  imports: [DatePipe, FormsModule, SeverityBadgeComponent],
  template: `
    <h1 class="mb-6 text-title-sm font-semibold text-gray-800 dark:text-white/90">Alerts</h1>

    <div class="mb-4 flex flex-wrap items-center gap-3">
      <select [(ngModel)]="severity" (ngModelChange)="reload()" class="input">
        <option [ngValue]="0">All severities</option>
        <option [ngValue]="1">Critical</option>
        <option [ngValue]="2">High</option>
        <option [ngValue]="3">Medium</option>
        <option [ngValue]="4">Low</option>
      </select>
      <input [(ngModel)]="ip" (keyup.enter)="reload()" placeholder="Filter by IP" class="input" />
      <button (click)="reload()" class="btn">Apply</button>
    </div>

    <div class="overflow-x-auto rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
      <table class="w-full text-left text-sm">
        <thead class="text-xs uppercase text-gray-500">
          <tr>
            <th class="px-4 py-3">Time</th><th class="px-4 py-3">Severity</th><th class="px-4 py-3">Signature</th>
            <th class="px-4 py-3">Source</th><th class="px-4 py-3">Destination</th><th class="px-4 py-3">Origin</th><th class="px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody>
          @for (a of items(); track a.id) {
            <tr class="border-t border-gray-100 dark:border-gray-800">
              <td class="whitespace-nowrap px-4 py-2 text-gray-500">{{ a.ts | date: 'short' }}</td>
              <td class="px-4 py-2"><app-badge-label [value]="a.severity_label" /></td>
              <td class="max-w-md px-4 py-2 text-gray-800 dark:text-white/90">
                {{ a.signature }}<span class="block text-xs text-gray-500">{{ a.category }}</span>
              </td>
              <td class="px-4 py-2 font-mono">{{ a.src_ip || a.offender_ip }}</td>
              <td class="px-4 py-2 font-mono">{{ a.dest_ip }}</td>
              <td class="px-4 py-2 text-gray-500">{{ a.source }}</td>
              <td class="px-4 py-2 text-gray-500">{{ decisionLabel(a.decision) }}</td>
            </tr>
          } @empty {
            <tr><td colspan="7" class="px-4 py-8 text-center text-gray-500">{{ loading() ? 'Loading...' : 'No alerts.' }}</td></tr>
          }
        </tbody>
      </table>
    </div>

    <div class="mt-4 flex items-center justify-between text-sm text-gray-500">
      <span>{{ total() }} alerts</span>
      <div class="flex items-center gap-2">
        <button class="btn" [disabled]="page() <= 1" (click)="go(page() - 1)">Previous</button>
        <span>Page {{ page() }}</span>
        <button class="btn" [disabled]="page() * limit >= total()" (click)="go(page() + 1)">Next</button>
      </div>
    </div>
  `,
  styles: [
    `
      .input { border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.875rem; background: transparent; }
      .btn { border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.4rem 0.9rem; font-size: 0.875rem; }
      .btn:disabled { opacity: 0.4; }
    `,
  ],
})
export class AlertsComponent implements OnInit {
  private api = inject(GatewayApi);
  readonly limit = 25;
  items = signal<Alert[]>([]);
  total = signal(0);
  page = signal(1);
  loading = signal(true);
  severity = 0;
  ip = '';

  ngOnInit() {
    this.load();
  }

  reload() {
    this.page.set(1);
    this.load();
  }

  go(p: number) {
    this.page.set(p);
    this.load();
  }

  decisionLabel(d: string): string {
    return (
      { auto_blocked: 'Auto-blocked', block_proposed: 'Block proposed', alert_only: 'Alert only', protected: 'Protected' }[d] ??
      ''
    );
  }

  private load() {
    this.loading.set(true);
    this.api
      .alerts({ page: this.page(), limit: this.limit, severity: this.severity || undefined, ip: this.ip.trim() || undefined })
      .subscribe({
        next: (r) => {
          this.items.set(r.items);
          this.total.set(r.total);
          this.loading.set(false);
        },
        error: () => this.loading.set(false),
      });
  }
}
