import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Subscription, timer } from 'rxjs';
import { GatewayApi, Overview } from '../../shared/services/gateway.service';
import { LiveFeed } from '../../shared/services/live-feed.service';
import { SeverityBadgeComponent } from '../../shared/components/common/badge/severity-badge.component';

interface LiveAlert {
  ts: string;
  severity_label: string;
  signature: string;
  offender_ip?: string;
  sensor_id?: string;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

@Component({
  selector: 'app-overview',
  imports: [DatePipe, DecimalPipe, RouterLink, SeverityBadgeComponent],
  template: `
    <div class="mb-6 flex items-center justify-between">
      <h1 class="text-title-sm font-semibold text-gray-800 dark:text-white/90">Overview</h1>
      <span class="text-xs text-gray-500 dark:text-gray-400">Last 24 hours</span>
    </div>

    @if (error()) {
      <div class="mb-4 rounded-lg border border-error-200 bg-error-50 px-4 py-3 text-sm text-error-700">{{ error() }}</div>
    }

    @if (data(); as d) {
      <div class="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div class="card"><p class="label">Events</p><p class="value">{{ d.events_24h | number }}</p></div>
        <div class="card"><p class="label">Alerts</p><p class="value">{{ d.alerts_24h | number }}</p></div>
        <a routerLink="/blocked" class="card">
          <p class="label">Pending approval</p>
          <p class="value" [class.text-warning-600]="d.blocked.pending > 0">{{ d.blocked.pending }}</p>
        </a>
        <a routerLink="/blocked" class="card"><p class="label">Active blocks</p><p class="value">{{ d.blocked.active }}</p></a>
        <a routerLink="/sensors" class="card">
          <p class="label">Sensors online</p>
          <p class="value">{{ d.sensors.online }} <span class="text-base text-gray-400">/ {{ d.sensors.total }}</span></p>
        </a>
      </div>

      <div class="mt-4 grid gap-4 lg:grid-cols-3">
        <div class="card lg:col-span-2">
          <h2 class="heading">Alerts per hour</h2>
          @if (d.alerts_per_hour.length === 0) {
            <p class="empty">No alerts in the last 24 hours.</p>
          } @else {
            <div class="flex h-32 items-end gap-1">
              @for (h of d.alerts_per_hour; track h.key) {
                <div class="flex-1 rounded-t bg-brand-500/80" [style.height.%]="barHeight(h.count)" [title]="(h.key | date: 'short') + ': ' + h.count"></div>
              }
            </div>
          }
        </div>
        <div class="card">
          <h2 class="heading">By severity</h2>
          <ul class="space-y-2 text-sm">
            @for (s of severities; track s) {
              <li class="flex items-center justify-between">
                <app-badge-label [value]="s" />
                <span class="font-medium text-gray-800 dark:text-white/90">{{ d.alerts_by_severity[s] }}</span>
              </li>
            }
          </ul>
        </div>
      </div>

      <div class="mt-4 grid gap-4 lg:grid-cols-3">
        <div class="card">
          <h2 class="heading">Top sources</h2>
          @if (d.top_sources.length === 0) {
            <p class="empty">Nothing yet.</p>
          } @else {
            <table class="w-full text-sm">
              @for (s of d.top_sources; track s.key) {
                <tr class="border-t border-gray-100 dark:border-gray-800">
                  <td class="py-1.5 font-mono text-gray-700 dark:text-gray-300">{{ s.key }}</td>
                  <td class="py-1.5 text-right text-gray-500">{{ s.count }}</td>
                </tr>
              }
            </table>
          }
          <p class="mt-4 text-xs text-gray-500 dark:text-gray-400">
            Threat feed: {{ d.threat_feed.entries | number }} indicators
            @if (d.threat_feed.last_refresh) { (updated {{ d.threat_feed.last_refresh | date: 'short' }}) }
            @else { (not loaded yet) }
          </p>
        </div>
        <div class="card lg:col-span-2">
          <h2 class="heading">Live alerts</h2>
          @if (live().length === 0) {
            <p class="empty">Waiting for alerts...</p>
          } @else {
            <ul class="space-y-2 text-sm">
              @for (a of live(); track $index) {
                <li class="flex items-start gap-3">
                  <app-badge-label [value]="a.severity_label" />
                  <div class="min-w-0">
                    <p class="truncate text-gray-800 dark:text-white/90">{{ a.signature }}</p>
                    <p class="text-xs text-gray-500">{{ a.offender_ip }} {{ a.ts | date: 'mediumTime' }}</p>
                  </div>
                </li>
              }
            </ul>
          }
        </div>
      </div>
    } @else if (!error()) {
      <p class="text-sm text-gray-500">Loading...</p>
    }
  `,
  styles: [
    `
      .card { display: block; border-radius: 1rem; border: 1px solid var(--color-gray-200, #e4e7ec); padding: 1.25rem; background: var(--color-white, #fff); }
      :host-context(.dark) .card { background: var(--color-gray-900, #101828); border-color: var(--color-gray-800, #1d2939); }
      .label { font-size: 0.8rem; color: #667085; }
      .value { margin-top: 0.25rem; font-size: 1.5rem; font-weight: 600; color: #1d2939; }
      :host-context(.dark) .value { color: rgba(255, 255, 255, 0.9); }
      .heading { margin-bottom: 0.75rem; font-weight: 600; color: #1d2939; }
      :host-context(.dark) .heading { color: rgba(255, 255, 255, 0.9); }
      .empty { font-size: 0.875rem; color: #98a2b3; }
    `,
  ],
})
export class OverviewComponent implements OnInit, OnDestroy {
  private api = inject(GatewayApi);
  private feed = inject(LiveFeed);
  private subs = new Subscription();
  private release?: () => void;

  readonly severities = SEVERITIES;
  data = signal<Overview | null>(null);
  live = signal<LiveAlert[]>([]);
  error = signal<string | null>(null);

  ngOnInit() {
    this.subs.add(
      timer(0, 30_000).subscribe(() =>
        this.api.overview().subscribe({
          next: (d) => {
            this.data.set(d);
            this.error.set(null);
          },
          error: () => this.error.set('Could not load the overview.'),
        }),
      ),
    );
    this.release = this.feed.acquire();
    this.subs.add(
      this.feed.messages$.subscribe((m) => {
        if (m.type === 'alert') {
          this.live.update((l) => [m as unknown as LiveAlert, ...l].slice(0, 12));
        }
      }),
    );
  }

  barHeight(count: number): number {
    const max = Math.max(1, ...(this.data()?.alerts_per_hour.map((h) => h.count) ?? [1]));
    return Math.max(4, (count / max) * 100);
  }

  ngOnDestroy() {
    this.subs.unsubscribe();
    this.release?.();
  }
}
