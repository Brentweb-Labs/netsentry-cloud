import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { AuthService } from '../../shared/services/auth.service';
import { Block, GatewayApi } from '../../shared/services/gateway.service';
import { LiveFeed } from '../../shared/services/live-feed.service';
import { SeverityBadgeComponent } from '../../shared/components/common/badge/severity-badge.component';

type Tab = 'pending' | 'active' | 'all';

@Component({
  selector: 'app-blocked',
  imports: [DatePipe, FormsModule, SeverityBadgeComponent],
  template: `
    <h1 class="mb-2 text-title-sm font-semibold text-gray-800 dark:text-white/90">Blocked IPs</h1>
    <p class="mb-6 text-sm text-gray-500 dark:text-gray-400">
      Detections create proposals that need approval unless automatic blocking is enabled in Settings. Every block expires
      after its TTL.
    </p>

    <div class="mb-4 flex gap-2">
      @for (t of tabs; track t.id) {
        <button (click)="select(t.id)" class="tab" [class.tab-active]="tab() === t.id">{{ t.label }}</button>
      }
    </div>

    @if (message()) {
      <div class="mb-4 rounded-lg border border-gray-200 px-4 py-2 text-sm dark:border-gray-800">{{ message() }}</div>
    }

    <div class="overflow-x-auto rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
      <table class="w-full text-left text-sm">
        <thead class="text-xs uppercase text-gray-500">
          <tr><th class="px-4 py-3">IP</th><th class="px-4 py-3">Reason</th><th class="px-4 py-3">Status</th><th class="px-4 py-3">Expires</th><th class="px-4 py-3"></th></tr>
        </thead>
        <tbody>
          @for (b of items(); track b.id) {
            <tr class="border-t border-gray-100 dark:border-gray-800">
              <td class="px-4 py-2 font-mono">{{ b.ip }}</td>
              <td class="max-w-md px-4 py-2 text-gray-800 dark:text-white/90">
                {{ b.reason }}<span class="block text-xs text-gray-500">{{ b.source }}{{ b.auto ? ', automatic' : '' }}</span>
              </td>
              <td class="px-4 py-2"><app-badge-label [value]="b.status" /></td>
              <td class="whitespace-nowrap px-4 py-2 text-gray-500">{{ b.expires_at | date: 'short' }}</td>
              <td class="whitespace-nowrap px-4 py-2 text-right">
                @if (canWrite) {
                  @if (b.status === 'pending') {
                    <button class="btn-primary" (click)="act(b, 'approve')">Approve</button>
                    <button class="btn" (click)="act(b, 'reject')">Reject</button>
                  } @else if (b.status === 'active') {
                    <button class="btn" (click)="act(b, 'remove')">Unblock</button>
                  }
                }
              </td>
            </tr>
          } @empty {
            <tr><td colspan="5" class="px-4 py-8 text-center text-gray-500">Nothing here.</td></tr>
          }
        </tbody>
      </table>
    </div>

    @if (canWrite) {
      <form class="mt-6 flex flex-wrap items-end gap-3" (ngSubmit)="blockManually()">
        <div>
          <label class="mb-1 block text-xs text-gray-500">Block an IP manually</label>
          <input name="ip" [(ngModel)]="newIp" required placeholder="203.0.113.9" class="input font-mono" />
        </div>
        <div>
          <label class="mb-1 block text-xs text-gray-500">Reason</label>
          <input name="reason" [(ngModel)]="newReason" placeholder="Manual block" class="input" />
        </div>
        <div>
          <label class="mb-1 block text-xs text-gray-500">Hours</label>
          <input name="hours" type="number" min="1" max="720" [(ngModel)]="newHours" class="input w-24" />
        </div>
        <button type="submit" class="btn-primary">Block</button>
      </form>
    }
  `,
  styles: [
    `
      .tab { border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.4rem 0.9rem; font-size: 0.875rem; }
      .tab-active { background: #465fff; color: #fff; border-color: #465fff; }
      .input { border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.875rem; background: transparent; }
      .btn { border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.3rem 0.8rem; font-size: 0.8rem; margin-left: 0.4rem; }
      .btn-primary { background: #465fff; color: #fff; border-radius: 0.5rem; padding: 0.35rem 0.9rem; font-size: 0.8rem; }
    `,
  ],
})
export class BlockedComponent implements OnInit, OnDestroy {
  private api = inject(GatewayApi);
  private feed = inject(LiveFeed);
  private auth = inject(AuthService);
  private subs = new Subscription();
  private release?: () => void;

  readonly tabs: { id: Tab; label: string }[] = [
    { id: 'pending', label: 'Pending approval' },
    { id: 'active', label: 'Active' },
    { id: 'all', label: 'History' },
  ];
  readonly canWrite = this.auth.canWrite();
  tab = signal<Tab>('pending');
  items = signal<Block[]>([]);
  message = signal('');
  newIp = '';
  newReason = '';
  newHours = 24;

  ngOnInit() {
    this.load();
    this.release = this.feed.acquire();
    this.subs.add(
      this.feed.messages$.subscribe((m) => {
        if (m.type.startsWith('block_')) this.load();
      }),
    );
  }

  select(t: Tab) {
    this.tab.set(t);
    this.load();
  }

  act(b: Block, action: 'approve' | 'reject' | 'remove') {
    const call = action === 'approve' ? this.api.approve(b.id) : action === 'reject' ? this.api.reject(b.id) : this.api.remove(b.id);
    call.subscribe({
      next: () => this.load(),
      error: (e) => this.message.set(e?.error?.error ?? 'Action failed'),
    });
  }

  blockManually() {
    this.message.set('');
    this.api.createBlock({ ip: this.newIp.trim(), reason: this.newReason.trim() || undefined, duration_hours: this.newHours }).subscribe({
      next: () => {
        this.newIp = '';
        this.newReason = '';
        this.tab.set('active');
        this.load();
      },
      error: (e) => this.message.set(e?.error?.error ?? 'Could not block that address'),
    });
  }

  private load() {
    const status = this.tab() === 'all' ? 'all' : this.tab();
    this.api.blocked(status).subscribe({ next: (r) => this.items.set(r.items) });
  }

  ngOnDestroy() {
    this.subs.unsubscribe();
    this.release?.();
  }
}
