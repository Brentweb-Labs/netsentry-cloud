import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../shared/services/auth.service';
import { GatewayApi, Settings } from '../../shared/services/gateway.service';

@Component({
  selector: 'app-settings',
  imports: [FormsModule],
  template: `
    <h1 class="mb-6 text-title-sm font-semibold text-gray-800 dark:text-white/90">Settings</h1>

    @if (s(); as cfg) {
      <form (ngSubmit)="save()" class="max-w-3xl space-y-8">
        <section>
          <h2 class="heading">Blocking</h2>
          <label class="row">
            <input type="radio" name="mode" value="manual" [(ngModel)]="cfg.block_mode" [disabled]="!canAdmin" />
            <span><b>Manual approval</b> (default): detections create proposals that an operator approves.</span>
          </label>
          <label class="row">
            <input type="radio" name="mode" value="auto" [(ngModel)]="cfg.block_mode" [disabled]="!canAdmin" />
            <span><b>Automatic</b>: the most severe detections are blocked immediately, within the limits below.</span>
          </label>
          <div class="mt-4 grid gap-4 sm:grid-cols-3">
            <label class="field">Block TTL (hours)
              <input type="number" name="ttl" min="1" max="720" [(ngModel)]="cfg.block_ttl_hours" [disabled]="!canAdmin" class="input" /></label>
            <label class="field">Auto-block up to severity
              <select name="autosev" [(ngModel)]="cfg.auto_block_max_severity" [disabled]="!canAdmin" class="input">
                <option [ngValue]="1">1 - critical only</option><option [ngValue]="2">2 - high</option><option [ngValue]="3">3 - medium</option>
              </select></label>
            <label class="field">Max auto-blocks per hour
              <input type="number" name="cap" min="0" max="1000" [(ngModel)]="cfg.max_auto_blocks_per_hour" [disabled]="!canAdmin" class="input" /></label>
          </div>
        </section>

        <section>
          <h2 class="heading">Allowlist (never blocked)</h2>
          <p class="mb-2 text-xs text-gray-500">One IP or CIDR range per line. Private ranges are listed by default.</p>
          <textarea name="allow" rows="5" [ngModel]="join(cfg.allowlist)" (ngModelChange)="cfg.allowlist = lines($event)" [disabled]="!canAdmin" class="input w-full font-mono"></textarea>
        </section>

        <section>
          <h2 class="heading">Brute-force detection</h2>
          <div class="grid gap-4 sm:grid-cols-2">
            <label class="field">Requests before alert
              <input type="number" name="bft" min="3" [(ngModel)]="cfg.brute_force_threshold" [disabled]="!canAdmin" class="input" /></label>
            <label class="field">Window (seconds)
              <input type="number" name="bfw" min="5" max="3600" [(ngModel)]="cfg.brute_force_window_secs" [disabled]="!canAdmin" class="input" /></label>
          </div>
          <label class="field mt-4">Monitored paths (one per line)
            <textarea name="paths" rows="4" [ngModel]="join(cfg.monitored_paths)" (ngModelChange)="cfg.monitored_paths = lines($event)" [disabled]="!canAdmin" class="input w-full font-mono"></textarea></label>
        </section>

        <section>
          <h2 class="heading">Threat intelligence</h2>
          <label class="row">
            <input type="checkbox" name="ti" [(ngModel)]="cfg.threat_intel_enabled" [disabled]="!canAdmin" />
            <span>Raise alerts for traffic involving hosts on the abuse.ch feeds.</span>
          </label>
        </section>

        @if (canAdmin) {
          <button type="submit" class="btn-primary">Save settings</button>
        } @else {
          <p class="text-sm text-gray-500">Only tenant administrators can change settings.</p>
        }
        @if (message()) { <p class="text-sm text-gray-600 dark:text-gray-300">{{ message() }}</p> }
      </form>
    }
  `,
  styles: [
    `
      .heading { margin-bottom: 0.75rem; font-weight: 600; color: #1d2939; }
      :host-context(.dark) .heading { color: rgba(255, 255, 255, 0.9); }
      .row { display: flex; gap: 0.6rem; align-items: flex-start; margin-bottom: 0.5rem; font-size: 0.875rem; }
      .field { display: block; font-size: 0.8rem; color: #667085; }
      .input { display: block; width: 100%; margin-top: 0.25rem; border: 1px solid #d0d5dd; border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.875rem; background: transparent; }
      .btn-primary { background: #465fff; color: #fff; border-radius: 0.5rem; padding: 0.55rem 1.2rem; font-size: 0.875rem; }
    `,
  ],
})
export class SettingsComponent implements OnInit {
  private api = inject(GatewayApi);
  readonly canAdmin = inject(AuthService).canAdmin();
  s = signal<Settings | null>(null);
  message = signal('');

  ngOnInit() {
    this.api.settings().subscribe({ next: (v) => this.s.set(v) });
  }

  join(list: string[]): string {
    return list.join('\n');
  }

  lines(text: string): string[] {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }

  save() {
    const cfg = this.s();
    if (!cfg) return;
    this.message.set('');
    this.api.saveSettings(cfg).subscribe({
      next: (saved) => {
        this.s.set(saved);
        this.message.set('Saved.');
      },
      error: (e) => this.message.set(e?.error?.error ?? 'Saving failed.'),
    });
  }
}
