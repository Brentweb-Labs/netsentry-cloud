import { Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { AuthService } from '../../shared/services/auth.service';
import { EnrollmentToken, GatewayApi, Sensor } from '../../shared/services/gateway.service';
import { SeverityBadgeComponent } from '../../shared/components/common/badge/severity-badge.component';

@Component({
  selector: 'app-sensors',
  imports: [DatePipe, SeverityBadgeComponent],
  template: `
    <div class="mb-6 flex items-center justify-between">
      <h1 class="text-title-sm font-semibold text-gray-800 dark:text-white/90">Sensors</h1>
      @if (canAdmin) {
        <button class="btn-primary" (click)="enroll()">Enroll a sensor</button>
      }
    </div>

    @if (token(); as t) {
      <div class="mb-6 rounded-2xl border border-gray-200 p-4 dark:border-gray-800">
        <p class="mb-1 font-semibold text-gray-800 dark:text-white/90">Enrollment token (shown once)</p>
        <p class="mb-2 text-xs text-gray-500">Valid until {{ t.expires_at | date: 'medium' }}. Run on the sensor host:</p>
        <pre class="overflow-x-auto whitespace-pre-wrap break-all rounded bg-gray-100 p-3 text-xs dark:bg-white/5">{{ command(t) }}</pre>
      </div>
    }
    @if (error()) {
      <div class="mb-4 rounded-lg border border-error-200 bg-error-50 px-4 py-2 text-sm text-error-700">{{ error() }}</div>
    }

    <div class="overflow-x-auto rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
      <table class="w-full text-left text-sm">
        <thead class="text-xs uppercase text-gray-500">
          <tr><th class="px-4 py-3">Name</th><th class="px-4 py-3">Mode</th><th class="px-4 py-3">Arch</th><th class="px-4 py-3">State</th><th class="px-4 py-3">Last seen</th></tr>
        </thead>
        <tbody>
          @for (s of items(); track s.sensorId) {
            <tr class="border-t border-gray-100 dark:border-gray-800">
              <td class="px-4 py-2 text-gray-800 dark:text-white/90">{{ s.name }}<span class="block font-mono text-xs text-gray-500">{{ s.sensorId }}</span></td>
              <td class="px-4 py-2">{{ s.mode }}</td>
              <td class="px-4 py-2">{{ s.arch }}</td>
              <td class="px-4 py-2">
                @if (s.online) { <app-badge-label value="online" label="Connected" /> }
                @else { <app-badge-label value="low" [label]="s.status" /> }
              </td>
              <td class="whitespace-nowrap px-4 py-2 text-gray-500">{{ s.lastConnectedAt ? (s.lastConnectedAt | date: 'short') : 'never' }}</td>
            </tr>
          } @empty {
            <tr><td colspan="5" class="px-4 py-8 text-center text-gray-500">No sensors enrolled yet.</td></tr>
          }
        </tbody>
      </table>
    </div>
  `,
  styles: [`.btn-primary { background: #465fff; color: #fff; border-radius: 0.5rem; padding: 0.45rem 1rem; font-size: 0.875rem; }`],
})
export class SensorsComponent implements OnInit {
  private api = inject(GatewayApi);
  readonly canAdmin = inject(AuthService).canAdmin();
  items = signal<Sensor[]>([]);
  token = signal<EnrollmentToken | null>(null);
  error = signal('');

  ngOnInit() {
    this.api.sensors().subscribe({ next: (r) => this.items.set(r.items) });
  }

  enroll() {
    this.error.set('');
    this.api.createEnrollmentToken().subscribe({
      next: (t) => this.token.set(t),
      error: () => this.error.set('Could not create an enrollment token.'),
    });
  }

  command(t: EnrollmentToken): string {
    return (
      'curl -fsSL https://raw.githubusercontent.com/Brentweb-Labs/netsentry-sensor/main/install.sh | ' +
      `sudo NETSENTRY_CLOUD_URL=${location.origin} NETSENTRY_ENROLL_TOKEN=${t.token} sh`
    );
  }
}
