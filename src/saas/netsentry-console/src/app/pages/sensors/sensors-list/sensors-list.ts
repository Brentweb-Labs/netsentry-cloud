import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Sensors, Sensor, EnrollmentToken } from '../../../shared/services/sensors';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';
import { EmptyState } from '../../../shared/components/empty-state/empty-state';

@Component({
  selector: 'app-sensors-list',
  imports: [RouterLink, StatusBadge, EmptyState, DatePipe],
  templateUrl: './sensors-list.html',
  styles: ``,
})
export class SensorsList implements OnInit {
  private svc = inject(Sensors);
  sensors = signal<Sensor[]>([]);
  loading = signal(true);
  error = signal<string | null>(null);
  token = signal<EnrollmentToken | null>(null);
  tokenError = signal<string | null>(null);
  copied = signal(false);

  /** One-line sensor install command using the freshly issued token. */
  installCommand(t: EnrollmentToken): string {
    return (
      `curl -fsSL https://raw.githubusercontent.com/Brentweb-Labs/netsentry-sensor/main/install.sh | ` +
      `sudo NETSENTRY_CLOUD_URL=${location.origin} NETSENTRY_ENROLL_TOKEN=${t.token} sh`
    );
  }

  createToken() {
    this.tokenError.set(null);
    this.copied.set(false);
    this.svc.createEnrollmentToken({ label: 'console', ttlHours: 24, maxUses: 1 }).subscribe({
      next: (t) => this.token.set(t),
      error: () => this.tokenError.set('Could not create an enrollment token (tenant admin role required)'),
    });
  }

  copy(text: string) {
    navigator.clipboard?.writeText(text).then(() => this.copied.set(true));
  }

  ngOnInit() {
    this.svc.list().subscribe({
      next: (data) => {
        this.sensors.set(data);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set('Failed to load sensors');
        this.loading.set(false);
      },
    });
  }
}
