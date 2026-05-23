import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Sensors, Sensor } from '../../../shared/services/sensors';
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
