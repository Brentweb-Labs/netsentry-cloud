import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Sensors, Sensor } from '../../../shared/services/sensors';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';

@Component({
  selector: 'app-sensor-detail',
  imports: [RouterLink, StatusBadge, DatePipe],
  templateUrl: './sensor-detail.html',
  styles: ``,
})
export class SensorDetail implements OnInit {
  private route = inject(ActivatedRoute);
  private svc = inject(Sensors);

  sensor = signal<Sensor | null>(null);
  loading = signal(true);
  error = signal<string | null>(null);

  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.svc.get(id).subscribe({
        next: (data) => {
          this.sensor.set(data);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Failed to load sensor');
          this.loading.set(false);
        },
      });
    }
  }
}
