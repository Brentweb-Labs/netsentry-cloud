import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Site, Sensor, Sites } from '../../../shared/services/sites';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';
import { StatCard } from '../../../shared/components/stat-card/stat-card';

type Tab = 'overview'|'sensors'|'alerts'|'config';

@Component({
  selector: 'app-site-detail',
  imports: [RouterLink, DatePipe, StatusBadge, StatCard],
  templateUrl: './site-detail.html',
  styles: ``,
})
export class SiteDetail implements OnInit {
  private route = inject(ActivatedRoute);
  private svc = inject(Sites);

  site = signal<Site|null>(null);
  sensors = signal<Sensor[]>([]);
  loading = signal(true);
  tab = signal<Tab>('overview');

  readonly tabs: { key: Tab; label: string }[] = [
    { key:'overview', label:'Overview' }, { key:'sensors', label:'Sensors' },
    { key:'alerts', label:'Alerts' },     { key:'config', label:'Config' },
  ];

  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id')!;
    this.svc.get(id).subscribe({
      next: s => { this.site.set(s); this.loading.set(false); this.svc.sensors(id).subscribe({ next: d => this.sensors.set(d) }); },
      error: () => this.loading.set(false),
    });
  }
}
