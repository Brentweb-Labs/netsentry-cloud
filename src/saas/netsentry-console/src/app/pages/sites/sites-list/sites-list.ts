import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Site, Sites } from '../../../shared/services/sites';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';
import { EmptyState } from '../../../shared/components/empty-state/empty-state';

@Component({
  selector: 'app-sites-list',
  imports: [RouterLink, StatusBadge, EmptyState],
  templateUrl: './sites-list.html',
  styles: ``,
})
export class SitesList implements OnInit {
  private svc = inject(Sites);
  sites = signal<Site[]>([]);
  loading = signal(true);

  ngOnInit() {
    this.svc.list().subscribe({ next: d => { this.sites.set(d); this.loading.set(false); }, error: () => this.loading.set(false) });
  }
}
