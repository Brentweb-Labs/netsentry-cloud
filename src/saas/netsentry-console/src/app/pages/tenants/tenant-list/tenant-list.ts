import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Tenant, TenantService } from '../../../shared/services/tenant';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';
import { EmptyState } from '../../../shared/components/empty-state/empty-state';

@Component({
  selector: 'app-tenant-list',
  imports: [RouterLink, DatePipe, StatusBadge, EmptyState],
  templateUrl: './tenant-list.html',
  styles: ``,
})
export class TenantList implements OnInit {
  private svc = inject(TenantService);
  tenants = signal<Tenant[]>([]);
  loading = signal(true);

  ngOnInit() { this.svc.list().subscribe({ next: d => { this.tenants.set(d); this.loading.set(false); }, error: () => this.loading.set(false) }); }
}
