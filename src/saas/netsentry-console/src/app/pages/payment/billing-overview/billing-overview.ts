import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Billing, Subscription } from '../../../shared/services/billing';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';

@Component({
  selector: 'app-billing-overview',
  imports: [RouterLink, DatePipe, StatusBadge],
  templateUrl: './billing-overview.html',
  styles: ``,
})
export class BillingOverview implements OnInit {
  private svc = inject(Billing);
  sub = signal<Subscription|null>(null);
  loading = signal(true);

  ngOnInit() { this.svc.subscription().subscribe({ next: s => { this.sub.set(s); this.loading.set(false); }, error: () => this.loading.set(false) }); }

  pct(used: number, limit: number) { return limit > 0 ? Math.min((used/limit)*100, 100) : 0; }
  meterClass(pct: number) { return pct >= 100 ? 'progress-error' : pct >= 80 ? 'progress-warning' : 'progress-primary'; }

  openPortal() { this.svc.portalSession().subscribe({ next: s => window.open(s.url, '_blank') }); }
}
