import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Billing, Invoice } from '../../../shared/services/billing';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';

@Component({
  selector: 'app-invoices',
  imports: [RouterLink, DatePipe, StatusBadge],
  templateUrl: './invoices.html',
  styles: ``,
})
export class Invoices implements OnInit {
  private svc = inject(Billing);
  invoices = signal<Invoice[]>([]);
  loading = signal(true);

  ngOnInit() { this.svc.invoices().subscribe({ next: d => { this.invoices.set(d); this.loading.set(false); }, error: () => this.loading.set(false) }); }
}
