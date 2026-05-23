import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ButtonComponent } from '../../../ui/button/button.component';
import { ApiService } from '../../../../services/api.service';

@Component({
  selector: 'app-billing-plan',
  imports: [ButtonComponent, CommonModule],
  templateUrl: './billing-plan.component.html',
  host: {
    class: 'rounded-2xl border border-gray-200 bg-white xl:w-4/6 dark:border-gray-800 dark:bg-white/[0.03]'
  }
})
export class BillingPlanComponent implements OnInit {
  planName = signal<string>('Loading…');
  active = signal<boolean>(false);
  periodEnd = signal<string | null>(null);
  loading = signal<boolean>(true);

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.getBillingStatus().subscribe({
      next: (res: any) => {
        this.planName.set(res.plan ?? 'None');
        this.active.set(res.active ?? false);
        if (res.current_period_end) {
          this.periodEnd.set(
            new Date(res.current_period_end * 1000).toLocaleDateString()
          );
        }
        this.loading.set(false);
      },
      error: () => {
        this.planName.set('Unknown');
        this.loading.set(false);
      },
    });
  }

  upgrade(): void {
    this.api.createCheckoutSession().subscribe({
      next: (res: any) => {
        if (res.checkout_url) {
          window.location.href = res.checkout_url;
        }
      },
    });
  }
}
