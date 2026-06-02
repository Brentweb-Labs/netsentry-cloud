import { Component, inject, OnInit, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { Sites } from '../../../shared/services/sites';
import { Tenant, TenantService } from '../../../shared/services/tenant';

type Step = 1|2|3;

@Component({
  selector: 'app-site-new',
  imports: [RouterLink, ReactiveFormsModule],
  templateUrl: './site-new.html',
  styles: ``,
})
export class SiteNew implements OnInit {
  private fb = inject(FormBuilder);
  private svc = inject(Sites);
  private tenantSvc = inject(TenantService);
  private router = inject(Router);

  step = signal<Step>(1);
  tenants = signal<Tenant[]>([]);
  saving = signal(false);
  error = signal('');

  step1 = this.fb.nonNullable.group({ name: ['', Validators.required], location: ['', Validators.required] });
  step2 = this.fb.nonNullable.group({ tenant_id: ['', Validators.required] });

  readonly stepLabels = ['Details', 'Tenant', 'Confirm'];

  ngOnInit() {
    this.tenantSvc.list().subscribe({
      next: t => {
        this.tenants.set(t);
        // Auto-select first tenant if available
        if (t.length === 1) {
          this.step2.patchValue({ tenant_id: t[0]._id || t[0].id || '' });
        }
      }
    });
  }

  getTenantId(t: Tenant): string {
    return (t._id || t.id || '') as string;
  }

  tenantName(): string {
    const tenantId = this.step2.value.tenant_id;
    if (!tenantId) return '';
    return this.tenants().find(t => this.getTenantId(t) === tenantId)?.name ?? '';
  }

  next() {
    if (this.step() === 1 && this.step1.valid) this.step.set(2);
    else if (this.step() === 2 && this.step2.valid) this.step.set(3);
  }

  create() {
    this.saving.set(true); this.error.set('');
    this.svc.create({ ...this.step1.getRawValue(), tenant_id: this.step2.value.tenant_id! }).subscribe({
      next: s => this.router.navigate(['/sites', s._id || s.id]),
      error: e => { this.error.set(e?.error?.message ?? 'Failed to create site'); this.saving.set(false); },
    });
  }
}
