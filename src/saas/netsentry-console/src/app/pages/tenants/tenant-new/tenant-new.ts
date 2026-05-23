import { Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { TenantService } from '../../../shared/services/tenant';

@Component({
  selector: 'app-tenant-new',
  imports: [RouterLink, ReactiveFormsModule],
  templateUrl: './tenant-new.html',
  styles: ``,
})
export class TenantNew {
  private fb = inject(FormBuilder);
  private svc = inject(TenantService);
  private router = inject(Router);

  form = this.fb.nonNullable.group({
    name:        ['', Validators.required],
    admin_email: ['', [Validators.required, Validators.email]],
    plan:        ['pro' as 'community'|'pro'|'enterprise', Validators.required],
  });

  saving = signal(false);
  error = signal('');

  submit() {
    if (this.form.invalid) return;
    this.saving.set(true); this.error.set('');
    this.svc.create(this.form.getRawValue()).subscribe({
      next: t => this.router.navigate(['/tenants', t.id]),
      error: e => { this.error.set(e?.error?.message ?? 'Failed to create tenant'); this.saving.set(false); },
    });
  }
}
