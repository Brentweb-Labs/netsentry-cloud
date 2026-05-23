import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Tenant, TenantUser, ApiKey, TenantService } from '../../../shared/services/tenant';
import { StatusBadge } from '../../../shared/components/status-badge/status-badge';
import { ConfirmModal } from '../../../shared/components/confirm-modal/confirm-modal';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';

type Tab = 'overview'|'users'|'api-keys';

@Component({
  selector: 'app-tenant-detail',
  imports: [RouterLink, DatePipe, StatusBadge, ConfirmModal, ReactiveFormsModule],
  templateUrl: './tenant-detail.html',
  styles: ``,
})
export class TenantDetail implements OnInit {
  private route = inject(ActivatedRoute);
  private svc = inject(TenantService);
  private fb = inject(FormBuilder);

  tenant = signal<Tenant|null>(null);
  users = signal<TenantUser[]>([]);
  apiKeys = signal<ApiKey[]>([]);
  loading = signal(true);
  tab = signal<Tab>('overview');
  deactivateTarget = signal<string|null>(null);
  newKeyVisible = signal(false);

  readonly tabs: { key: Tab; label: string }[] = [
    { key:'overview', label:'Overview' }, { key:'users', label:'Users' }, { key:'api-keys', label:'API Keys' },
  ];

  inviteForm = this.fb.nonNullable.group({
    name:  ['', Validators.required],
    email: ['', [Validators.required, Validators.email]],
    role:  ['viewer' as TenantUser['role'], Validators.required],
  });

  newKeyForm = this.fb.nonNullable.group({ name: ['', Validators.required] });

  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id')!;
    this.svc.get(id).subscribe({
      next: t => { this.tenant.set(t); this.loading.set(false); this.loadUsers(); this.loadKeys(); },
      error: () => this.loading.set(false),
    });
  }

  loadUsers() { const id = this.tenant()!.id; this.svc.users(id).subscribe({ next: d => this.users.set(d) }); }
  loadKeys()  { const id = this.tenant()!.id; this.svc.apiKeys(id).subscribe({ next: d => this.apiKeys.set(d) }); }

  invite() {
    if (this.inviteForm.invalid) return;
    this.svc.invite(this.tenant()!.id, this.inviteForm.getRawValue()).subscribe({ next: () => { this.loadUsers(); this.inviteForm.reset({ role:'viewer' }); } });
  }

  promptDeactivate(uid: string) {
    this.deactivateTarget.set(uid);
    (document.getElementById('deactivate-modal') as HTMLDialogElement)?.showModal();
  }

  deactivate() {
    const uid = this.deactivateTarget();
    if (!uid) return;
    this.svc.deactivate(this.tenant()!.id, uid).subscribe({ next: () => { this.loadUsers(); this.deactivateTarget.set(null); } });
  }

  createKey() {
    if (this.newKeyForm.invalid) return;
    this.svc.createApiKey(this.tenant()!.id, this.newKeyForm.value.name!).subscribe({ next: () => { this.loadKeys(); this.newKeyForm.reset(); this.newKeyVisible.set(false); } });
  }

  revokeKey(kid: string) { this.svc.revokeApiKey(this.tenant()!.id, kid).subscribe({ next: () => this.loadKeys() }); }
}
