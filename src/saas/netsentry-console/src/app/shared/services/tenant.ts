import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Tenant {
  _id?: string; id?: string; name: string; plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  site_count?: number; user_count?: number; admin_email?: string; created_at?: string; createdAt?: string;
}

export interface TenantUser {
  id: string; email: string; name: string;
  role: 'tenant_admin' | 'operator' | 'viewer';
  status: 'active' | 'invited' | 'deactivated';
  last_login: string | null; created_at: string;
}

export interface ApiKey {
  id: string; name: string; prefix: string; created_at: string; last_used: string | null;
}

const BASE = '/api/console/tenants';

@Injectable({ providedIn: 'root' })
export class TenantService {
  private http = inject(HttpClient);

  list(): Observable<Tenant[]>                                               { return this.http.get<Tenant[]>(BASE); }
  get(id: string): Observable<Tenant>                                       { return this.http.get<Tenant>(`${BASE}/${id}`); }
  create(b: Pick<Tenant,'name'|'plan'> & { admin_email: string }): Observable<Tenant> { return this.http.post<Tenant>(BASE, b); }
  update(id: string, b: Partial<Tenant>): Observable<Tenant>                { return this.http.put<Tenant>(`${BASE}/${id}`, b); }

  users(tid: string): Observable<TenantUser[]>                               { return this.http.get<TenantUser[]>(`${BASE}/${tid}/users`); }
  invite(tid: string, b: Pick<TenantUser,'email'|'name'|'role'>): Observable<TenantUser> {
    return this.http.post<TenantUser>(`${BASE}/${tid}/users`, b);
  }
  deactivate(tid: string, uid: string): Observable<void>                    { return this.http.delete<void>(`${BASE}/${tid}/users/${uid}`); }

  apiKeys(tid: string): Observable<ApiKey[]>                                 { return this.http.get<ApiKey[]>(`${BASE}/${tid}/api-keys`); }
  createApiKey(tid: string, name: string): Observable<ApiKey & { key: string }> {
    return this.http.post<ApiKey & { key: string }>(`${BASE}/${tid}/api-keys`, { name });
  }
  revokeApiKey(tid: string, kid: string): Observable<void>                  { return this.http.delete<void>(`${BASE}/${tid}/api-keys/${kid}`); }
}
