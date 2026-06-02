import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';

interface LoginResponse { access_token: string; }

export interface TokenPayload {
  sub: string; tenant_id: string; org_id: string;
  role: 'msp_admin' | 'tenant_admin' | 'operator' | 'viewer'; exp: number;
}

const KEY = 'netsentry_console_token';

@Injectable({ providedIn: 'root' })
export class Auth {
  private http = inject(HttpClient);
  private router = inject(Router);

  login(email: string, password: string): Observable<LoginResponse> {
    return this.http
      .post<LoginResponse>('/api/auth/login', { email, password })
      .pipe(tap(r => localStorage.setItem(KEY, r.access_token)));
  }

  logout(): void { localStorage.removeItem(KEY); this.router.navigate(['/signin']); }

  isAuthenticated(): boolean {
    const p = this.payload();
    return !!p && p.exp * 1000 > Date.now();
  }

  token(): string | null { return localStorage.getItem(KEY); }

  payload(): TokenPayload | null {
    const t = this.token();
    if (!t) return null;
    try { return JSON.parse(atob(t.split('.')[1])) as TokenPayload; } catch { return null; }
  }

  orgId(): string     { return this.payload()?.org_id    ?? ''; }
  role(): string      { return this.payload()?.role      ?? 'viewer'; }
  isMspAdmin(): boolean { return this.payload()?.role === 'msp_admin'; }
}
