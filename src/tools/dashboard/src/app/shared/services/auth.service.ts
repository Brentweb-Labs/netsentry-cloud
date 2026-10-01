import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

interface LoginResponse {
  access_token: string;
  role: string;
  tenant_id: string;
}

export interface TokenClaims {
  sub: string;
  email: string;
  role: string;
  tenantId: string;
  exp: number;
}

const TOKEN_KEY = 'netsentry_token';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(
    private http: HttpClient,
    private router: Router,
  ) {}

  login(email: string, password: string): Observable<LoginResponse> {
    return this.http
      .post<LoginResponse>(`${environment.apiUrl}/auth/login`, { email, password })
      .pipe(tap((res) => localStorage.setItem(TOKEN_KEY, res.access_token)));
  }

  logout(): void {
    localStorage.removeItem(TOKEN_KEY);
    this.router.navigate(['/signin']);
  }

  getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  }

  claims(): TokenClaims | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(b64)) as TokenClaims;
    } catch {
      return null;
    }
  }

  isAuthenticated(): boolean {
    const c = this.claims();
    return !!c && c.exp * 1000 > Date.now();
  }

  /** Viewers are read-only in the API; hide write controls for them. */
  canWrite(): boolean {
    const role = this.claims()?.role;
    return !!role && role !== 'viewer';
  }

  canAdmin(): boolean {
    const role = this.claims()?.role;
    return role === 'platform_admin' || role === 'tenant_admin';
  }

  email(): string {
    return this.claims()?.email ?? '';
  }
}
