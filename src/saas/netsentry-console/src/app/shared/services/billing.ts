import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Subscription {
  plan: 'community' | 'pro' | 'enterprise';
  status: 'active' | 'past_due' | 'canceled' | 'trialing';
  current_period_end: string; cancel_at_period_end: boolean; amount_eur: number;
  sites_used: number; sites_limit: number;
  sensors_used: number; sensors_limit: number;
  storage_gb_used: number; storage_gb_limit: number;
}

export interface Invoice {
  id: string; number: string; date: string; amount_eur: number;
  status: 'paid' | 'pending' | 'failed'; pdf_url: string;
}

const BASE = '/api/console/billing';

@Injectable({ providedIn: 'root' })
export class Billing {
  private http = inject(HttpClient);

  subscription(): Observable<Subscription>       { return this.http.get<Subscription>(`${BASE}/subscription`); }
  invoices(): Observable<Invoice[]>              { return this.http.get<Invoice[]>(`${BASE}/invoices`); }
  portalSession(): Observable<{ url: string }>   { return this.http.post<{ url: string }>(`${BASE}/portal`, {}); }
}
