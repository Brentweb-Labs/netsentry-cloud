import { Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Billing, Subscription } from '../../../shared/services/billing';

interface Tier { id: 'community'|'pro'|'enterprise'; name: string; price: string; features: string[]; }

@Component({
  selector: 'app-plan',
  imports: [RouterLink],
  templateUrl: './plan.html',
  styles: ``,
})
export class Plan implements OnInit {
  private svc = inject(Billing);
  sub = signal<Subscription|null>(null);

  readonly tiers: Tier[] = [
    { id:'community', name:'Community', price:'Free',
      features:['1 site','2 sensors','Community support','Basic detection'] },
    { id:'pro',       name:'Pro',       price:'€39/mo',
      features:['Unlimited sites','Unlimited sensors','Email alerts','Advanced detection','PDF reports','Priority support'] },
    { id:'enterprise',name:'Enterprise',price:'Custom',
      features:['Everything in Pro','SSO / SAML','Custom SLA','Dedicated support','On-premise option'] },
  ];

  ngOnInit() { this.svc.subscription().subscribe({ next: s => this.sub.set(s) }); }

  select() { this.svc.portalSession().subscribe({ next: s => window.open(s.url, '_blank') }); }
}
