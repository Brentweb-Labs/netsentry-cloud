import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'ns-pricing',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './pricing.html',
})
export class PricingComponent {
  annual = signal(true);

  plans = [
    {
      name: 'Open Source',
      price: { monthly: 0, annual: 0 },
      description: 'Self-hosted. Full sensor + cloud stack on your own infrastructure.',
      cta: 'Deploy now',
      ctaHref: 'https://github.com/brentschoenmakers/netsentry-sensor',
      accent: '#00ffa3',
      featured: false,
      features: [
        'Rust sensor — unlimited traffic',
        'Suricata IDS integration',
        'WireGuard tunneling',
        'iptables auto-enforcement',
        'Angular dashboard',
        'Community support',
      ],
    },
    {
      name: 'Cloud',
      price: { monthly: 39, annual: 31 },
      description: 'Managed cloud console. Connect your own sensor, we handle the rest.',
      cta: 'Start free trial',
      ctaHref: '#',
      accent: '#7c3aed',
      featured: true,
      features: [
        'Everything in Open Source',
        'Managed VPS cloud console',
        'Automatic SSL + Traefik routing',
        'Real-time threat intelligence',
        'MongoDB managed storage',
        'Grafana + Prometheus included',
        'Email + SMS alerting',
        'PDF compliance reports',
        'Priority support',
      ],
    },
    {
      name: 'Enterprise',
      price: { monthly: 0, annual: 0 },
      description: 'Multi-site deployments, custom integrations, dedicated SLA.',
      cta: 'Contact us',
      ctaHref: 'mailto:hello@netsentry.io',
      accent: '#f59e0b',
      featured: false,
      features: [
        'Everything in Cloud',
        'Multi-sensor fleet management',
        'Custom detection rules',
        'SIEM integration',
        'Dedicated cloud region',
        'Custom SLA & support',
      ],
    },
  ];
}
