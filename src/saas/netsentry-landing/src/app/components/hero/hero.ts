import { Component } from '@angular/core';

@Component({
  selector: 'ns-hero',
  standalone: true,
  templateUrl: './hero.html',
})
export class HeroComponent {
  stats = [
    { value: '<1ms',  label: 'Detection latency' },
    { value: '99.9%', label: 'Uptime SLA' },
    { value: '10Gbps', label: 'Max throughput' },
    { value: 'Zero',  label: 'Firewall changes' },
  ];

  trust = [
    { label: 'Open source' },
    { label: 'MIT licensed' },
    { label: 'Self-hostable' },
  ];
}
