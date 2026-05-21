import { Component, AfterViewInit, ElementRef, PLATFORM_ID, Inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Component({
  selector: 'ns-features',
  standalone: true,
  templateUrl: './features.html',
})
export class FeaturesComponent implements AfterViewInit {
  constructor(
    @Inject(PLATFORM_ID) private platformId: object,
    private host: ElementRef<HTMLElement>,
  ) {}

  ngAfterViewInit() {
    if (!isPlatformBrowser(this.platformId)) return;
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => {
        if (e.isIntersecting) {
          (e.target as HTMLElement).classList.add('visible');
          obs.unobserve(e.target);
        }
      }),
      { threshold: 0.08 }
    );
    this.host.nativeElement.querySelectorAll<HTMLElement>('[data-reveal]')
      .forEach(el => obs.observe(el));
  }

  features = [
    {
      icon: 'shield', eyebrow: 'Core engine',
      title: 'Rust-native packet processing',
      description: 'Built on Tokio async runtime for zero-copy packet capture via libpcap. A local DashMap cache short-circuits repeat offenders in microseconds without any cloud round-trip.',
    },
    {
      icon: 'radar', eyebrow: 'Deep inspection',
      title: 'Suricata IDS integration',
      description: "Natively consumes Suricata's eve.json event stream. Dynamic detection rules pushed from the cloud are applied to the sensor live — no service restart required.",
    },
    {
      icon: 'tunnel', eyebrow: 'Zero-config connectivity',
      title: 'WireGuard outbound tunnel',
      description: 'The sensor initiates an outbound WireGuard VPN tunnel to your cloud console. No inbound ports, no NAT rules, no firewall changes on your perimeter.',
    },
    {
      icon: 'lock', eyebrow: 'Automatic enforcement',
      title: 'iptables-level blocking',
      description: 'When a threat is confirmed, the cloud generates an iptables rule and pushes it to the edge sensor in real time. Blocking happens at the Pi — the only node on the wire.',
    },
    {
      icon: 'failsafe', eyebrow: 'Resilience by design',
      title: 'Fail-open bridge mode',
      description: 'The sensor runs as a transparent br0 bridge. If the cloud is unreachable, traffic passes through normally. Only actively flagged IPs are dropped from the local cache.',
    },
    {
      icon: 'chart', eyebrow: 'Full observability',
      title: 'Real-time management console',
      description: 'Live WebSocket telemetry streams threat events, blocked IPs, packet rates, and hardware metrics to the Angular dashboard — updated as events happen.',
    },
  ];
}
