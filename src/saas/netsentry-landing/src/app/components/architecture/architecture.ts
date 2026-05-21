import { Component, AfterViewInit, ElementRef, PLATFORM_ID, Inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Component({
  selector: 'ns-architecture',
  standalone: true,
  templateUrl: './architecture.html',
})
export class ArchitectureComponent implements AfterViewInit {
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

  steps = [
    { step: '01', title: 'Packet captured passively', description: 'libpcap takes a non-blocking copy of every packet at eth0. The original flows through with zero added latency.' },
    { step: '02', title: 'Local cache check',         description: 'Known-blocked IPs are dropped from the in-memory DashMap in sub-millisecond — no cloud round-trip needed.' },
    { step: '03', title: 'Cloud threat analysis',     description: 'Unknown IPs are streamed over WireGuard to the VPS, which scans for SQLi, XSS, DDoS, port scans and more.' },
    { step: '04', title: 'Rule generated & persisted', description: 'Threats trigger Suricata rule generation, MongoDB storage, and a WebSocket broadcast to all connected sensors.' },
    { step: '05', title: 'iptables enforcement',      description: 'The edge network-filter applies iptables DROP rules immediately. Future packets are stopped at step 2.' },
  ];

  detections = [
    { threat: 'SQL Injection',    method: 'Payload regex scan',       level: 8, action: 'Auto-block' },
    { threat: 'XSS',              method: 'Payload regex scan',       level: 7, action: 'Auto-block' },
    { threat: 'Command Injection', method: 'Payload regex scan',      level: 9, action: 'Auto-block' },
    { threat: 'DDoS / Flood',     method: 'Packet rate per IP',       level: 9, action: 'Auto-block' },
    { threat: 'Port Scan',        method: 'Distinct-port counter',    level: 7, action: 'Auto-block' },
    { threat: 'Shellshock',       method: 'Payload regex scan',       level: 9, action: 'Auto-block' },
  ];
}
