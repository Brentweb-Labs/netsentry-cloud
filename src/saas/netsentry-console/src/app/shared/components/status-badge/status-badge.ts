import { Component, Input } from '@angular/core';
import { NgClass } from '@angular/common';

type Status = 'online'|'offline'|'degraded'|'unknown'|'running'|'stopped'|'error'|'starting'|
              'active'|'suspended'|'pending'|'connected'|'disconnected'|'paid'|'failed'|
              'past_due'|'canceled'|'trialing'|'invited'|'deactivated'|'inactive'|'revoked';

@Component({
  selector: 'app-status-badge',
  imports: [NgClass],
  templateUrl: './status-badge.html',
  styles: ``,
})
export class StatusBadge {
  @Input() status: Status = 'unknown';
  @Input() label?: string;

  get cls(): string {
    const map: Record<string,string> = {
      online:'badge-success', running:'badge-success', active:'badge-success',
      connected:'badge-success', paid:'badge-success',
      degraded:'badge-warning', starting:'badge-warning', pending:'badge-warning',
      trialing:'badge-warning', invited:'badge-warning',
      offline:'badge-error', stopped:'badge-error', error:'badge-error',
      failed:'badge-error', suspended:'badge-error', past_due:'badge-error',
      canceled:'badge-error', disconnected:'badge-ghost', deactivated:'badge-ghost',
    };
    return map[this.status] ?? 'badge-ghost';
  }

  get text(): string { return this.label ?? this.status.replace(/_/g,' '); }
}
