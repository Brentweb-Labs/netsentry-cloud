import { Component, Input } from '@angular/core';

const CLASSES: Record<string, string> = {
  critical: 'bg-error-50 text-error-600 dark:bg-error-500/15 dark:text-error-500',
  high: 'bg-warning-50 text-warning-600 dark:bg-warning-500/15 dark:text-orange-400',
  medium: 'bg-blue-light-50 text-blue-light-500 dark:bg-blue-light-500/15 dark:text-blue-light-500',
  low: 'bg-gray-100 text-gray-700 dark:bg-white/5 dark:text-white/80',
  pending: 'bg-warning-50 text-warning-600 dark:bg-warning-500/15 dark:text-orange-400',
  active: 'bg-error-50 text-error-600 dark:bg-error-500/15 dark:text-error-500',
  online: 'bg-success-50 text-success-600 dark:bg-success-500/15 dark:text-success-500',
};

@Component({
  selector: 'app-badge-label',
  template: `<span
    class="inline-flex items-center px-2.5 py-0.5 text-xs font-medium rounded-full"
    [class]="cls()"
    >{{ label || value }}</span
  >`,
})
export class SeverityBadgeComponent {
  @Input({ required: true }) value = '';
  @Input() label = '';

  cls(): string {
    return CLASSES[this.value] ?? CLASSES['low'];
  }
}
