import { Component, EventEmitter, Input, Output } from '@angular/core';
import { RouterLink } from '@angular/router';

export type EmptyStateIcon = 'building' | 'folder' | 'search' | 'document' | 'user' | 'shield' | 'cpu';

@Component({
  selector: 'app-empty-state',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './empty-state.html',
  styles: ``,
})
export class EmptyState {
  @Input() icon: EmptyStateIcon = 'folder';
  @Input() title = 'Nothing here yet';
  @Input() description = '';
  @Input() actionLabel?: string;
  @Input() routerLink?: string;
  @Output() action = new EventEmitter<void>();

  getIconPath(): string {
    const paths: Record<EmptyStateIcon, string> = {
      building: 'M3 21h18M3 10h18M3 7l9-4 9 4M4 10v11m16 0v-8m-4 8v-3m-4 8v-5m-4 8v-2m8-14v7m-4-7v4m-4-4v5m-4-5v2m8 0v7',
      folder: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z',
      search: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
      document: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
      user: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
      shield: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
      cpu: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
    };
    return paths[this.icon];
  }
}
