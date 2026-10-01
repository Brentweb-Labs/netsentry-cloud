import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { SidebarService } from '../../services/sidebar.service';
import { AuthService } from '../../services/auth.service';
import { ThemeToggleButtonComponent } from '../../components/common/theme-toggle/theme-toggle-button.component';

@Component({
  selector: 'app-header',
  imports: [CommonModule, RouterModule, ThemeToggleButtonComponent],
  templateUrl: './app-header.component.html',
})
export class AppHeaderComponent {
  readonly sidebarService = inject(SidebarService);
  readonly auth = inject(AuthService);
  readonly isMobileOpen$ = this.sidebarService.isMobileOpen$;

  handleToggle() {
    if (window.innerWidth >= 1280) {
      this.sidebarService.toggleExpanded();
    } else {
      this.sidebarService.toggleMobileOpen();
    }
  }
}
