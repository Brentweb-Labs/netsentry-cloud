import { Component, EventEmitter, Output, inject, OnInit } from '@angular/core';
import { Auth } from '../../shared/services/auth';

@Component({
  selector: 'app-console-topbar',
  imports: [],
  templateUrl: './console-topbar.html',
  styles: ``,
})
export class ConsoleTopbar implements OnInit {
  @Output() menuToggle = new EventEmitter<void>();

  private auth = inject(Auth);

  get orgId()   { return this.auth.orgId(); }
  get initials(){ return (this.auth.orgId() || 'N').slice(0, 1).toUpperCase(); }
  get roleLabel(){
    return this.auth.role().replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  get isDarkMode(): boolean {
    return document.documentElement.getAttribute('data-theme') === 'night';
  }

  ngOnInit() {
    // Apply saved theme or default to corporate (light)
    this.applySavedTheme();
  }

  private applySavedTheme() {
    const savedTheme = localStorage.getItem('netsentry-theme');
    const theme = savedTheme || 'corporate';
    document.documentElement.setAttribute('data-theme', theme);
  }

  toggleTheme(event: Event) {
    const checkbox = event.target as HTMLInputElement;
    const theme = checkbox.checked ? 'night' : 'corporate';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('netsentry-theme', theme);
  }

  logout() { this.auth.logout(); }
}
