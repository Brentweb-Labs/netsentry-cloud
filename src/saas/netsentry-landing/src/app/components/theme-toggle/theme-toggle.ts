import { Component, OnInit, signal, PLATFORM_ID, Inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Component({
  selector: 'ns-theme-toggle',
  standalone: true,
  templateUrl: './theme-toggle.html',
})
export class ThemeToggleComponent implements OnInit {
  isDark = signal(false);

  constructor(@Inject(PLATFORM_ID) private platformId: object) {}

  ngOnInit() {
    if (!isPlatformBrowser(this.platformId)) return;
    const saved = localStorage.getItem('ns-theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const dark = saved ? saved === 'business' : prefersDark;
    this.isDark.set(dark);
    this.apply(dark);
  }

  toggle() {
    const next = !this.isDark();
    this.isDark.set(next);
    this.apply(next);
    if (isPlatformBrowser(this.platformId)) {
      localStorage.setItem('ns-theme', next ? 'business' : 'nord');
    }
  }

  private apply(dark: boolean) {
    if (!isPlatformBrowser(this.platformId)) return;
    document.documentElement.setAttribute('data-theme', dark ? 'business' : 'nord');
  }
}
