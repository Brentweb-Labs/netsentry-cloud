import { Component, signal, HostListener } from '@angular/core';
import { NgStyle } from '@angular/common';
import { ThemeToggleComponent } from '../theme-toggle/theme-toggle';

@Component({
  selector: 'ns-nav',
  standalone: true,
  imports: [NgStyle, ThemeToggleComponent],
  templateUrl: './nav.html',
})
export class NavComponent {
  menuOpen = signal(false);
  scrolled = signal(false);

  @HostListener('window:scroll')
  onScroll() { this.scrolled.set(window.scrollY > 40); }

  toggleMenu() { this.menuOpen.update(v => !v); }

  navLinks = [
    { label: 'Features',     href: '#features' },
    { label: 'How it works', href: '#architecture' },
    { label: 'Pricing',      href: '#pricing' },
    { label: 'Docs',         href: 'https://github.com/brentschoenmakers/netsentry-sensor', external: true },
  ];
}
