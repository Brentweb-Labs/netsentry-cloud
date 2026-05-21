import { Component } from '@angular/core';

@Component({
  selector: 'ns-footer',
  standalone: true,
  templateUrl: './footer.html',
})
export class FooterComponent {
  year = new Date().getFullYear();

  links = [
    { label: 'Features',  href: '#features' },
    { label: 'How it works', href: '#architecture' },
    { label: 'Pricing',   href: '#pricing' },
    { label: 'GitHub',    href: 'https://github.com/brentschoenmakers/netsentry-sensor', external: true },
    { label: 'Contact',   href: 'mailto:hello@netsentry.io' },
  ];
}
