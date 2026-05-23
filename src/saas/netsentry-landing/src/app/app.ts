import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { NavComponent } from './components/nav/nav';
import { HeroComponent } from './components/hero/hero';
import { FeaturesComponent } from './components/features/features';
import { ArchitectureComponent } from './components/architecture/architecture';
import { PricingComponent } from './components/pricing/pricing';
import { CtaComponent } from './components/cta/cta';
import { FooterComponent } from './components/footer/footer';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet,
    NavComponent,
    HeroComponent,
    FeaturesComponent,
    ArchitectureComponent,
    PricingComponent,
    CtaComponent,
    FooterComponent,
  ],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {}
