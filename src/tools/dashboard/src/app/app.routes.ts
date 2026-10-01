import { Routes } from '@angular/router';
import { AppLayoutComponent } from './shared/layout/app-layout/app-layout.component';
import { SignInComponent } from './pages/auth-pages/sign-in/sign-in.component';
import { NotFoundComponent } from './pages/other-page/not-found/not-found.component';
import { OverviewComponent } from './pages/overview/overview.component';
import { AlertsComponent } from './pages/alerts/alerts.component';
import { BlockedComponent } from './pages/blocked/blocked.component';
import { SensorsComponent } from './pages/sensors/sensors.component';
import { SettingsComponent } from './pages/settings/settings.component';
import { authGuard } from './shared/guards/auth.guard';

export const routes: Routes = [
  {
    path: '',
    component: AppLayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'overview', pathMatch: 'full' },
      { path: 'overview', component: OverviewComponent, title: 'Overview | NetSentry' },
      { path: 'alerts', component: AlertsComponent, title: 'Alerts | NetSentry' },
      { path: 'blocked', component: BlockedComponent, title: 'Blocked IPs | NetSentry' },
      { path: 'sensors', component: SensorsComponent, title: 'Sensors | NetSentry' },
      { path: 'settings', component: SettingsComponent, title: 'Settings | NetSentry' },
    ],
  },
  { path: 'signin', component: SignInComponent, title: 'Sign In | NetSentry' },
  { path: '**', component: NotFoundComponent, title: 'Not Found | NetSentry' },
];
