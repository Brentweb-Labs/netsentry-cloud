import { Routes } from '@angular/router';
import { authGuard } from './shared/guards/auth-guard';

export const routes: Routes = [
  { path: '', redirectTo: '/sites', pathMatch: 'full' },
  {
    path: 'signin',
    loadComponent: () => import('./pages/auth/sign-in/sign-in').then(m => m.SignIn),
    title: 'Sign In | NetSentry Console',
  },
  {
    path: '',
    loadComponent: () => import('./layout/console-layout/console-layout').then(m => m.ConsoleLayout),
    canActivate: [authGuard],
    children: [
      // Sites
      { path: 'sites',       loadComponent: () => import('./pages/sites/sites-list/sites-list').then(m => m.SitesList),     title: 'Sites | NetSentry' },
      { path: 'sites/new',   loadComponent: () => import('./pages/sites/site-new/site-new').then(m => m.SiteNew),           title: 'New Site | NetSentry' },
      { path: 'sites/:id',   loadComponent: () => import('./pages/sites/site-detail/site-detail').then(m => m.SiteDetail),  title: 'Site | NetSentry' },
      // Payment
      { path: 'payment',          loadComponent: () => import('./pages/payment/billing-overview/billing-overview').then(m => m.BillingOverview), title: 'Billing | NetSentry' },
      { path: 'payment/invoices', loadComponent: () => import('./pages/payment/invoices/invoices').then(m => m.Invoices),                       title: 'Invoices | NetSentry' },
      { path: 'payment/plan',     loadComponent: () => import('./pages/payment/plan/plan').then(m => m.Plan),                                   title: 'Plan | NetSentry' },
      // Tenants
      { path: 'tenants',       loadComponent: () => import('./pages/tenants/tenant-list/tenant-list').then(m => m.TenantList),       title: 'Tenants | NetSentry' },
      { path: 'tenants/new',   loadComponent: () => import('./pages/tenants/tenant-new/tenant-new').then(m => m.TenantNew),          title: 'New Tenant | NetSentry' },
      { path: 'tenants/:id',   loadComponent: () => import('./pages/tenants/tenant-detail/tenant-detail').then(m => m.TenantDetail), title: 'Tenant | NetSentry' },
      // Config
      { path: 'config',              redirectTo: 'config/detection', pathMatch: 'full' },
      { path: 'config/detection',    loadComponent: () => import('./pages/config/detection/detection').then(m => m.Detection),       title: 'Detection | NetSentry' },
      { path: 'config/alerts',       loadComponent: () => import('./pages/config/alert-rules/alert-rules').then(m => m.AlertRules),  title: 'Alert Rules | NetSentry' },
      { path: 'config/integrations', loadComponent: () => import('./pages/config/integrations/integrations').then(m => m.Integrations), title: 'Integrations | NetSentry' },
      // Sensors
      { path: 'sensors',       loadComponent: () => import('./pages/sensors/sensors-list/sensors-list').then(m => m.SensorsList),     title: 'Sensors | NetSentry' },
      { path: 'sensors/:id',   loadComponent: () => import('./pages/sensors/sensor-detail/sensor-detail').then(m => m.SensorDetail),  title: 'Sensor | NetSentry' },
      { path: 'sensors/config/setup', loadComponent: () => import('./pages/sensors/sensor-config/sensor-config').then(m => m.SensorConfig), title: 'Sensor Setup | NetSentry' },
      // IDPS
      { path: 'idps',          loadComponent: () => import('./pages/idps/idps').then(m => m.IdpsPage), title: 'IDPS | NetSentry' },
      // System
      { path: 'system',          redirectTo: 'system/services', pathMatch: 'full' },
      { path: 'system/services', loadComponent: () => import('./pages/system/services/services').then(m => m.Services), title: 'Services | NetSentry' },
      { path: 'system/logs',     loadComponent: () => import('./pages/system/logs/logs').then(m => m.Logs),             title: 'Logs | NetSentry' },
    ],
  },
  {
    path: '**',
    loadComponent: () => import('./pages/not-found/not-found').then(m => m.NotFound),
    title: '404 | NetSentry',
  },
];
