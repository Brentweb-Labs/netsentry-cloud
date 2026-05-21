import { Routes } from '@angular/router';
import { IdpsComponent } from './pages/dashboard/idps/idps.component';
import { SettingsComponent } from './pages/settings/settings.component';
import { AppLayoutComponent } from './shared/layout/app-layout/app-layout.component';
import { SignInComponent } from './pages/auth-pages/sign-in/sign-in.component';
import { NotFoundComponent } from './pages/other-page/not-found/not-found.component';
import { authGuard } from './shared/guards/auth.guard';

export const routes: Routes = [
  {
    path: '',
    component: AppLayoutComponent,
    canActivate: [authGuard],
    children: [
      {
        path: '',
        redirectTo: '/idps',
        pathMatch: 'full'
      },
      {
        path: 'idps',
        component: IdpsComponent,
        title: 'IDPS Dashboard | Intrusion Detection and Prevention System',
      },
      {
        path: 'settings',
        component: SettingsComponent,
        title: 'Detection Settings | IDPS',
      },
    ]
  },
  {
    path: 'signin',
    component: SignInComponent,
    title: 'Sign In | IDPS'
  },
  {
    path: '**',
    component: NotFoundComponent,
    title: 'Not Found | IDPS'
  },
];
