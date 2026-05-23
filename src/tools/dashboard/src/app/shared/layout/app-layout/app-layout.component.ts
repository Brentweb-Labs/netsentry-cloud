import { Component } from '@angular/core';
import { SidebarService } from '../../services/sidebar.service';
import { CommonModule } from '@angular/common';
import { AppSidebarComponent } from '../app-sidebar/app-sidebar.component';
import { BackdropComponent } from '../backdrop/backdrop.component';
import { RouterModule } from '@angular/router';
import { AppHeaderComponent } from '../app-header/app-header.component';
import { Observable, combineLatest } from 'rxjs';
import { map } from 'rxjs/operators';

@Component({
  selector: 'app-layout',
  imports: [
    CommonModule,
    RouterModule,
    AppHeaderComponent,
    AppSidebarComponent,
    BackdropComponent
  ],
  templateUrl: './app-layout.component.html',
})

export class AppLayoutComponent {
  readonly containerClasses$: Observable<string>;

  constructor(public sidebarService: SidebarService) {
    this.containerClasses$ = combineLatest([
      this.sidebarService.isExpanded$,
      this.sidebarService.isHovered$,
      this.sidebarService.isMobileOpen$
    ]).pipe(
      map(([isExpanded, isHovered, isMobileOpen]) => {
        const classes = [
          'flex-1',
          'transition-all',
          'duration-300',
          'ease-in-out'
        ];
        
        if (isExpanded || isHovered) {
          classes.push('xl:ml-[290px]');
        } else {
          classes.push('xl:ml-[90px]');
        }
        
        if (!isMobileOpen) {
          classes.push('ml-0');
        }
        
        return classes.join(' ');
      })
    );
  }
}
