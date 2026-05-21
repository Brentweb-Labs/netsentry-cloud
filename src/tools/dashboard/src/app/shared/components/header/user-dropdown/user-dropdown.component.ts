import { Component } from '@angular/core';
import { DropdownComponent } from '../../ui/dropdown/dropdown.component';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { DropdownItemTwoComponent } from '../../ui/dropdown/dropdown-item/dropdown-item.component-two';
import { AuthService } from '../../../services/auth.service';

@Component({
  selector: 'app-user-dropdown',
  templateUrl: './user-dropdown.component.html',
  imports: [CommonModule, RouterModule, DropdownComponent, DropdownItemTwoComponent]
})
export class UserDropdownComponent {
  isOpen = false;
  username: string;

  constructor(private auth: AuthService) {
    const token = this.auth.getToken();
    try {
      const payload = JSON.parse(atob(token!.split('.')[1]));
      this.username = payload.sub ?? payload.username ?? 'Admin';
    } catch {
      this.username = 'Admin';
    }
  }

  toggleDropdown() {
    this.isOpen = !this.isOpen;
  }

  closeDropdown() {
    this.isOpen = false;
  }

  signOut() {
    this.auth.logout();
  }
}