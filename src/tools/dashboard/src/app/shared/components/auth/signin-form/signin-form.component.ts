import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { LabelComponent } from '../../form/label/label.component';
import { ButtonComponent } from '../../ui/button/button.component';
import { InputFieldComponent } from '../../form/input/input-field.component';
import { AuthService } from '../../../services/auth.service';

@Component({
  selector: 'app-signin-form',
  imports: [CommonModule, LabelComponent, ButtonComponent, InputFieldComponent],
  templateUrl: './signin-form.component.html',
  styles: ``
})
export class SigninFormComponent {
  showPassword = false;
  email = '';
  password = '';
  errorMessage = '';
  loading = false;

  constructor(private auth: AuthService, private router: Router) {}

  togglePasswordVisibility() {
    this.showPassword = !this.showPassword;
  }

  onSignIn() {
    if (!this.email || !this.password) {
      this.errorMessage = 'E-mail and password are required.';
      return;
    }
    this.loading = true;
    this.errorMessage = '';
    this.auth.login(this.email.trim(), this.password).subscribe({
      next: () => this.router.navigate(['/overview']),
      error: err => {
        this.errorMessage = err.status === 401
          ? 'Invalid e-mail or password.'
          : 'Login failed. Please try again.';
        this.loading = false;
      }
    });
  }
}
