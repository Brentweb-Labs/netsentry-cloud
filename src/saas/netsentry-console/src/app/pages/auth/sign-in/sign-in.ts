import { Component, inject, signal, OnInit } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Auth } from '../../../shared/services/auth';

@Component({
  selector: 'app-sign-in',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './sign-in.html',
  styles: ``,
})
export class SignIn implements OnInit {
  private fb = inject(FormBuilder);
  private auth = inject(Auth);
  private router = inject(Router);

  currentTheme = 'night';

  form = this.fb.nonNullable.group({
    username: ['', Validators.required],
    password: ['', Validators.required],
  });

  loading = signal(false);
  error = signal('');

  ngOnInit() {
    const savedTheme = localStorage.getItem('netsentry-theme');
    if (savedTheme) {
      this.currentTheme = savedTheme;
    }
    this.applyTheme();
  }

  toggleTheme() {
    this.currentTheme = this.currentTheme === 'night' ? 'corporate' : 'night';
    localStorage.setItem('netsentry-theme', this.currentTheme);
    this.applyTheme();
  }

  private applyTheme() {
    const html = document.documentElement;
    html.setAttribute('data-theme', this.currentTheme);
  }

  submit() {
    if (this.form.invalid) return;
    this.loading.set(true);
    this.error.set('');
    const { username, password } = this.form.getRawValue();
    this.auth.login(username, password).subscribe({
      next: () => this.router.navigate(['/sites']),
      error: (e) => { this.error.set(e?.error?.message ?? 'Invalid credentials'); this.loading.set(false); },
    });
  }
}
