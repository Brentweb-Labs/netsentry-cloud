import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-alert-rules',
  imports: [RouterLink, ReactiveFormsModule],
  templateUrl: './alert-rules.html',
  styles: ``,
})
export class AlertRules {
  private fb = inject(FormBuilder);
  private http = inject(HttpClient);
  saving = signal(false);
  saved = signal(false);

  form = this.fb.nonNullable.group({
    smtp_host:    [''],
    smtp_port:    [587],
    smtp_from:    [''],
    slack_webhook:[''],
    webhook_url:  [''],
    webhook_secret:[''],
  });

  save() {
    this.saving.set(true);
    this.http.post('/api/console/config/alerts', this.form.getRawValue()).subscribe({
      next: () => { this.saving.set(false); this.saved.set(true); setTimeout(() => this.saved.set(false), 2000); },
      error: () => this.saving.set(false),
    });
  }
}
