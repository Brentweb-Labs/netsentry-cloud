import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-integrations',
  imports: [RouterLink, ReactiveFormsModule],
  templateUrl: './integrations.html',
  styles: ``,
})
export class Integrations {
  private fb = inject(FormBuilder);
  private http = inject(HttpClient);
  saving = signal(false);
  saved = signal(false);

  form = this.fb.nonNullable.group({
    pagerduty_routing_key: [''],
    syslog_host: [''], syslog_port: [514], syslog_protocol: ['udp' as 'udp'|'tcp'],
  });

  save() {
    this.saving.set(true);
    this.http.post('/api/console/config/integrations', this.form.getRawValue()).subscribe({
      next: () => { this.saving.set(false); this.saved.set(true); setTimeout(() => this.saved.set(false), 2000); },
      error: () => this.saving.set(false),
    });
  }
}
