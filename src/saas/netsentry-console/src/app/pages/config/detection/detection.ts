import { Component, inject, OnInit, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { HttpClient } from '@angular/common/http';

interface DetectionSettings {
  brute_force_threshold: number; brute_force_window_seconds: number;
  block_duration_hours: number; auto_block_enabled: boolean;
  monitored_paths: string[]; whitelist: string[];
}

@Component({
  selector: 'app-detection',
  imports: [RouterLink, ReactiveFormsModule],
  templateUrl: './detection.html',
  styles: ``,
})
export class Detection implements OnInit {
  private http = inject(HttpClient);
  private fb = inject(FormBuilder);

  form = this.fb.nonNullable.group({
    brute_force_threshold:       [20, [Validators.required, Validators.min(1)]],
    brute_force_window_seconds:  [60, [Validators.required, Validators.min(10)]],
    block_duration_hours:        [1,  [Validators.required, Validators.min(1)]],
    auto_block_enabled:          [false],
    monitored_paths_raw:         ['/login\n/api/auth\n/wp-admin'],
    whitelist_raw:               [''],
  });

  loading = signal(true);
  saving = signal(false);
  saved = signal(false);

  ngOnInit() {
    this.http.get<DetectionSettings>('/api/settings/detection').subscribe({
      next: s => {
        this.form.patchValue({
          ...s,
          monitored_paths_raw: s.monitored_paths.join('\n'),
          whitelist_raw: s.whitelist.join('\n'),
        });
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  save() {
    if (this.form.invalid) return;
    this.saving.set(true);
    const v = this.form.getRawValue();
    const payload: DetectionSettings = {
      brute_force_threshold:      v.brute_force_threshold,
      brute_force_window_seconds: v.brute_force_window_seconds,
      block_duration_hours:       v.block_duration_hours,
      auto_block_enabled:         v.auto_block_enabled,
      monitored_paths: v.monitored_paths_raw.split('\n').map(s => s.trim()).filter(Boolean),
      whitelist:       v.whitelist_raw.split('\n').map(s => s.trim()).filter(Boolean),
    };
    this.http.post('/api/settings/detection', payload).subscribe({
      next: () => { this.saving.set(false); this.saved.set(true); setTimeout(() => this.saved.set(false), 2000); },
      error: () => this.saving.set(false),
    });
  }
}
