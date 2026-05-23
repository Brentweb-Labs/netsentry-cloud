import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, DetectionSettings } from '../../shared/services/api.service';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './settings.component.html',
  styleUrls: ['./settings.component.css']
})
export class SettingsComponent implements OnInit {
  settings: DetectionSettings = {
    brute_force_threshold: 10,
    brute_force_window_seconds: 60,
    block_duration_hours: 1,
    monitored_paths: ['/login', '/api/auth', '/api/login', '/admin', '/wp-admin', '/signin'],
    auto_block_enabled: true,
    dns_enrichment_enabled: true,
    whitelist: [],
    min_alert_level: 5,
    updated_at: ''
  };

  loading = false;
  saving = false;
  saveSuccess = false;
  saveError = '';
  newPath = '';

  constructor(private apiService: ApiService) {}

  ngOnInit(): void {
    this.loadSettings();
  }

  loadSettings(): void {
    this.loading = true;
    this.apiService.getDetectionSettings().subscribe({
      next: (s) => {
        this.settings = s;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  saveSettings(): void {
    this.saving = true;
    this.saveSuccess = false;
    this.saveError = '';

    this.apiService.updateDetectionSettings(this.settings).subscribe({
      next: (updated) => {
        this.settings = updated;
        this.saving = false;
        this.saveSuccess = true;
        setTimeout(() => (this.saveSuccess = false), 3000);
      },
      error: (err) => {
        this.saving = false;
        this.saveError = 'Failed to save settings. Please try again.';
      }
    });
  }

  addPath(): void {
    const path = this.newPath.trim();
    if (path && !this.settings.monitored_paths.includes(path)) {
      this.settings.monitored_paths = [...this.settings.monitored_paths, path];
      this.newPath = '';
    }
  }

  removePath(path: string): void {
    this.settings.monitored_paths = this.settings.monitored_paths.filter(p => p !== path);
  }

  onPathKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.addPath();
    }
  }

  get windowLabel(): string {
    const s = this.settings.brute_force_window_seconds;
    if (s >= 3600) return `${s / 3600} hour(s)`;
    if (s >= 60) return `${s / 60} minute(s)`;
    return `${s} seconds`;
  }

  get blockDurationLabel(): string {
    const h = this.settings.block_duration_hours;
    if (h >= 24) return `${h / 24} day(s)`;
    return `${h} hour(s)`;
  }
}
