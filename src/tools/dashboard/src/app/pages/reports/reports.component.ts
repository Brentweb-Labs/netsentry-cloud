import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

interface ReportEntry {
  period_start: string;
  period_end: string;
  generated_at: string;
  size_bytes: number;
}

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="p-6 space-y-6">
      <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Compliance Reports</h1>

      <!-- Branding config -->
      <div class="rounded-xl border border-gray-200 bg-white p-5 dark:border-gray-800 dark:bg-white/[0.03]">
        <h2 class="mb-4 text-lg font-semibold text-gray-800 dark:text-white">Report Branding</h2>
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <label class="mb-1 block text-sm text-gray-600 dark:text-gray-400">Agency Name</label>
            <input [(ngModel)]="agencyName" class="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm dark:border-gray-700 dark:bg-gray-900 dark:text-white" />
          </div>
          <div>
            <label class="mb-1 block text-sm text-gray-600 dark:text-gray-400">Primary Colour (hex)</label>
            <input [(ngModel)]="primaryColor" class="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm dark:border-gray-700 dark:bg-gray-900 dark:text-white" />
          </div>
          <div class="flex items-end">
            <button (click)="saveBranding()" class="rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-700">
              Save Branding
            </button>
          </div>
        </div>
        @if (brandingSaved()) {
          <p class="mt-2 text-sm text-green-600">Saved.</p>
        }
      </div>

      <!-- Download current report -->
      <div class="rounded-xl border border-gray-200 bg-white p-5 dark:border-gray-800 dark:bg-white/[0.03]">
        <h2 class="mb-3 text-lg font-semibold text-gray-800 dark:text-white">Download Latest Report</h2>
        <p class="mb-4 text-sm text-gray-500">Generates a PDF for the most recently completed week.</p>
        <button (click)="downloadReport()" [disabled]="downloading()"
          class="rounded-lg bg-violet-600 px-5 py-2 text-sm font-medium text-white hover:bg-violet-700 disabled:opacity-50">
          {{ downloading() ? 'Generating…' : 'Download PDF' }}
        </button>
      </div>

      <!-- History -->
      <div class="rounded-xl border border-gray-200 bg-white p-5 dark:border-gray-800 dark:bg-white/[0.03]">
        <h2 class="mb-4 text-lg font-semibold text-gray-800 dark:text-white">Report History</h2>
        @if (loading()) {
          <p class="text-sm text-gray-500">Loading…</p>
        } @else if (reports().length === 0) {
          <p class="text-sm text-gray-500">No reports generated yet. Reports are auto-generated every Monday at 08:00 UTC.</p>
        } @else {
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-gray-700">
                <th class="pb-2 text-left text-gray-600 dark:text-gray-400">Period</th>
                <th class="pb-2 text-left text-gray-600 dark:text-gray-400">Generated</th>
                <th class="pb-2 text-left text-gray-600 dark:text-gray-400">Size</th>
              </tr>
            </thead>
            <tbody>
              @for (r of reports(); track r.generated_at) {
                <tr class="border-b border-gray-100 dark:border-gray-800">
                  <td class="py-2 text-gray-700 dark:text-gray-300">
                    {{ r.period_start | date:'mediumDate' }} – {{ r.period_end | date:'mediumDate' }}
                  </td>
                  <td class="py-2 text-gray-500">{{ r.generated_at | date:'medium' }}</td>
                  <td class="py-2 text-gray-500">{{ (r.size_bytes / 1024).toFixed(1) }} KB</td>
                </tr>
              }
            </tbody>
          </table>
        }
      </div>
    </div>
  `,
})
export class ReportsComponent implements OnInit {
  private readonly apiUrl = environment.apiUrl;

  agencyName = '';
  primaryColor = '#7c3aed';
  brandingSaved = signal(false);
  downloading = signal(false);
  loading = signal(true);
  reports = signal<ReportEntry[]>([]);

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.http.get<any>(`${this.apiUrl}/reports/history`).subscribe({
      next: (res) => {
        this.reports.set(res.reports ?? []);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  saveBranding(): void {
    this.http.post(`${this.apiUrl}/reports/config`, {
      agency_name: this.agencyName || undefined,
      primary_color: this.primaryColor || undefined,
    }).subscribe({
      next: () => {
        this.brandingSaved.set(true);
        setTimeout(() => this.brandingSaved.set(false), 2500);
      },
    });
  }

  downloadReport(): void {
    this.downloading.set(true);
    this.http.get(`${this.apiUrl}/reports/weekly`, { responseType: 'blob' }).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `netsentry-report-${new Date().toISOString().slice(0, 10)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        this.downloading.set(false);
      },
      error: () => this.downloading.set(false),
    });
  }
}
