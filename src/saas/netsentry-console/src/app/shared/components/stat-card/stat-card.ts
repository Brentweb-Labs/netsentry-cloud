import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-stat-card',
  imports: [],
  templateUrl: './stat-card.html',
  styles: ``,
})
export class StatCard {
  @Input() title = '';
  @Input() value: string | number = '—';
  @Input() desc?: string;
  @Input() figure?: string;
}
