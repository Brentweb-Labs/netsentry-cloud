import { Component, EventEmitter, Input, Output } from '@angular/core';

@Component({
  selector: 'app-confirm-modal',
  imports: [],
  templateUrl: './confirm-modal.html',
  styles: ``,
})
export class ConfirmModal {
  @Input() id = 'confirm-modal';
  @Input() title = 'Confirm action';
  @Input() message = 'Are you sure you want to proceed?';
  @Input() confirmLabel = 'Confirm';
  @Input() danger = false;
  @Output() confirmed = new EventEmitter<void>();
}
