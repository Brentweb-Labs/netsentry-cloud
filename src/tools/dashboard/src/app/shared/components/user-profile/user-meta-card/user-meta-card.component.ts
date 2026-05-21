import { Component } from '@angular/core';
import { InputFieldComponent } from '../../form/input/input-field.component';
import { ModalService } from '../../../services/modal.service';

import { ModalComponent } from '../../ui/modal/modal.component';
import { ButtonComponent } from '../../ui/button/button.component';

@Component({
  selector: 'app-user-meta-card',
  imports: [
    ModalComponent,
    InputFieldComponent,
    ButtonComponent
],
  templateUrl: './user-meta-card.component.html',
  styles: ``
})
export class UserMetaCardComponent {

  constructor(public modal: ModalService) {}

  isOpen = false;
  openModal() { this.isOpen = true; }
  closeModal() { this.isOpen = false; }

  // Example user data (could be made dynamic)
  user = {
    firstName: 'Admin',
    lastName: '',
    role: 'IDPS Administrator',
    location: '',
    avatar: '',
    social: {
      facebook: '',
      x: '',
      linkedin: '',
      instagram: '',
    },
    email: '',
    phone: '',
    bio: 'IDPS Administrator',
  };

  handleSave() {
    // Handle save logic here
    console.log('Saving changes...');
    this.modal.closeModal();
  }
}
