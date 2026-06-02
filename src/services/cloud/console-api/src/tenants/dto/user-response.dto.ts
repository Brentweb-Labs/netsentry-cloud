export class UserResponseDto {
  id: string;
  email: string;
  name: string;
  role: 'tenant_admin' | 'operator' | 'viewer';
  status: 'active' | 'invited' | 'deactivated';
  last_login: Date | null;
  created_at: Date;
}
