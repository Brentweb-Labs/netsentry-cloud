export class UserResponseDto {
  id: string;
  email: string;
  name: string;
  role: 'platform_admin' | 'tenant_admin' | 'operator' | 'viewer';
  status: 'active' | 'invited' | 'deactivated';
  last_login: Date | null;
  created_at: Date;
  /** Only present in the response to an invite; shown once. */
  temporary_password?: string;
}
