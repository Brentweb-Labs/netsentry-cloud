import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export type Role = 'platform_admin' | 'tenant_admin' | 'operator' | 'viewer';

/** Restrict a route to the given roles (use together with JwtAuthGuard and RolesGuard). */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
