import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';

function ctx(role: string | undefined): ExecutionContext {
  return {
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({ getRequest: () => ({ user: role ? { role } : undefined }) }),
  } as unknown as ExecutionContext;
}

function guard(required: string[] | undefined): RolesGuard {
  const reflector = { getAllAndOverride: () => required } as unknown as Reflector;
  return new RolesGuard(reflector);
}

describe('RolesGuard', () => {
  it('allows routes without role metadata', () => {
    expect(guard(undefined).canActivate(ctx('viewer'))).toBe(true);
  });

  it('allows a matching role', () => {
    expect(guard(['platform_admin']).canActivate(ctx('platform_admin'))).toBe(true);
  });

  it('rejects other roles and missing users', () => {
    expect(() => guard(['platform_admin']).canActivate(ctx('tenant_admin'))).toThrow(ForbiddenException);
    expect(() => guard(['tenant_admin']).canActivate(ctx(undefined))).toThrow(ForbiddenException);
  });
});
