import { ForbiddenException } from '@nestjs/common';
import { generateToken, hashToken, resolveTenant } from './enrollment.service';
import { AuthUser } from '../auth/jwt.strategy';

const user = (role: string, tenantId = 't1'): AuthUser => ({ userId: 'u', email: 'a@b.c', role, tenantId });

describe('enrollment tokens', () => {
  it('generates unique prefixed tokens', () => {
    const a = generateToken();
    expect(a).toMatch(/^nse_[0-9a-f]{48}$/);
    expect(generateToken()).not.toBe(a);
  });

  it('hashes with SHA-256 (hex), matching what the gateway computes', () => {
    expect(hashToken('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(hashToken('nse_x')).toHaveLength(64);
  });

  it('pins non-platform users to their own tenant', () => {
    expect(resolveTenant(user('tenant_admin'))).toBe('t1');
    expect(resolveTenant(user('tenant_admin'), 't1')).toBe('t1');
    expect(() => resolveTenant(user('tenant_admin'), 't2')).toThrow(ForbiddenException);
  });

  it('lets platform admins target another tenant', () => {
    expect(resolveTenant(user('platform_admin'), 't2')).toBe('t2');
  });
});
