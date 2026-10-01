import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';

const SECRET = '0123456789abcdef0123456789abcdef';

function makeService(user: Record<string, unknown> | null) {
  const model = { findOne: jest.fn().mockResolvedValue(user) };
  const jwt = new JwtService({ secret: SECRET, signOptions: { expiresIn: '1h' } });
  return { service: new AuthService(model as never, jwt), jwt };
}

describe('AuthService', () => {
  it('issues a JWT carrying tenantId and role (read by the Rust gateway)', async () => {
    const user = {
      id: 'u1',
      email: 'a@b.c',
      role: 'tenant_admin',
      tenantId: 't1',
      status: 'active',
      passwordHash: await bcrypt.hash('correct horse', 4),
      save: jest.fn(),
    };
    const { service, jwt } = makeService(user);
    const res = await service.login({ email: 'A@B.C', password: 'correct horse' });
    const claims = jwt.verify<Record<string, unknown>>(res.access_token);
    expect(claims).toMatchObject({ sub: 'u1', email: 'a@b.c', role: 'tenant_admin', tenantId: 't1' });
    expect(user.save).toHaveBeenCalled();
  });

  it('rejects a wrong password, unknown user and deactivated user', async () => {
    const hash = await bcrypt.hash('right-password', 4);
    const base = { id: 'u', email: 'a@b.c', role: 'viewer', tenantId: 't', passwordHash: hash, save: jest.fn() };
    await expect(
      makeService({ ...base, status: 'active' }).service.login({ email: 'a@b.c', password: 'wrong-password' }),
    ).rejects.toThrow(UnauthorizedException);
    await expect(makeService(null).service.login({ email: 'x@y.z', password: 'whatever' })).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(
      makeService({ ...base, status: 'deactivated' }).service.login({ email: 'a@b.c', password: 'right-password' }),
    ).rejects.toThrow(UnauthorizedException);
  });
});
