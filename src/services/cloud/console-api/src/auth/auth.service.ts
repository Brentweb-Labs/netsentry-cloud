import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from '../schemas/user.schema';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './jwt.strategy';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
  ) {}

  /** Claims shared with the Rust gateway, which verifies the same HS256 secret. */
  buildPayload(user: { id: string; email: string; role: string; tenantId: string }): JwtPayload {
    return { sub: user.id, email: user.email, role: user.role, tenantId: user.tenantId };
  }

  async login(dto: LoginDto): Promise<{ access_token: string; role: string; tenant_id: string }> {
    const user = await this.userModel.findOne({ email: dto.email.toLowerCase() });
    // Always run a bcrypt compare to keep timing similar for unknown users.
    const hash = user?.passwordHash ?? '$2b$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidi';
    const valid = await bcrypt.compare(dto.password, hash).catch(() => false);
    if (!user || !valid || user.status === 'deactivated' || !user.tenantId) {
      throw new UnauthorizedException('Invalid credentials');
    }
    user.lastLogin = new Date();
    if (user.status === 'invited') user.status = 'active';
    await user.save();

    const payload = this.buildPayload({
      id: user.id as string,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId,
    });
    return { access_token: this.jwtService.sign(payload), role: user.role, tenant_id: user.tenantId };
  }
}
