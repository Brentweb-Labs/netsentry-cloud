import { IsEmail, IsString, MinLength } from 'class-validator';

export class InviteUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(1)
  name: string;

  @IsString()
  role: 'tenant_admin' | 'operator' | 'viewer';
}
