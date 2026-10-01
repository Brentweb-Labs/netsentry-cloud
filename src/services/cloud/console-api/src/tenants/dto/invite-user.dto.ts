import { IsEmail, IsIn, IsString, MinLength } from 'class-validator';

export class InviteUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(1)
  name: string;

  @IsIn(['tenant_admin', 'operator', 'viewer'])
  role: 'tenant_admin' | 'operator' | 'viewer';
}
