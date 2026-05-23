import { IsString, IsEmail, IsOptional, IsEnum } from 'class-validator';

export class CreateTenantDto {
  @IsString()
  name: string;

  @IsEmail()
  @IsOptional()
  contactEmail?: string;

  @IsEnum(['starter', 'pro', 'enterprise'])
  @IsOptional()
  plan?: string;
}
