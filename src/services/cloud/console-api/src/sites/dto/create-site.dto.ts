import { IsString, IsOptional, IsEnum } from 'class-validator';

export class CreateSiteDto {
  @IsString()
  name: string;

  @IsString()
  tenantId: string;

  @IsString()
  @IsOptional()
  location?: string;

  @IsEnum(['active', 'inactive', 'maintenance'])
  @IsOptional()
  status?: string;
}
