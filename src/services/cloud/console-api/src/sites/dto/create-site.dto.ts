import { IsString, IsOptional, IsEnum } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateSiteDto {
  @IsString()
  name: string;

  @IsString()
  @Transform(({ value }) => value, { toClassOnly: true })
  tenant_id: string;

  @IsString()
  @IsOptional()
  location?: string;

  @IsEnum(['active', 'inactive', 'maintenance'])
  @IsOptional()
  status?: string;

  get tenantId(): string {
    return this.tenant_id;
  }
}
