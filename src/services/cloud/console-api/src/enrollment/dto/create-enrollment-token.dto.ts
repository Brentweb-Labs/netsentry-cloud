import { IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';

export class CreateEnrollmentTokenDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  label?: string;

  /** Lifetime in hours (default 24, max 168). */
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(168)
  ttlHours?: number;

  /** How many sensors may enroll with this token (default 1). */
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  maxUses?: number;

  /** Only honoured for platform admins; everyone else is pinned to their own tenant. */
  @IsOptional()
  @IsString()
  tenantId?: string;
}
