export class ApiKeyResponseDto {
  id: string;
  name: string;
  prefix: string;
  created_at: Date;
  last_used: Date | null;
}

export class CreateApiKeyResponseDto extends ApiKeyResponseDto {
  key: string;
}
