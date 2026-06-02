import { IsString, IsOptional, IsEnum, IsArray, IsIP } from 'class-validator';

export class CreateWireGuardConfigDto {
  @IsOptional()
  @IsString()
  customSubnet?: string;
}

export class WireGuardConfigResponseDto {
  @IsString()
  interfaceName: string;

  @IsString()
  subnet: string;

  @IsString()
  peerEndpoint: string;

  @IsString()
  peerPublicKey: string;

  @IsArray()
  allowedIPs: string[];

  @IsEnum(['active', 'inactive', 'pending'])
  status: string;
}

export class SensorConfigResponseDto {
  @IsString()
  privateKey: string;

  @IsString()
  address: string;

  @IsString()
  endpoint: string;

  @IsString()
  peerPublicKey: string;

  @IsArray()
  allowedIPs: string[];

  @IsArray()
  dns: string[];

  persistentKeepalive: number;
}
