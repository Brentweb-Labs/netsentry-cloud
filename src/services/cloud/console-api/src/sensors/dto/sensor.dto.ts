export class CreateSensorDto {
  name: string;
  tenantId: string;
  siteId?: string;
  location?: string;
  hardwareInfo?: {
    model: string;
    os: string;
    suricataVersion: string;
  };
}

export class UpdateSensorDto {
  name?: string;
  status?: string;
  location?: string;
  autoBlockEnabled?: boolean;
  config?: {
    autoBlockEnabled: boolean;
    blockDurationHours: number;
    minThreatLevel: number;
    whitelist: string[];
    monitoredPaths: string[];
  };
}

export class RegisterSensorResponse {
  sensorId: string;
  apiKey: string;
  name: string;
  status: string;
}
