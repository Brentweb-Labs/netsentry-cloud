export interface ITenant {
  id: string;
  name: string;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  contactEmail?: string;
  sensorCount: number;
  maxSensors: number;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  createdAt: Date;
  updatedAt: Date;
  apiKeys: IApiKey[];
}

export interface IApiKey {
  _id?: string;
  key: string;
  name: string;
  createdAt: Date;
  lastUsed: Date | null;
}

export interface IUser {
  id: string;
  email: string;
  name: string;
  role: 'tenant_admin' | 'operator' | 'viewer';
  tenantId: string;
  status: 'active' | 'invited' | 'deactivated';
  lastLogin: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface IApiKeyResponse {
  id: string;
  name: string;
  prefix: string;
  created_at: Date;
  last_used: Date | null;
}

export interface IApiKeyCreateResponse extends IApiKeyResponse {
  key: string;
}

export interface IUserResponse {
  id: string;
  email: string;
  name: string;
  role: 'tenant_admin' | 'operator' | 'viewer';
  status: 'active' | 'invited' | 'deactivated';
  last_login: Date | null;
  created_at: Date;
}
