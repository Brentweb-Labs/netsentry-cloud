# Tenant API Quick Reference Guide

## Base URL
```
http://localhost:3000/api/console/tenants
```

## Authentication
All requests require `Authorization: Bearer <JWT_TOKEN>` header.

---

## Tenants

### List All Tenants
```
GET /
Response: Tenant[]
```

### Get Single Tenant
```
GET /:id
Response: Tenant
```

### Create Tenant
```
POST /
Body: { name: string, plan: 'starter'|'pro'|'enterprise' }
Response: Tenant
```

### Update Tenant
```
PUT /:id
Body: Partial<Tenant>
Response: Tenant
```

### Delete Tenant
```
DELETE /:id
Response: { deleted: true }
```

---

## Users

### List Users
```
GET /:tenantId/users
Response: UserResponseDto[]
```

### Invite User
```
POST /:tenantId/users
Body: {
  email: string,
  name: string,
  role: 'tenant_admin'|'operator'|'viewer'
}
Response: UserResponseDto (201 Created)
```

### Deactivate User
```
DELETE /:tenantId/users/:userId
Response: 204 No Content
```

---

## API Keys

### List API Keys
```
GET /:tenantId/api-keys
Response: ApiKeyResponseDto[]
```

### Create API Key
```
POST /:tenantId/api-keys
Body: { name: string }
Response: CreateApiKeyResponseDto (includes raw key, shown once!)
```

### Revoke API Key
```
DELETE /:tenantId/api-keys/:keyId
Response: 204 No Content
```

---

## Response Objects

### Tenant
```typescript
{
  id: string;
  name: string;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  contactEmail?: string;
  sensorCount: number;
  maxSensors: number;
  createdAt: Date;
  updatedAt: Date;
}
```

### UserResponseDto
```typescript
{
  id: string;
  email: string;
  name: string;
  role: 'tenant_admin' | 'operator' | 'viewer';
  status: 'active' | 'invited' | 'deactivated';
  last_login: Date | null;
  created_at: Date;
}
```

### ApiKeyResponseDto
```typescript
{
  id: string;
  name: string;
  prefix: string;           // First 10 chars of key
  created_at: Date;
  last_used: Date | null;
}
```

### CreateApiKeyResponseDto (includes key)
```typescript
{
  id: string;
  name: string;
  key: string;              // Full API key (shown once!)
  prefix: string;
  created_at: Date;
  last_used: Date | null;
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "statusCode": 400,
  "message": "Invalid ID: tenantId must be a string",
  "error": "Bad Request"
}
```

### 404 Not Found
```json
{
  "statusCode": 404,
  "message": "Tenant not found",
  "error": "Not Found"
}
```

### 409 Conflict
```json
{
  "statusCode": 409,
  "message": "User already exists in this tenant",
  "error": "Conflict"
}
```

---

## Common Curl Examples

### List Tenants
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/console/tenants
```

### Invite User
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"John Doe","role":"operator"}' \
  http://localhost:3000/api/console/tenants/$TENANT_ID/users
```

### Create API Key
```bash
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Production Key"}' \
  http://localhost:3000/api/console/tenants/$TENANT_ID/api-keys
```

### Deactivate User
```bash
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/console/tenants/$TENANT_ID/users/$USER_ID
```

### Revoke API Key
```bash
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/console/tenants/$TENANT_ID/api-keys/$KEY_ID
```

---

## TypeScript Usage (Frontend)

```typescript
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class TenantService {
  private http = inject(HttpClient);
  private BASE = '/api/console/tenants';

  // Users
  getUsers(tenantId: string) {
    return this.http.get<UserResponseDto[]>(`${this.BASE}/${tenantId}/users`);
  }

  inviteUser(tenantId: string, dto: InviteUserDto) {
    return this.http.post<UserResponseDto>(`${this.BASE}/${tenantId}/users`, dto);
  }

  deactivateUser(tenantId: string, userId: string) {
    return this.http.delete<void>(`${this.BASE}/${tenantId}/users/${userId}`);
  }

  // API Keys
  getApiKeys(tenantId: string) {
    return this.http.get<ApiKeyResponseDto[]>(`${this.BASE}/${tenantId}/api-keys`);
  }

  createApiKey(tenantId: string, name: string) {
    return this.http.post<CreateApiKeyResponseDto>(
      `${this.BASE}/${tenantId}/api-keys`,
      { name }
    );
  }

  revokeApiKey(tenantId: string, keyId: string) {
    return this.http.delete<void>(`${this.BASE}/${tenantId}/api-keys/${keyId}`);
  }
}
```

---

## Validation Rules

| Field | Rule | Example |
|-------|------|---------|
| email | Valid email format | user@example.com |
| name | Non-empty string | John Doe |
| role | One of: tenant_admin, operator, viewer | operator |
| API key name | Non-empty string | Production Key |
| tenantId | Valid MongoDB ObjectId | 507f1f77bcf86cd799439011 |
| userId | Valid MongoDB ObjectId | 507f1f77bcf86cd799439012 |
| keyId | Valid MongoDB ObjectId | 507f1f77bcf86cd799439013 |

---

## Important Notes

1. **API Keys are shown only once** - Save the key immediately after creation
2. **User Status Flow:** invited → active (after first login) → deactivated (optional)
3. **Cannot update user role** - Deactivate and re-invite with different role
4. **Tenant deletion** - Cascades to users and API keys
5. **HTTP Status Codes:**
   - 200 OK - Successful GET/POST with content
   - 201 Created - Not used (returns 200)
   - 204 No Content - Successful DELETE
   - 400 Bad Request - Validation error
   - 404 Not Found - Resource not found
   - 409 Conflict - Resource already exists

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check JWT token validity and Authorization header |
| 404 Not Found | Verify tenant/user/key ID exists |
| 409 Conflict | User already exists; try different email or delete first |
| 400 Bad Request | Check request body format and required fields |
| No API key returned | Save key immediately; it's not stored in plain text |

---

## Rate Limiting

Currently no rate limiting implemented. Contact DevOps for configuration if needed.

---

## Changelog

### Version 1.0.0 (Current)
- Initial implementation
- Tenant CRUD operations
- User management (invite/deactivate)
- API key management with metadata
- Full request validation
- Comprehensive error handling
