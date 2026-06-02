# Tenant Management API Implementation

## Overview
This document describes the complete implementation of the Tenant Management API, including tenant CRUD operations, user management (invite/deactivate), and API key management.

## API Endpoints

### Tenants
- `GET /api/console/tenants` - List all tenants
- `GET /api/console/tenants/:id` - Get tenant details
- `POST /api/console/tenants` - Create new tenant
- `PUT /api/console/tenants/:id` - Update tenant
- `DELETE /api/console/tenants/:id` - Delete tenant

### Users
- `GET /api/console/tenants/:id/users` - List tenant users
- `POST /api/console/tenants/:id/users` - Invite user to tenant
- `DELETE /api/console/tenants/:id/users/:userId` - Deactivate user

### API Keys
- `GET /api/console/tenants/:id/api-keys` - List tenant API keys
- `POST /api/console/tenants/:id/api-keys` - Create new API key
- `DELETE /api/console/tenants/:id/api-keys/:keyId` - Revoke API key

## Request/Response Formats

### Invite User Request
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "role": "operator"
}
```

### Invite User Response
```json
{
  "id": "objectId",
  "email": "user@example.com",
  "name": "John Doe",
  "role": "operator",
  "status": "invited",
  "last_login": null,
  "created_at": "2024-05-29T10:00:00Z"
}
```

### Create API Key Request
```json
{
  "name": "Production API Key"
}
```

### Create API Key Response
```json
{
  "id": "objectId",
  "name": "Production API Key",
  "key": "nsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "prefix": "nsk_xxxxxxxx",
  "created_at": "2024-05-29T10:00:00Z",
  "last_used": null
}
```

### List API Keys Response
```json
[
  {
    "id": "objectId",
    "name": "Production API Key",
    "prefix": "nsk_xxxxxxxx",
    "created_at": "2024-05-29T10:00:00Z",
    "last_used": "2024-05-29T15:30:00Z"
  }
]
```

## Database Schema Changes

### Tenant Schema
- Enhanced `apiKeys` field from `string[]` to array of objects with metadata:
  - `key`: The actual API key string
  - `name`: Human-readable name for the key
  - `createdAt`: Creation timestamp
  - `lastUsed`: Last usage timestamp (nullable)

### User Schema
- Added `name` field (string)
- Added `status` field (enum: 'active', 'invited', 'deactivated')
- Added `lastLogin` field (Date, nullable)
- Updated `role` enum values: 'tenant_admin', 'operator', 'viewer'

## Migration Guide

### For Existing Data
Run the migration script to upgrade existing API keys from string format to the new object format:

```bash
npm run migrate:api-keys
```

This will:
1. Convert existing API key strings to objects with metadata
2. Add missing fields to existing users
3. Maintain backward compatibility

### Add to package.json Scripts
```json
{
  "scripts": {
    "migrate:api-keys": "ts-node src/migrations/migrate-api-keys.ts",
    "seed:tenants": "ts-node src/seeds/tenants.seed.ts"
  }
}
```

## Error Handling

### Common Errors
- `400 Bad Request` - Invalid or missing tenantId/userId
- `404 Not Found` - Tenant, user, or API key not found
- `409 Conflict` - User already exists in tenant
- `401 Unauthorized` - Missing or invalid JWT token

### Response Format
```json
{
  "statusCode": 400,
  "message": "Invalid ID: tenantId must be a string",
  "error": "Bad Request"
}
```

## Validation Rules

### Create API Key
- `name` is required and must be a non-empty string

### Invite User
- `email` must be a valid email address
- `name` must be a non-empty string
- `role` must be one of: 'tenant_admin', 'operator', 'viewer'
- User must not already exist in the tenant

### Deactivate User
- User must belong to the specified tenant
- Cannot be undone (user will need to be invited again)

## Security Considerations

1. **API Key Storage**: Keys are stored in plaintext in the database. In production, consider:
   - Hashing API keys with a salt
   - Storing only the hash and returning the full key only once during creation

2. **JWT Authentication**: All endpoints require JWT authentication via `JwtAuthGuard`

3. **Tenant Isolation**: Users can only access tenants they belong to (enforced at service layer)

4. **Password Handling**: Invited users are created with a temporary password that should be reset on first login

## Testing

### Integration Testing
Use the seed script to create test data:
```bash
npm run seed:tenants
```

### Manual Testing
```bash
# List tenants
curl -H "Authorization: Bearer <TOKEN>" http://localhost:3000/api/console/tenants

# Invite user
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"John Doe","role":"operator"}' \
  http://localhost:3000/api/console/tenants/<TENANT_ID>/users

# Create API key
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Production Key"}' \
  http://localhost:3000/api/console/tenants/<TENANT_ID>/api-keys
```

## Future Enhancements

1. **API Key Permissions**: Add scoped permissions to API keys
2. **Usage Analytics**: Track API key usage statistics
3. **Bulk Operations**: Support bulk user invitations
4. **Audit Logging**: Log all tenant/user/API key operations
5. **Rate Limiting**: Implement per-tenant rate limits
