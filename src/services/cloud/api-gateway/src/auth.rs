//! Authentication: dashboard users (JWT issued by console-api) and sensors
//! (per-sensor API key in the `X-API-Key` header).

use crate::error::ApiError;
use crate::models::SensorIdentity;
use crate::state::SharedState;
use crate::store::{bdt_now, SENSORS};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use mongodb::bson::doc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const SENSOR_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    PlatformAdmin,
    TenantAdmin,
    Operator,
    Viewer,
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s {
            "platform_admin" => Role::PlatformAdmin,
            "tenant_admin" => Role::TenantAdmin,
            "operator" => Role::Operator,
            _ => Role::Viewer,
        }
    }

    /// May approve/reject/create blocks and change settings.
    pub fn can_write(&self) -> bool {
        !matches!(self, Role::Viewer)
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Role::PlatformAdmin | Role::TenantAdmin)
    }
}

/// JWT claims as issued by console-api.
#[derive(Debug, Deserialize)]
struct RawClaims {
    sub: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    role: String,
    #[serde(rename = "tenantId", alias = "tenant_id", default)]
    tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct Claims {
    pub user_id: String,
    pub email: String,
    pub role: Role,
    pub tenant_id: String,
}

/// Verify an HS256 JWT (signature and `exp`) and require a tenant.
pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_required_spec_claims(&["exp", "sub"]);
    let data = jsonwebtoken::decode::<RawClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v)
        .map_err(|_| ApiError::Unauthorized("invalid or expired token"))?;
    let c = data.claims;
    if c.tenant_id.is_empty() {
        return Err(ApiError::Forbidden("token carries no tenant"));
    }
    Ok(Claims {
        user_id: c.sub,
        email: c.email,
        role: Role::parse(&c.role),
        tenant_id: c.tenant_id,
    })
}

/// Sensor API keys are stored only as SHA-256 hashes.
pub fn hash_api_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// Extractor for dashboard/API users (`Authorization: Bearer <jwt>`).
pub struct UserAuth(pub Claims);

impl FromRequestParts<SharedState> for UserAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized("missing bearer token"))?;
        verify_jwt(token, &state.cfg.jwt_secret).map(UserAuth)
    }
}

/// Dashboard WebSocket auth: JWT from the `token` query parameter.
pub struct WsUserAuth(pub Claims);

impl FromRequestParts<SharedState> for WsUserAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let token = parts
            .uri
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
            .ok_or(ApiError::Unauthorized("missing token"))?;
        verify_jwt(token, &state.cfg.jwt_secret).map(WsUserAuth)
    }
}

impl UserAuth {
    pub fn require_write(&self) -> Result<(), ApiError> {
        if self.0.role.can_write() {
            Ok(())
        } else {
            Err(ApiError::Forbidden("read-only role"))
        }
    }
}

/// Extractor for sensors (`X-API-Key` header only; query parameters are ignored).
pub struct SensorAuth(pub SensorIdentity);

impl FromRequestParts<SharedState> for SensorAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .filter(|k| !k.is_empty() && k.len() <= 256)
            .ok_or(ApiError::Unauthorized("missing X-API-Key header"))?;
        let hash = hash_api_key(key);

        if let Some(entry) = state.sensor_cache.get(&hash) {
            if entry.1.elapsed() < SENSOR_CACHE_TTL {
                return Ok(SensorAuth(entry.0.clone()));
            }
        }
        state.sensor_cache.remove(&hash);

        let found = state
            .store
            .coll(SENSORS)
            .find_one(doc! { "apiKeyHash": &hash, "status": { "$ne": "revoked" } })
            .await?;
        let Some(d) = found else {
            return Err(ApiError::Unauthorized("invalid sensor API key"));
        };
        let ident = SensorIdentity {
            sensor_id: d.get_str("sensorId").map_err(ApiError::internal)?.to_string(),
            tenant_id: d.get_str("tenantId").map_err(ApiError::internal)?.to_string(),
            command_secret: d.get_str("commandHmacSecret").unwrap_or_default().to_string(),
        };
        touch_sensor(state, &ident.sensor_id).await;
        state.sensor_cache.insert(hash, (ident.clone(), Instant::now()));
        Ok(SensorAuth(ident))
    }
}

/// Mark a sensor as seen just now.
pub async fn touch_sensor(state: &SharedState, sensor_id: &str) {
    let res = state
        .store
        .coll(SENSORS)
        .update_one(
            doc! { "sensorId": sensor_id, "status": { "$ne": "revoked" } },
            doc! { "$set": { "lastConnectedAt": bdt_now(), "status": "active" } },
        )
        .await;
    if let Err(e) = res {
        tracing::warn!("touch_sensor failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn token(claims: serde_json::Value, secret: &str) -> String {
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn exp(offset: i64) -> i64 {
        chrono::Utc::now().timestamp() + offset
    }

    #[test]
    fn accepts_valid_console_token() {
        let t = token(
            json!({"sub": "u1", "email": "a@b.c", "role": "operator", "tenantId": "t1", "exp": exp(60)}),
            SECRET,
        );
        let c = verify_jwt(&t, SECRET).unwrap();
        assert_eq!(c.tenant_id, "t1");
        assert_eq!(c.role, Role::Operator);
        assert!(c.role.can_write());
        assert!(!c.role.can_admin());
    }

    #[test]
    fn rejects_wrong_secret_expired_and_missing_tenant() {
        let good = json!({"sub": "u1", "role": "viewer", "tenantId": "t1", "exp": exp(60)});
        assert!(verify_jwt(&token(good, "another-secret-another-secret-123"), SECRET).is_err());
        let expired = json!({"sub": "u1", "tenantId": "t1", "exp": exp(-3600)});
        assert!(verify_jwt(&token(expired, SECRET), SECRET).is_err());
        let no_tenant = json!({"sub": "u1", "role": "viewer", "exp": exp(60)});
        assert!(matches!(
            verify_jwt(&token(no_tenant, SECRET), SECRET),
            Err(ApiError::Forbidden(_))
        ));
        assert!(verify_jwt("garbage", SECRET).is_err());
    }

    #[test]
    fn rejects_unsigned_none_algorithm() {
        // header {"alg":"none"}, payload with tenant, empty signature
        let t = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1MSIsInRlbmFudElkIjoidDEiLCJleHAiOjQxMDI0NDQ4MDB9.";
        assert!(verify_jwt(t, SECRET).is_err());
    }

    #[test]
    fn unknown_role_is_read_only() {
        assert_eq!(Role::parse("hacker"), Role::Viewer);
        assert!(!Role::Viewer.can_write());
        assert!(Role::PlatformAdmin.can_admin());
    }

    #[test]
    fn api_key_hash_is_stable_sha256() {
        // sha256("nss_test")
        let h = hash_api_key("nss_test");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_api_key("nss_test"));
        assert_ne!(h, hash_api_key("nss_test2"));
        assert_eq!(
            hash_api_key(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
