//! MongoDB access: collection names, indexes and BSON/JSON helpers.
//!
//! Every tenant-owned collection stores `tenant_id` (and `sensor_id` where a
//! sensor is the origin). Sensors and tenants are shared with the NestJS
//! console-api, which uses camelCase field names (`tenantId`, `sensorId`).

use anyhow::Result;
use chrono::{DateTime, Utc};
use mongodb::bson::{doc, Bson, DateTime as BsonDateTime, Document};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde_json::{Map, Value};
use std::time::Duration;

pub const EVENTS: &str = "events";
pub const ALERTS: &str = "alerts";
pub const BLOCKED_IPS: &str = "blocked_ips";
pub const SENSORS: &str = "sensors";
pub const TENANTS: &str = "tenants";
pub const ENROLLMENT_TOKENS: &str = "enrollment_tokens";
pub const TENANT_SETTINGS: &str = "tenant_settings";
pub const TELEMETRY: &str = "telemetry";

#[derive(Clone)]
pub struct Store {
    pub db: Database,
}

impl Store {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub fn coll(&self, name: &str) -> Collection<Document> {
        self.db.collection::<Document>(name)
    }

    /// Create indexes (idempotent). Safe to call at every start.
    pub async fn ensure_indexes(&self, event_retention_days: u32) -> Result<()> {
        let idx = |keys: Document, opts: Option<IndexOptions>| IndexModel::builder().keys(keys).options(opts).build();
        let retention = Duration::from_secs(u64::from(event_retention_days.max(1)) * 86_400);
        let ttl = IndexOptions::builder().expire_after(retention).build();
        self.coll(EVENTS)
            .create_indexes([
                idx(doc! { "tenant_id": 1, "sensor_id": 1, "ts": -1 }, None),
                idx(doc! { "tenant_id": 1, "event_type": 1, "ts": -1 }, None),
                idx(doc! { "processed_at": 1 }, Some(ttl.clone())),
            ])
            .await?;
        self.coll(ALERTS)
            .create_indexes([
                idx(doc! { "tenant_id": 1, "ts": -1 }, None),
                idx(doc! { "tenant_id": 1, "sensor_id": 1, "ts": -1 }, None),
                idx(doc! { "tenant_id": 1, "severity": 1, "ts": -1 }, None),
                idx(doc! { "processed_at": 1 }, Some(ttl)),
            ])
            .await?;
        self.coll(BLOCKED_IPS)
            .create_indexes([
                idx(doc! { "tenant_id": 1, "ip": 1, "status": 1 }, None),
                idx(doc! { "tenant_id": 1, "status": 1, "created_at": -1 }, None),
                idx(doc! { "status": 1, "expires_at": 1 }, None),
            ])
            .await?;
        self.coll(TELEMETRY)
            .create_index(idx(
                doc! { "received_at": 1 },
                Some(
                    IndexOptions::builder()
                        .expire_after(Duration::from_secs(7 * 86_400))
                        .build(),
                ),
            ))
            .await?;
        self.coll(TELEMETRY)
            .create_index(idx(doc! { "tenant_id": 1, "sensor_id": 1, "received_at": -1 }, None))
            .await?;
        self.coll(ENROLLMENT_TOKENS)
            .create_indexes([
                idx(
                    doc! { "token_hash": 1 },
                    Some(IndexOptions::builder().unique(true).build()),
                ),
                idx(doc! { "tenant_id": 1, "created_at": -1 }, None),
            ])
            .await?;
        self.coll(SENSORS)
            .create_indexes([
                idx(
                    doc! { "apiKeyHash": 1 },
                    Some(
                        IndexOptions::builder()
                            .unique(true)
                            .partial_filter_expression(doc! { "apiKeyHash": { "$type": "string" } })
                            .build(),
                    ),
                ),
                idx(doc! { "tenantId": 1, "status": 1 }, None),
            ])
            .await?;
        self.coll(TENANT_SETTINGS)
            .create_index(idx(
                doc! { "tenant_id": 1 },
                Some(IndexOptions::builder().unique(true).build()),
            ))
            .await?;
        Ok(())
    }
}

pub fn bdt(dt: DateTime<Utc>) -> BsonDateTime {
    BsonDateTime::from_millis(dt.timestamp_millis())
}

pub fn bdt_now() -> BsonDateTime {
    bdt(Utc::now())
}

pub fn bson_to_json(b: &Bson) -> Value {
    match b {
        Bson::Double(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Bson::String(s) => Value::String(s.clone()),
        Bson::Array(a) => Value::Array(a.iter().map(bson_to_json).collect()),
        Bson::Document(d) => doc_to_json(d),
        Bson::Boolean(v) => Value::Bool(*v),
        Bson::Null => Value::Null,
        Bson::Int32(i) => Value::from(*i),
        Bson::Int64(i) => Value::from(*i),
        Bson::DateTime(dt) => Value::String(
            DateTime::<Utc>::from_timestamp_millis(dt.timestamp_millis())
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                .unwrap_or_default(),
        ),
        Bson::ObjectId(o) => Value::String(o.to_hex()),
        other => Value::String(other.to_string()),
    }
}

/// Convert a BSON document to plain JSON (dates as RFC 3339, ObjectId as hex).
/// `_id` is exposed as `id`; fields listed in `hide` are dropped.
pub fn doc_to_json_hiding(d: &Document, hide: &[&str]) -> Value {
    let mut m = Map::new();
    for (k, v) in d {
        if hide.contains(&k.as_str()) {
            continue;
        }
        let key = if k == "_id" { "id" } else { k.as_str() };
        m.insert(key.to_string(), bson_to_json(v));
    }
    Value::Object(m)
}

pub fn doc_to_json(d: &Document) -> Value {
    doc_to_json_hiding(d, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::oid::ObjectId;

    #[test]
    fn converts_dates_ids_and_hides_fields() {
        let oid = ObjectId::new();
        let d = doc! {
            "_id": oid,
            "ts": BsonDateTime::from_millis(1_700_000_000_000),
            "n": 3i64,
            "secret": "x",
            "nested": { "a": [1i32, 2i32] },
        };
        let v = doc_to_json_hiding(&d, &["secret"]);
        assert_eq!(v["id"], oid.to_hex());
        assert_eq!(v["ts"], "2023-11-14T22:13:20.000Z");
        assert_eq!(v["n"], 3);
        assert!(v.get("secret").is_none());
        assert_eq!(v["nested"]["a"][1], 2);
    }
}
