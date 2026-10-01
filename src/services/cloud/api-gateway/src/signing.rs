//! HMAC signing of commands sent to sensors.
//!
//! Wire format: `{"type", "payload", "ts", "sig"}` where
//! `sig = hex(HMAC-SHA256(secret, type + "." + ts + "." + canonical(payload)))`.
//! `ts` is an integer number of Unix seconds rendered in decimal.
//! `canonical(payload)` is compact JSON with object keys sorted
//! lexicographically at every level (no whitespace). Payloads must not use
//! floating point numbers.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Deterministic JSON encoding: sorted keys, no whitespace.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

fn mac_for(secret: &str, msg_type: &str, ts: i64, payload: &Value) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(msg_type.as_bytes());
    mac.update(b".");
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(canonical_json(payload).as_bytes());
    mac
}

pub fn sign(secret: &str, msg_type: &str, ts: i64, payload: &Value) -> String {
    hex::encode(mac_for(secret, msg_type, ts, payload).finalize().into_bytes())
}

/// Constant-time verification (used by tests and for symmetry with the sensor).
pub fn verify(secret: &str, msg_type: &str, ts: i64, payload: &Value, sig_hex: &str) -> bool {
    let Ok(sig) = hex::decode(sig_hex) else {
        return false;
    };
    mac_for(secret, msg_type, ts, payload).verify_slice(&sig).is_ok()
}

/// Build the signed envelope sent over the sensor WebSocket.
pub fn envelope(secret: &str, msg_type: &str, payload: Value) -> Value {
    envelope_at(secret, msg_type, payload, chrono::Utc::now().timestamp())
}

pub fn envelope_at(secret: &str, msg_type: &str, payload: Value, ts: i64) -> Value {
    let sig = sign(secret, msg_type, ts, &payload);
    serde_json::json!({ "type": msg_type, "payload": payload, "ts": ts, "sig": sig })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_recursively() {
        let v = json!({"b": 1, "a": {"z": [3, {"y": 1, "x": 2}], "c": "s\"q"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":"s\"q","z":[3,{"x":2,"y":1}]},"b":1}"#);
    }

    #[test]
    fn known_vector() {
        // HMAC-SHA256("secret", "block_command.1700000000.{\"ip\":\"203.0.113.9\"}")
        let payload = json!({"ip": "203.0.113.9"});
        let sig = sign("secret", "block_command", 1_700_000_000, &payload);
        assert_eq!(sig.len(), 64);
        assert!(verify("secret", "block_command", 1_700_000_000, &payload, &sig));
        // Independent recomputation of the documented construction.
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"block_command.1700000000.{\"ip\":\"203.0.113.9\"}");
        assert_eq!(sig, hex::encode(mac.finalize().into_bytes()));
    }

    #[test]
    fn key_order_does_not_matter() {
        let a = json!({"x": 1, "y": 2});
        let b: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(sign("k", "t", 5, &a), sign("k", "t", 5, &b));
    }

    #[test]
    fn tampering_is_detected() {
        let payload = json!({"ip": "203.0.113.9"});
        let sig = sign("secret", "block_command", 10, &payload);
        assert!(!verify("secret", "unblock_command", 10, &payload, &sig));
        assert!(!verify("secret", "block_command", 11, &payload, &sig));
        assert!(!verify("other", "block_command", 10, &payload, &sig));
        assert!(!verify(
            "secret",
            "block_command",
            10,
            &json!({"ip": "203.0.113.10"}),
            &sig
        ));
        assert!(!verify("secret", "block_command", 10, &payload, "zz"));
    }

    #[test]
    fn envelope_roundtrip() {
        let env = envelope_at("s", "rule_update", json!({"rule_id": "r1"}), 42);
        let sig = env["sig"].as_str().unwrap();
        assert!(verify(
            "s",
            env["type"].as_str().unwrap(),
            env["ts"].as_i64().unwrap(),
            &env["payload"],
            sig
        ));
    }
}
