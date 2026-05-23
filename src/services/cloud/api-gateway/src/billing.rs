use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStatus {
    pub active: bool,
    pub plan: String,
    pub current_period_end: Option<i64>,
    pub cancel_at_period_end: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeEvent {
    pub event_type: String,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    pub checkout_session_id: Option<String>,
}

/// Create a Stripe Checkout Session and return the hosted URL.
pub async fn create_checkout_session(
    client: &reqwest::Client,
    secret_key: &str,
    tenant_id: &str,
    price_id: &str,
    success_url: &str,
    cancel_url: &str,
) -> anyhow::Result<String> {
    let params = [
        ("mode", "subscription"),
        ("line_items[0][price]", price_id),
        ("line_items[0][quantity]", "1"),
        ("success_url", success_url),
        ("cancel_url", cancel_url),
        ("client_reference_id", tenant_id),
    ];

    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(secret_key, Some(""))
        .form(&params)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let url = body["url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing url in Stripe response: {:?}", body))?
        .to_string();
    Ok(url)
}

/// Retrieve a subscription's status from Stripe.
pub async fn get_subscription_status(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
) -> anyhow::Result<SubscriptionStatus> {
    let url = format!(
        "https://api.stripe.com/v1/subscriptions?customer={}&limit=1&status=active",
        customer_id
    );
    let resp = client
        .get(&url)
        .basic_auth(secret_key, Some(""))
        .send()
        .await?;
    let body: serde_json::Value = resp.json().await?;

    let sub = &body["data"][0];
    if sub.is_null() {
        return Ok(SubscriptionStatus {
            active: false,
            plan: "none".into(),
            current_period_end: None,
            cancel_at_period_end: false,
        });
    }

    let plan = sub["items"]["data"][0]["price"]["nickname"]
        .as_str()
        .unwrap_or("cloud")
        .to_string();

    Ok(SubscriptionStatus {
        active: sub["status"].as_str() == Some("active"),
        plan,
        current_period_end: sub["current_period_end"].as_i64(),
        cancel_at_period_end: sub["cancel_at_period_end"].as_bool().unwrap_or(false),
    })
}

/// Verify Stripe webhook signature and parse the event.
/// Returns `Err` if the signature is invalid.
pub fn handle_webhook(
    payload: &[u8],
    signature_header: &str,
    webhook_secret: &str,
) -> anyhow::Result<StripeEvent> {
    // Parse t= and v1= from the Stripe-Signature header
    let mut timestamp = "";
    let mut v1_sig = "";
    for part in signature_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(v) = part.strip_prefix("v1=") {
            v1_sig = v;
        }
    }
    if timestamp.is_empty() || v1_sig.is_empty() {
        anyhow::bail!("malformed Stripe-Signature header");
    }

    // signed_payload = timestamp + "." + raw_body
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("HMAC init error: {}", e))?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected != v1_sig {
        anyhow::bail!("Stripe webhook signature mismatch");
    }

    // Parse the event JSON
    let event: serde_json::Value = serde_json::from_slice(payload)?;
    let event_type = event["type"].as_str().unwrap_or("").to_string();
    let obj = &event["data"]["object"];

    Ok(StripeEvent {
        event_type,
        customer_id: obj["customer"].as_str().map(str::to_string),
        subscription_id: obj["subscription"].as_str().map(str::to_string),
        checkout_session_id: obj["id"].as_str().map(str::to_string),
    })
}
