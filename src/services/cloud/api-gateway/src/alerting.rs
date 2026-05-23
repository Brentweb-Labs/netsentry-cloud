use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AlertingConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_address: String,
    pub twilio_account_sid: String,
    pub twilio_auth_token: String,
    pub twilio_from_number: String,
}

impl AlertingConfig {
    pub fn smtp_configured(&self) -> bool {
        !self.smtp_host.is_empty() && !self.smtp_username.is_empty()
    }
    pub fn twilio_configured(&self) -> bool {
        !self.twilio_account_sid.is_empty() && !self.twilio_auth_token.is_empty()
    }
}

/// Send an HTML email via SMTP (STARTTLS on the configured port).
pub async fn send_email_alert(
    config: &AlertingConfig,
    to: &str,
    subject: &str,
    body_html: &str,
) -> anyhow::Result<()> {
    let email = Message::builder()
        .from(config.from_address.parse()?)
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body_html.to_string())?;

    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

    mailer.send(email).await?;
    Ok(())
}

/// Send an SMS via Twilio Messages API.
pub async fn send_sms_alert(
    client: &reqwest::Client,
    config: &AlertingConfig,
    to_number: &str,
    message: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        config.twilio_account_sid
    );
    let params = [
        ("To", to_number),
        ("From", &config.twilio_from_number),
        ("Body", message),
    ];
    let resp = client
        .post(&url)
        .basic_auth(&config.twilio_account_sid, Some(&config.twilio_auth_token))
        .form(&params)
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Twilio error: {}", body);
    }
    Ok(())
}

// ── Alert rule document stored in MongoDB ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub tenant_id: String,
    /// "email" or "sms"
    pub rule_type: String,
    pub destination: String,
    /// "critical", "high", "medium", "low"
    pub min_severity: String,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Check whether a severity label meets or exceeds the rule's minimum.
pub fn severity_meets_threshold(alert_severity: &str, min_severity: &str) -> bool {
    let rank = |s: &str| match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    rank(alert_severity) >= rank(min_severity)
}
