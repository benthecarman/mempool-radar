use anyhow::{Context, Result};
use bitcoin::Txid;
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::inspector::Anomaly;

pub struct Notifier {
    config: Config,
    client: Client,
    rate_limiter: Mutex<RateLimiter>,
}

struct RateLimiter {
    sent_messages: HashMap<Txid, Instant>,
    cooldown: Duration,
}

impl RateLimiter {
    fn new(cooldown_seconds: u64) -> Self {
        Self {
            sent_messages: HashMap::new(),
            cooldown: Duration::from_secs(cooldown_seconds),
        }
    }

    fn should_send(&mut self, txid: Txid) -> bool {
        let now = Instant::now();

        if let Some(last_sent) = self.sent_messages.get(&txid)
            && now.duration_since(*last_sent) < self.cooldown
        {
            return false;
        }

        self.sent_messages.insert(txid, now);

        self.sent_messages
            .retain(|_, v| now.duration_since(*v) < Duration::from_secs(3600));

        true
    }
}

impl Notifier {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            client: Client::new(),
            rate_limiter: Mutex::new(RateLimiter::new(60)),
        }
    }

    pub async fn notify(&self, txid: Txid, anomalies: Vec<Anomaly>) -> Result<()> {
        let mut rate_limiter = self.rate_limiter.lock().await;
        if !rate_limiter.should_send(txid) {
            warn!("Rate limited notification for: {txid}");
            return Ok(());
        }
        drop(rate_limiter);

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            self.send_telegram(txid, anomalies).await?;
        } else {
            self.log_anomalies(txid, &anomalies);
        }

        Ok(())
    }

    async fn send_telegram(&self, txid: Txid, anomalies: Vec<Anomaly>) -> Result<()> {
        let token = self.config.telegram_token.as_ref().unwrap();
        let chat_id = self.config.telegram_chat_id.as_ref().unwrap();

        let message = create_telegram_message(txid, &anomalies);

        let url = format!("https://api.telegram.org/bot{token}/sendMessage");

        let payload = json!({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("Failed to send Telegram message")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Telegram API error: {status} - {text}");
            anyhow::bail!("Telegram API error: {status}");
        }

        info!("Sent Telegram notification for anomaly {txid}");
        Ok(())
    }

    fn log_anomalies(&self, txid: Txid, anomalies: &[Anomaly]) {
        info!("Anomalies detected for transaction {txid}:");
        for anomaly in anomalies {
            info!(" - {anomaly}");
        }
    }

    pub async fn send_startup_message(&self) {
        let message = format!(
            "🚀 Mempool Radar Started\nNetwork: {:?}\nMonitoring mempool for anomalies...",
            self.config.network
        );

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            let token = self.config.telegram_token.as_ref().unwrap();
            let chat_id = self.config.telegram_chat_id.as_ref().unwrap();

            let url = format!("https://api.telegram.org/bot{token}/sendMessage");

            let payload = json!({
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
            });

            if let Err(e) = self
                .client
                .post(&url)
                .json(&payload)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                error!("Failed to send startup message: {}", e);
            }
        }

        info!("{}", message);
    }
}

fn create_telegram_message(txid: Txid, anomalies: &[Anomaly]) -> String {
    let mut message = format!("🚨 <b>Anomalies detected in transaction {txid}</b> 🚨\n\n");

    for anomaly in anomalies {
        message.push_str(anomaly.to_message().as_str());
        message.push_str("\n");
    }

    message.push_str("\nhttps://mempool.space/tx/");
    message.push_str(&txid.to_string());

    message
}
