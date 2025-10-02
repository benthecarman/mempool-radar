use anyhow::{Context, Result};
use bitcoin::Txid;
use reqwest::Client;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::config::Config;
use crate::inspector::Anomaly;

pub struct Notifier {
    config: Config,
    client: Client,
    rate_limiter: Mutex<RateLimiter>,
}

struct RateLimiter {
    telegram: bool,
    last_send: Option<Instant>,
}

impl RateLimiter {
    fn new(telegram: bool) -> Self {
        Self {
            telegram,
            last_send: None,
        }
    }

    fn time_until_next_send(&self) -> Option<Duration> {
        if !self.telegram {
            return None;
        }

        if let Some(last) = self.last_send {
            let elapsed = Instant::now().duration_since(last);
            let rate_limit = Duration::from_secs(1);

            if elapsed < rate_limit {
                return Some(rate_limit - elapsed);
            }
        }

        None
    }

    fn mark_sent(&mut self) {
        self.last_send = Some(Instant::now());
    }
}

impl Notifier {
    pub fn new(config: Config) -> Self {
        let telegram = config.telegram_token.is_some() && config.telegram_chat_id.is_some();

        Self {
            config,
            client: Client::new(),
            rate_limiter: Mutex::new(RateLimiter::new(telegram)),
        }
    }

    pub async fn notify(&self, txid: Txid, anomalies: Vec<Anomaly>) -> Result<()> {
        // Check if we need to wait for rate limiting
        let mut rate_limiter = self.rate_limiter.lock().await;
        if let Some(wait_time) = rate_limiter.time_until_next_send() {
            drop(rate_limiter);
            tokio::time::sleep(wait_time).await;
            rate_limiter = self.rate_limiter.lock().await;
        }

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            rate_limiter.mark_sent();
            drop(rate_limiter);
            self.send_telegram(txid, anomalies).await?;
        } else {
            drop(rate_limiter);
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
        message.push('\n');
    }

    message.push_str("\nhttps://mempool.space/tx/");
    message.push_str(&txid.to_string());

    message
}
