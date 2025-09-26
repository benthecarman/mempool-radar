use anyhow::{Context, Result};
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
    sent_messages: HashMap<String, Instant>,
    cooldown: Duration,
}

impl RateLimiter {
    fn new(cooldown_seconds: u64) -> Self {
        Self {
            sent_messages: HashMap::new(),
            cooldown: Duration::from_secs(cooldown_seconds),
        }
    }

    fn should_send(&mut self, key: &str) -> bool {
        let now = Instant::now();

        if let Some(last_sent) = self.sent_messages.get(key)
            && now.duration_since(*last_sent) < self.cooldown
        {
            return false;
        }

        self.sent_messages.insert(key.to_string(), now);

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

    pub async fn notify(&self, anomaly: &Anomaly) -> Result<()> {
        let key = format!("{:?}", anomaly);

        let mut rate_limiter = self.rate_limiter.lock().await;
        if !rate_limiter.should_send(&key) {
            warn!("Rate limited notification for: {}", key);
            return Ok(());
        }
        drop(rate_limiter);

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            self.send_telegram(anomaly).await?;
        } else {
            self.log_anomaly(anomaly);
        }

        Ok(())
    }

    async fn send_telegram(&self, anomaly: &Anomaly) -> Result<()> {
        let token = self.config.telegram_token.as_ref().unwrap();
        let chat_id = self.config.telegram_chat_id.as_ref().unwrap();

        let message = anomaly.to_message();

        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

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
            error!("Telegram API error: {} - {}", status, text);
            anyhow::bail!("Telegram API error: {}", status);
        }

        info!("Sent Telegram notification for anomaly");
        Ok(())
    }

    fn log_anomaly(&self, anomaly: &Anomaly) {
        info!("ANOMALY DETECTED:\n{}", anomaly.to_message());
    }

    pub async fn send_startup_message(&self) {
        let message = format!(
            "🚀 Mempool Radar Started\nNetwork: {:?}\nMonitoring mempool for anomalies...",
            self.config.network
        );

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            let token = self.config.telegram_token.as_ref().unwrap();
            let chat_id = self.config.telegram_chat_id.as_ref().unwrap();

            let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

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
