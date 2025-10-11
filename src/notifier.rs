use anyhow::{Context, Result};
use bitcoin::Txid;
use egg_mode::Token;
use egg_mode::tweet::DraftTweet;
use nostr_sdk::{Client as NostrClient, EventBuilder, Keys};
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
    nostr_keys: Option<Keys>,
    twitter_token: Option<Token>,
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
    pub fn new(config: Config) -> Result<Self> {
        let telegram = config.telegram_token.is_some() && config.telegram_chat_id.is_some();

        // Parse Nostr keys if private key is provided
        let nostr_keys = if let Some(ref private_key) = config.nostr_private_key {
            match Keys::parse(private_key) {
                Ok(keys) => {
                    info!("Nostr keys parsed successfully");
                    Some(keys)
                }
                Err(e) => {
                    error!("Failed to parse Nostr private key: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Set up Twitter token if all credentials are provided
        let twitter_token = if let (
            Some(consumer_key),
            Some(consumer_secret),
            Some(access_token),
            Some(access_token_secret),
        ) = (
            &config.twitter_consumer_key,
            &config.twitter_consumer_secret,
            &config.twitter_access_token,
            &config.twitter_access_token_secret,
        ) {
            let con_token = egg_mode::KeyPair::new(consumer_key.clone(), consumer_secret.clone());
            let access_token_kp =
                egg_mode::KeyPair::new(access_token.clone(), access_token_secret.clone());
            let token = Token::Access {
                consumer: con_token,
                access: access_token_kp,
            };
            info!("Twitter credentials configured successfully");
            Some(token)
        } else {
            None
        };

        Ok(Self {
            config,
            client: Client::new(),
            nostr_keys,
            twitter_token,
            rate_limiter: Mutex::new(RateLimiter::new(telegram)),
        })
    }

    pub async fn notify(&self, txid: Txid, anomalies: Vec<Anomaly>) -> Result<()> {
        self.log_anomalies(txid, &anomalies);

        let has_telegram =
            self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some();
        let has_nostr = self.nostr_keys.is_some();
        let has_twitter = self.twitter_token.is_some();

        // Send to all services in parallel
        let telegram_future = async {
            if has_telegram {
                // Check if we need to wait for rate limiting (for Telegram only)
                let mut rate_limiter = self.rate_limiter.lock().await;
                if let Some(wait_time) = rate_limiter.time_until_next_send() {
                    drop(rate_limiter);
                    tokio::time::sleep(wait_time).await;
                    rate_limiter = self.rate_limiter.lock().await;
                }
                rate_limiter.mark_sent();
                drop(rate_limiter);

                if let Err(e) = self.send_telegram(txid, anomalies.clone()).await {
                    error!("Failed to send Telegram notification: {e}");
                }
            }
        };

        let nostr_future = async {
            if has_nostr {
                if let Err(e) = self.send_nostr(txid, &anomalies).await {
                    error!("Failed to send Nostr notification: {e}");
                }
            }
        };

        let twitter_future = async {
            if has_twitter {
                if let Err(e) = self.send_twitter(txid, &anomalies).await {
                    error!("Failed to send Twitter notification: {e}");
                }
            }
        };

        // Send to all services in parallel
        tokio::join!(telegram_future, nostr_future, twitter_future);

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

    async fn send_nostr(&self, txid: Txid, anomalies: &[Anomaly]) -> Result<()> {
        let keys = self.nostr_keys.as_ref().context("Nostr keys not set")?;

        let message = create_nostr_message(txid, anomalies);

        // Create a new client and connect on-demand
        let client = NostrClient::new(keys.clone());

        // Add relays
        for relay in &self.config.nostr_relays {
            client.add_relay(relay).await?;
        }

        // Connect to relays
        client.connect().await;

        // Create a text note event (kind 1) and publish
        let builder = EventBuilder::text_note(&message);
        client.send_event_builder(builder).await?;

        info!("Sent Nostr notification for anomaly {txid}");

        if let Err(e) = client.disconnect().await {
            error!("Failed to disconnect Nostr client: {e}");
        }

        Ok(())
    }

    async fn send_twitter(&self, txid: Txid, anomalies: &[Anomaly]) -> Result<()> {
        let token = self
            .twitter_token
            .as_ref()
            .context("Twitter token not set")?;

        let message = create_twitter_message(txid, anomalies);

        // Send the tweet
        let draft = DraftTweet::new(message);
        draft.send(token).await.context("Failed to send tweet")?;

        info!("Sent Twitter notification for anomaly {txid}");
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

        // Send to Telegram if configured
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
                error!("Failed to send Telegram startup message: {e}");
            }
        }

        // Send to Nostr if configured
        if let Some(ref keys) = self.nostr_keys {
            // Create a new client and connect on-demand
            let client = NostrClient::new(keys.clone());

            // Add relays
            for relay in &self.config.nostr_relays {
                if let Err(e) = client.add_relay(relay).await {
                    error!("Failed to add Nostr relay {relay}: {e}");
                    continue;
                }
            }

            // Connect to relays
            client.connect().await;

            let builder = EventBuilder::text_note(&message);
            if let Err(e) = client.send_event_builder(builder).await {
                error!("Failed to send Nostr startup message: {e}");
            }
        }

        // Send to Twitter if configured
        if let Some(ref token) = self.twitter_token {
            let draft = DraftTweet::new(message.clone());
            if let Err(e) = draft.send(token).await {
                error!("Failed to send Twitter startup message: {e}");
            }
        }

        info!("{message}");
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

fn create_nostr_message(txid: Txid, anomalies: &[Anomaly]) -> String {
    let mut message = format!("🚨 Anomalies detected in transaction {txid} 🚨\n\n");

    for anomaly in anomalies {
        message.push_str(&anomaly.to_string());
        message.push('\n');
    }

    message.push_str("\nhttps://mempool.space/tx/");
    message.push_str(&txid.to_string());

    message
}

fn create_twitter_message(txid: Txid, anomalies: &[Anomaly]) -> String {
    use std::collections::HashSet;

    const TWITTER_LIMIT: usize = 280;

    // 24 chars
    let header = "🚨 Anomaly Detected 🚨\n\n";

    // ~89 chars (26 + 64 for txid)
    let footer = format!("\nhttps://mempool.space/tx/{txid}");

    // Available space for anomaly content
    let available_space = TWITTER_LIMIT - header.len() - footer.len();

    // Group anomalies by type (discriminant) to get unique types
    let mut seen_types = HashSet::new();
    let mut unique_anomalies = Vec::new();

    for anomaly in anomalies {
        let disc = std::mem::discriminant(anomaly);
        if seen_types.insert(disc) {
            unique_anomalies.push(anomaly);
        }
    }

    let anomaly_count = anomalies.len();

    // Build anomaly section
    let mut content = String::new();

    if anomaly_count == 1 {
        // Single anomaly
        let line = format!("{}\n", anomalies[0]);
        if line.len() <= available_space {
            content = line;
        } else {
            content = "Anomaly details too long\n".to_string();
        }
    } else {
        // Add unique anomalies one by one, checking if they fit
        for anomaly in &unique_anomalies {
            let line = format!("{anomaly}\n");

            if content.len() + line.len() <= available_space {
                content.push_str(&line);
            } else {
                // Can't fit anymore, stop here
                break;
            }
        }
    }

    // Build final message
    let mut message = String::from(header);
    message.push_str(&content);
    message.push_str(&footer);

    message
}
