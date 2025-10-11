use bitcoin::Network;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// Mempool Radar
pub struct Config {
    /// Network bitcoind is running on ["bitcoin", "testnet", "signet, "regtest"]
    #[clap(default_value_t = Network::Bitcoin, short, long, env = "MEMPOOL_RADAR_NETWORK")]
    pub network: Network,

    /// Telegram bot token for sending notifications
    #[clap(long, env = "MEMPOOL_RADAR_TELEGRAM_TOKEN")]
    pub telegram_token: Option<String>,

    /// Telegram chat id for sending notifications
    #[clap(long, env = "MEMPOOL_RADAR_TELEGRAM_CHAT_ID")]
    pub telegram_chat_id: Option<String>,

    /// Nostr private key (nsec or hex format) for signing events
    #[clap(long, env = "MEMPOOL_RADAR_NOSTR_PRIVATE_KEY")]
    pub nostr_private_key: Option<String>,

    /// Nostr relays to publish events to (comma-separated)
    #[clap(
        long,
        env = "MEMPOOL_RADAR_NOSTR_RELAYS",
        value_delimiter = ',',
        default_value = "wss://relay.damus.io,wss://relay.primal.net,wss://nos.lol"
    )]
    pub nostr_relays: Vec<String>,

    /// Twitter API consumer key
    #[clap(long, env = "MEMPOOL_RADAR_TWITTER_CONSUMER_KEY")]
    pub twitter_consumer_key: Option<String>,

    /// Twitter API consumer secret
    #[clap(long, env = "MEMPOOL_RADAR_TWITTER_CONSUMER_SECRET")]
    pub twitter_consumer_secret: Option<String>,

    /// Twitter API access token
    #[clap(long, env = "MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN")]
    pub twitter_access_token: Option<String>,

    /// Twitter API access token secret
    #[clap(long, env = "MEMPOOL_RADAR_TWITTER_ACCESS_TOKEN_SECRET")]
    pub twitter_access_token_secret: Option<String>,

    /// Bitcoin Core RPC URL
    #[clap(default_value_t = String::from("http://127.0.0.1:8332"), long, env = "MEMPOOL_RADAR_RPC_URL")]
    pub rpc_url: String,

    /// Bitcoin Core RPC username
    #[clap(long, env = "MEMPOOL_RADAR_RPC_USER")]
    pub rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[clap(long, env = "MEMPOOL_RADAR_RPC_PASSWORD")]
    pub rpc_password: Option<String>,

    /// Path to Bitcoin Core cookie file (auto-detected if not specified)
    #[clap(long, env = "MEMPOOL_RADAR_COOKIE_FILE")]
    pub cookie_file: Option<PathBuf>,

    /// ZMQ endpoint for sequence notifications
    #[clap(default_value_t = String::from("tcp://127.0.0.1:28332"), long, env = "MEMPOOL_RADAR_ZMQ_ENDPOINT")]
    pub zmq_endpoint: String,

    /// Large transaction size threshold in bytes
    #[clap(default_value_t = 100_000, long, env = "MEMPOOL_RADAR_LARGE_TX_SIZE")]
    pub large_tx_size: usize,

    /// Maximum number of ancestor transactions before flagging as anomaly
    #[clap(default_value_t = 25, long, env = "MEMPOOL_RADAR_MAX_ANCESTORS")]
    pub max_ancestors: u32,

    /// Maximum number of descendant transactions before flagging as anomaly
    #[clap(default_value_t = 25, long, env = "MEMPOOL_RADAR_MAX_DESCENDANTS")]
    pub max_descendants: u32,

    /// Maximum package size in bytes before flagging as anomaly
    #[clap(
        default_value_t = 101_000,
        long,
        env = "MEMPOOL_RADAR_MAX_PACKAGE_SIZE"
    )]
    pub max_package_size: usize,
}

impl Config {
    /// Get the Bitcoin Core data directory based on the network
    pub fn bitcoin_data_dir(&self) -> anyhow::Result<PathBuf> {
        let home =
            home::home_dir().ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;

        let base_dir = match std::env::consts::OS {
            "macos" => home.join("Library/Application Support/Bitcoin"),
            "windows" => std::env::var("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join("AppData/Roaming"))
                .join("Bitcoin"),
            _ => home.join(".bitcoin"), // Linux and others
        };

        Ok(match self.network {
            Network::Bitcoin => base_dir,
            Network::Testnet => base_dir.join("testnet3"),
            Network::Testnet4 => base_dir.join("testnet4"),
            Network::Signet => base_dir.join("signet"),
            Network::Regtest => base_dir.join("regtest"),
        })
    }

    /// Get the cookie file path (either explicit or auto-detected)
    pub fn get_cookie_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        // First check if explicitly provided
        if let Some(ref cookie) = self.cookie_file {
            return Ok(Some(cookie.clone()));
        }

        // Use standard location
        Ok(Some(self.bitcoin_data_dir()?.join(".cookie")))
    }
}
