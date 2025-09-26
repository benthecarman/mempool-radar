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
