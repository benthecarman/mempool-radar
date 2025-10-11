pub mod config;
pub mod inspector;
pub mod notifier;
pub mod zmq_listener;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client;
use inspector::Inspector;
use notifier::Notifier;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zmq_listener::{TransactionSource, ZmqListener};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mempool_radar=debug")),
        )
        .init();

    let config = Config::parse();

    info!("Starting Mempool Radar on network: {:?}", config.network);

    // Determine authentication method
    let auth = if let (Some(user), Some(pass)) = (&config.rpc_user, &config.rpc_password) {
        // Use provided username/password
        info!("Using RPC username/password authentication");
        Auth::UserPass(user.clone(), pass.clone())
    } else {
        // Try to get cookie file path
        match config.get_cookie_file_path()? {
            Some(cookie_path) => {
                // Use cookie file authentication
                if cookie_path.exists() {
                    info!(
                        "Using cookie file authentication from: {}",
                        cookie_path.display()
                    );
                    Auth::CookieFile(cookie_path)
                } else {
                    anyhow::bail!(
                        "Cookie file not found at: {}\n\
                        Please ensure Bitcoin Core is running or provide explicit credentials with --rpc-user and --rpc-password",
                        cookie_path.display()
                    );
                }
            }
            None => {
                anyhow::bail!("Unable to determine authentication method");
            }
        }
    };

    let rpc = Client::new_with_auth(&config.rpc_url, auth.clone())
        .context("Failed to create Bitcoin Core RPC client")?;

    let notifier =
        Arc::new(Notifier::new(config.clone()).context("Failed to initialize notifier")?);

    // Send startup message if enabled
    if config.send_startup_message {
        notifier.send_startup_message().await;
    }

    let rpc_clone = Client::new_with_auth(&config.rpc_url, auth)
        .context("Failed to create second Bitcoin Core RPC client")?;
    let inspector = Inspector::new(rpc);

    let (tx_sender, mut tx_receiver) = mpsc::channel(1000);

    let zmq_listener = ZmqListener::new(config.zmq_endpoint.clone(), rpc_clone);
    let zmq_handle = tokio::spawn(async move {
        if let Err(e) = zmq_listener.start(tx_sender).await {
            error!("ZMQ listener error: {e}");
        }
    });

    let processor_handle = tokio::spawn(async move {
        while let Some(tx_with_source) = tx_receiver.recv().await {
            let txid = tx_with_source.txid;
            let tx = &tx_with_source.transaction;
            let from_block = tx_with_source.source == TransactionSource::Block;

            match inspector.analyze_transaction(txid, tx, from_block).await {
                Ok(anomalies) => {
                    if !anomalies.is_empty() {
                        let n = Arc::clone(&notifier);
                        tokio::spawn(async move {
                            if let Err(e) = n.notify(tx_with_source.txid, anomalies).await {
                                error!("Failed to send notification: {e}");
                            }
                        });
                    }
                }
                Err(e) => {
                    error!("Error analyzing transaction {txid}: {e}");
                    continue;
                }
            }
        }
    });

    tokio::select! {
        _ = zmq_handle => {
            error!("ZMQ listener terminated");
        }
        _ = processor_handle => {
            error!("Transaction processor terminated");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }

    Ok(())
}
