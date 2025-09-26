use anyhow::{Context, Result};
use bitcoin::{Transaction, consensus::encode::deserialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use zeromq::{Socket, SocketRecv};

pub struct ZmqListener {
    endpoint: String,
}

impl ZmqListener {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    pub async fn start(self, tx_sender: mpsc::Sender<Transaction>) -> Result<()> {
        let mut socket = zeromq::SubSocket::new();

        socket
            .connect(&self.endpoint)
            .await
            .context("Failed to connect to ZMQ endpoint")?;

        socket
            .subscribe("rawtx")
            .await
            .context("Failed to subscribe to rawtx")?;

        info!(
            "ZMQ listener connected to {} and subscribed to rawtx",
            self.endpoint
        );

        loop {
            match socket.recv().await {
                Ok(msg) => {
                    let topic = msg
                        .get(0)
                        .and_then(|frame| std::str::from_utf8(frame).ok())
                        .unwrap_or("unknown");

                    if topic == "rawtx"
                        && let Some(tx_data) = msg.get(1)
                    {
                        match deserialize::<Transaction>(tx_data) {
                            Ok(tx) => {
                                let txid = tx.compute_txid();
                                debug!("Received new transaction: {txid}");

                                if let Err(e) = tx_sender.send(tx).await {
                                    error!("Failed to send transaction to processor: {e}");
                                }
                            }
                            Err(e) => {
                                error!("Failed to deserialize transaction: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("ZMQ receive error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}
