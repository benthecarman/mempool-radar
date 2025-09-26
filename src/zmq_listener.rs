use anyhow::{Context, Result};
use bitcoin::hex::FromHex;
use bitcoin::{Transaction, Txid, consensus::encode::deserialize};
use corepc_client::client_sync::v29::Client;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zeromq::{Socket, SocketRecv};

pub struct ZmqListener {
    endpoint: String,
    rpc: Client,
}

impl ZmqListener {
    pub fn new(endpoint: String, rpc: Client) -> Self {
        Self { endpoint, rpc }
    }

    pub async fn start(self, tx_sender: mpsc::Sender<Transaction>) -> Result<()> {
        let mut socket = zeromq::SubSocket::new();

        socket
            .connect(&self.endpoint)
            .await
            .context("Failed to connect to ZMQ endpoint")?;

        socket
            .subscribe("sequence")
            .await
            .context("Failed to subscribe to sequence")?;

        info!(
            "ZMQ listener connected to {} and subscribed to sequence",
            self.endpoint
        );

        loop {
            match socket.recv().await {
                Ok(msg) => {
                    let topic = msg
                        .get(0)
                        .and_then(|frame| std::str::from_utf8(frame).ok())
                        .unwrap_or("unknown");

                    if topic == "sequence"
                        && let Err(e) = self.process_sequence_message(&msg, &tx_sender).await
                    {
                        error!("Failed to process sequence message: {e}");
                    }
                }
                Err(e) => {
                    error!("ZMQ receive error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn process_sequence_message(
        &self,
        msg: &zeromq::ZmqMessage,
        tx_sender: &mpsc::Sender<Transaction>,
    ) -> Result<()> {
        if msg.len() < 4 {
            return Ok(());
        }

        let hash_bytes = msg.get(1).context("Missing hash in sequence message")?;
        let event_type_byte = msg
            .get(2)
            .context("Missing event type in sequence message")?;
        let sequence_bytes = msg.get(3).context("Missing sequence number")?;

        if hash_bytes.len() != 32 || event_type_byte.len() != 1 || sequence_bytes.len() != 4 {
            warn!("Invalid sequence message format");
            return Ok(());
        }

        let event_type = event_type_byte[0] as char;
        let sequence_num = u32::from_le_bytes([
            sequence_bytes[0],
            sequence_bytes[1],
            sequence_bytes[2],
            sequence_bytes[3],
        ]);

        let reversed_hash: Vec<u8> = hash_bytes.iter().rev().cloned().collect();
        let hash_hex = reversed_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        match event_type {
            'A' => {
                debug!(
                    "Transaction added to mempool: {} (seq: {})",
                    hash_hex, sequence_num
                );

                if let Ok(txid) = hash_hex.parse::<Txid>() {
                    match self.rpc.get_raw_transaction(txid) {
                        Ok(raw_tx_response) => match <Vec<u8>>::from_hex(&raw_tx_response.0) {
                            Ok(raw_tx_bytes) => match deserialize::<Transaction>(&raw_tx_bytes) {
                                Ok(tx) => {
                                    if let Err(e) = tx_sender.send(tx).await {
                                        error!("Failed to send transaction to processor: {e}");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to deserialize transaction {hash_hex}: {e}");
                                }
                            },
                            Err(e) => {
                                error!("Failed to decode hex transaction data for {hash_hex}: {e}");
                            }
                        },
                        Err(e) => {
                            debug!(
                                "Failed to fetch transaction {hash_hex} (may have been removed from mempool): {e}"
                            );
                        }
                    }
                } else {
                    error!("Invalid transaction hash format: {hash_hex}");
                }
            }
            'R' => {
                debug!("Transaction removed from mempool: {hash_hex} (seq: {sequence_num})");
            }
            'C' => {
                debug!("Block connected: {hash_hex} (seq: {sequence_num})");
            }
            'D' => {
                debug!("Block disconnected: {hash_hex} (seq: {sequence_num})");
            }
            _ => {
                warn!("Unknown sequence event type: {event_type}");
            }
        }

        Ok(())
    }
}
