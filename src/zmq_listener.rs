use anyhow::{Context, Result};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{BlockHash, Transaction, Txid, consensus::encode::deserialize};
use corepc_client::client_sync::v29::Client;
use std::collections::HashSet;
use std::str::FromStr;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zeromq::{Socket, SocketRecv};

pub struct ZmqListener {
    endpoint: String,
    rpc: Client,
    processed_txs: HashSet<Txid>,
    processed_blocks: HashSet<BlockHash>,
}

impl ZmqListener {
    pub fn new(endpoint: String, rpc: Client) -> Self {
        Self {
            endpoint,
            rpc,
            processed_txs: HashSet::with_capacity(11_000),
            processed_blocks: HashSet::with_capacity(60),
        }
    }

    #[tracing::instrument(skip(self, tx_sender))]
    pub async fn start(mut self, tx_sender: mpsc::Sender<Transaction>) -> Result<()> {
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

                    if topic == "sequence" {
                        if let Err(e) = self.process_sequence_message(&msg, &tx_sender).await {
                            error!("Failed to process sequence message: {e}");
                        }
                    } else {
                        warn!("Received message with unknown topic: {topic}");
                    }
                }
                Err(e) => {
                    error!("ZMQ receive error: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    #[tracing::instrument(skip(self, msg, tx_sender))]
    async fn process_sequence_message(
        &mut self,
        msg: &zeromq::ZmqMessage,
        tx_sender: &mpsc::Sender<Transaction>,
    ) -> Result<()> {
        if msg.len() < 3 {
            warn!("Invalid sequence message length {}", msg.len());
            return Ok(());
        }

        let topic = msg.get(0).context("Missing topic in sequence message")?;
        if topic.to_vec() != b"sequence" {
            warn!("Invalid topic in sequence message: {topic:?}");
            return Ok(());
        }

        let body = &msg.get(1).context("Missing body in sequence message")?;

        // mempool sequence message format:
        // [32 bytes tx hash][1 byte event type][4 bytes sequence number]
        // block sequence message format:
        // [32 bytes block hash][1 byte event type]
        if body.len() != 41 && body.len() != 37 {
            return Ok(());
        }

        let hash_bytes = &body[0..32];
        let event_type_byte = &body[32..33];

        let event_type = event_type_byte[0] as char;

        let hash_hex = hash_bytes.to_lower_hex_string();

        match event_type {
            'A' => {
                if body.len() != 41 {
                    warn!("Invalid mempool sequence message length {}", body.len());
                    return Ok(());
                }
                let sequence_bytes = &body[33..37];
                let sequence_num = u32::from_le_bytes([
                    sequence_bytes[0],
                    sequence_bytes[1],
                    sequence_bytes[2],
                    sequence_bytes[3],
                ]);
                debug!("Transaction added to mempool: {hash_hex} (seq: {sequence_num})");

                if let Ok(txid) = Txid::from_str(hash_hex.as_str()) {
                    if self.processed_txs.contains(&txid) {
                        debug!("Skipping already processed transaction: {txid}");
                        return Ok(());
                    }

                    match self.rpc.get_raw_transaction(txid) {
                        Ok(raw_tx_response) => match <Vec<u8>>::from_hex(&raw_tx_response.0) {
                            Ok(raw_tx_bytes) => match deserialize::<Transaction>(&raw_tx_bytes) {
                                Ok(tx) => {
                                    self.processed_txs.insert(txid);
                                    if let Err(e) = tx_sender.send(tx).await {
                                        error!("Failed to send transaction to processor: {e}");
                                    }

                                    // Periodically cleanup old entries (every 1,000 txs)
                                    if self.processed_txs.len().is_multiple_of(1_000) {
                                        self.cleanup_old_entries();
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
                if body.len() != 41 {
                    warn!("Invalid mempool sequence message length {}", body.len());
                    return Ok(());
                }
                let sequence_bytes = &body[33..37];
                let sequence_num = u32::from_le_bytes([
                    sequence_bytes[0],
                    sequence_bytes[1],
                    sequence_bytes[2],
                    sequence_bytes[3],
                ]);
                debug!("Transaction removed from mempool: {hash_hex} (seq: {sequence_num})");
            }
            'C' => {
                debug!("Block connected: {hash_hex}");

                if let Ok(block_hash) = BlockHash::from_str(hash_hex.as_str()) {
                    if self.processed_blocks.contains(&block_hash) {
                        debug!("Skipping already processed block: {block_hash}");
                        return Ok(());
                    }

                    if let Err(e) = self.process_block(block_hash, tx_sender).await {
                        error!("Failed to process block {block_hash}: {e}");
                    } else {
                        self.processed_blocks.insert(block_hash);
                    }
                } else {
                    error!("Invalid block hash format: {hash_hex}");
                }
            }
            'D' => {
                debug!("Block disconnected: {hash_hex}");
            }
            _ => {
                warn!("Unknown sequence event type: {event_type}");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, tx_sender))]
    async fn process_block(
        &mut self,
        block_hash: BlockHash,
        tx_sender: &mpsc::Sender<Transaction>,
    ) -> Result<()> {
        info!("Processing block: {block_hash}");

        // Fetch the block
        let block = self
            .rpc
            .get_block(block_hash)
            .context("Failed to fetch block")?;

        let mut new_txs = 0;
        let mut skipped_txs = 0;

        // Process each transaction in the block
        for tx in block.txdata {
            if tx.is_coinbase() {
                continue; // Skip coinbase
            }

            let txid = tx.compute_txid();
            if self.processed_txs.contains(&txid) {
                skipped_txs += 1;
                continue;
            }

            self.processed_txs.insert(txid);
            new_txs += 1;
            if let Err(e) = tx_sender.send(tx).await {
                error!("Failed to send transaction to processor: {e}");
            }
        }

        info!(
            "Block {block_hash} processed: {new_txs} new transactions, {skipped_txs} already seen"
        );

        // Periodically cleanup old entries (every 10 blocks)
        if self.processed_blocks.len().is_multiple_of(10) {
            self.cleanup_old_entries();
        }

        Ok(())
    }

    fn cleanup_old_entries(&mut self) {
        let tx_count = self.processed_txs.len();
        let block_count = self.processed_blocks.len();

        // Keep only the most recent entries (prevent unbounded growth)
        // Keep last 10,000 txs and 50 blocks
        if tx_count > 10_000 {
            let to_remove = tx_count - 10_000;
            let txs_to_remove: Vec<Txid> =
                self.processed_txs.iter().take(to_remove).copied().collect();
            for tx in txs_to_remove {
                self.processed_txs.remove(&tx);
            }
            info!("Cleaned up {to_remove} old transaction entries");
        }

        if block_count > 50 {
            let to_remove = block_count - 50;
            let blocks_to_remove: Vec<BlockHash> = self
                .processed_blocks
                .iter()
                .take(to_remove)
                .copied()
                .collect();
            for block in blocks_to_remove {
                self.processed_blocks.remove(&block);
            }
            info!("Cleaned up {to_remove} old block entries");
        }
    }
}
