use anyhow::{Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{BlockHash, Transaction, Txid};
use corepc_client::client_sync::v29::Client;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use zeromq::{Socket, SocketRecv};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransactionSource {
    Mempool,
    Block,
}

#[derive(Debug, Clone)]
pub struct TransactionWithSource {
    pub transaction: Transaction,
    pub source: TransactionSource,
}

pub struct ZmqListener {
    endpoint: String,
    rpc: Client,
    processed_txs: HashMap<Txid, Instant>,
    processed_blocks: HashMap<BlockHash, Instant>,
}

impl ZmqListener {
    pub fn new(endpoint: String, rpc: Client) -> Self {
        Self {
            endpoint,
            rpc,
            processed_txs: HashMap::with_capacity(11_000),
            processed_blocks: HashMap::with_capacity(60),
        }
    }

    #[tracing::instrument(skip(self, tx_sender))]
    pub async fn start(mut self, tx_sender: mpsc::Sender<TransactionWithSource>) -> Result<()> {
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
        tx_sender: &mpsc::Sender<TransactionWithSource>,
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
        if body.len() != 41 && body.len() != 33 {
            warn!("Invalid sequence message body length {}", body.len());
            return Ok(());
        }

        let mut hash_bytes: [u8; 32] = body[0..32].try_into()?;
        let event_type_byte = &body[32..33];

        let event_type = event_type_byte[0] as char;

        let hash_hex = hash_bytes.to_lower_hex_string();

        hash_bytes.reverse(); // Convert from little-endian to big-endian

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
                trace!("Transaction added to mempool: {hash_hex} (seq: {sequence_num})");

                let txid = Txid::from_byte_array(hash_bytes);

                if self.processed_txs.contains_key(&txid) {
                    debug!("Skipping already processed transaction: {txid}");
                    return Ok(());
                }

                match self.rpc.get_raw_transaction(txid) {
                    Ok(tx) => match tx.transaction() {
                        Ok(transaction) => {
                            self.processed_txs.insert(txid, Instant::now());
                            if let Err(e) = tx_sender
                                .send(TransactionWithSource {
                                    transaction,
                                    source: TransactionSource::Mempool,
                                })
                                .await
                            {
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
                        error!("Failed to get raw transaction: {hash_hex}: {e}");
                    }
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
                trace!("Transaction removed from mempool: {hash_hex} (seq: {sequence_num})");
            }
            'C' => {
                debug!("Block connected: {hash_hex}");

                let block_hash = BlockHash::from_byte_array(hash_bytes);

                if self.processed_blocks.contains_key(&block_hash) {
                    debug!("Skipping already processed block: {block_hash}");
                    return Ok(());
                }

                if let Err(e) = self.process_block(block_hash, tx_sender).await {
                    error!("Failed to process block {block_hash}: {e}");
                } else {
                    self.processed_blocks.insert(block_hash, Instant::now());
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
        tx_sender: &mpsc::Sender<TransactionWithSource>,
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
        let mut found_coinbase = false;
        for tx in block.txdata {
            if !found_coinbase && tx.is_coinbase() {
                found_coinbase = true;
                continue; // Skip coinbase
            }

            let txid = tx.compute_txid();
            if self.processed_txs.contains_key(&txid) {
                skipped_txs += 1;
                continue;
            }

            self.processed_txs.insert(txid, Instant::now());
            new_txs += 1;
            if let Err(e) = tx_sender
                .send(TransactionWithSource {
                    transaction: tx,
                    source: TransactionSource::Block,
                })
                .await
            {
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
            let mut oldest: Vec<_> = self
                .processed_txs
                .iter()
                .map(|(txid, instant)| (*txid, *instant))
                .collect();
            oldest.sort_by_key(|(_, instant)| *instant);

            for (txid, _) in oldest.iter().take(to_remove) {
                self.processed_txs.remove(txid);
            }
            info!("Cleaned up {to_remove} old transaction entries");
        }

        if block_count > 50 {
            let to_remove = block_count - 50;
            let mut oldest: Vec<_> = self
                .processed_blocks
                .iter()
                .map(|(hash, instant)| (*hash, *instant))
                .collect();
            oldest.sort_by_key(|(_, instant)| *instant);

            for (hash, _) in oldest.iter().take(to_remove) {
                self.processed_blocks.remove(hash);
            }
            info!("Cleaned up {to_remove} old block entries");
        }
    }
}
