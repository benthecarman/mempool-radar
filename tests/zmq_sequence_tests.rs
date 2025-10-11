use anyhow::{Context, Result};
use bitcoin::{Amount, BlockHash, Network, Txid};
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v17::{Input, Output};
use corepc_client::client_sync::v29::Client;
use corepc_node::{Conf, Node as Bitcoind, get_available_port};
use mempool_radar::zmq_listener::{TransactionWithSource, ZmqListener};
use std::str::FromStr;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{Instrument, Level, debug};

const RPC_USER: &str = "user";
const RPC_PASS: &str = "pass";

async fn setup_test() -> Result<(Bitcoind, mpsc::Receiver<TransactionWithSource>)> {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .try_init()
        .ok();

    let zmq = get_available_port()?;
    let bitcoind = create_bitcoind(zmq);
    let config = create_config(zmq, bitcoind.rpc_url());

    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;

    let (tx_sender, tx_receiver) = mpsc::channel(1000);
    let zmq_listener = ZmqListener::new(config.zmq_endpoint.clone(), rpc);

    tokio::spawn(
        async move {
            if let Err(e) = zmq_listener.start(tx_sender).await {
                tracing::error!("ZMQ listener error: {e}");
            }
        }
        .instrument(tracing::info_span!("zmq_listener")),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok((bitcoind, tx_receiver))
}

#[tokio::test]
async fn test_zmq_listener() -> Result<()> {
    let (bitcoind, mut tx_receiver) = setup_test().await?;

    // Generate a tx to trigger a sequence message
    let address = bitcoin::Address::from_str("bcrt1qfehlhwqmwc3x39h5z4fw0vygqkdc82qxjchzds")?;
    let sent = bitcoind
        .client
        .send_to_address(&address.assume_checked(), Amount::from_btc(1.)?)?;
    debug!(
        "Sent transaction to trigger ZMQ sequence message {}",
        sent.0
    );

    // Wait for the transaction to be received via ZMQ
    let received_tx_with_source =
        tokio::time::timeout(Duration::from_secs(10), tx_receiver.recv()).await?;

    assert!(!tx_receiver.is_closed());
    assert_eq!(received_tx_with_source.unwrap().transaction.output.len(), 2);

    // Generate a block to confirm the transaction and trigger another sequence message
    generate_blocks(&bitcoind, 1);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // We should not receive any more transactions since it was already processed from mempool
    assert_eq!(tx_receiver.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_block_processing() -> Result<()> {
    let (bitcoind, mut tx_receiver) = setup_test().await?;

    // Create a raw transaction without broadcasting it to mempool
    let address = bitcoin::Address::from_str("bcrt1qfehlhwqmwc3x39h5z4fw0vygqkdc82qxjchzds")?
        .assume_checked();

    // Get a UTXO from the wallet using list_unspent
    let unspent = bitcoind.client.list_unspent()?;
    let utxo = unspent.0.first().context("No UTXOs available")?;

    // Create inputs and outputs for raw transaction
    let input = Input {
        txid: Txid::from_str(&utxo.txid)?,
        vout: utxo.vout as u64,
        sequence: None,
    };
    let output = Output::new(address, Amount::from_btc(0.5)?);

    // Create raw transaction
    let created = bitcoind
        .client
        .create_raw_transaction(&[input], &[output])?;

    let tx = created.transaction()?;

    // Sign the transaction
    let signed = bitcoind.client.sign_raw_transaction_with_wallet(&tx)?;

    // Mine a block with this transaction using generateblock so it bypasses the mempool
    let mine_address = bitcoind.client.new_address()?;
    let block_result =
        bitcoind
            .client
            .generate_block(&mine_address.to_string(), &[signed.hex], true)?;

    debug!(
        "Mined block with transaction bypassing mempool: {}",
        block_result.hash
    );

    // Invalidate and reconsider the block to trigger ZMQ notifications
    let block_hash = BlockHash::from_str(&block_result.hash)?;
    bitcoind.client.invalidate_block(block_hash)?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _: serde_json::Value = bitcoind
        .client
        .call("reconsiderblock", &[serde_json::json!(block_result.hash)])?;

    // Wait for block to be processed
    tokio::time::sleep(Duration::from_secs(2)).await;

    // We should receive 1 transaction from the block (not from mempool)
    let mut block_tx_count = 0;
    while let Ok(Some(tx_with_source)) =
        tokio::time::timeout(Duration::from_secs(1), tx_receiver.recv()).await
    {
        debug!("Received transaction: {}", tx_with_source.txid);
        block_tx_count += 1;
    }

    debug!("Total transactions received from block: {block_tx_count}");

    assert_eq!(
        block_tx_count, 1,
        "Should receive 1 transaction from block that was never in mempool"
    );

    Ok(())
}

fn create_bitcoind(zmq: u16) -> Bitcoind {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    conf.args.push("-rpcworkqueue=100");
    conf.args.push("-rpcauth=user:ac6353465c83ab76d9f9aa48ca5310f4$ebac2905e61287be9805709beb971a51696ae8802aa3c74e7057359e0975b2c5");

    let zmq_port = format!("-zmqpubsequence=tcp://127.0.0.1:{zmq}");
    conf.args.push(&zmq_port);

    let bitcoind = Bitcoind::with_conf(corepc_node::downloaded_exe_path().unwrap(), &conf)
        .expect("failed to start bitcoind");

    // Wait for bitcoind to be ready before returning
    wait_for_bitcoind_ready(&bitcoind);

    let address = bitcoind.client.new_address().unwrap();
    let _block_hashes = bitcoind.client.generate_to_address(101, &address).unwrap();

    bitcoind
}

fn wait_for_bitcoind_ready(bitcoind: &Bitcoind) {
    let max_attempts = 30;
    let delay = Duration::from_millis(500);

    for attempt in 0..max_attempts {
        match bitcoind.client.get_blockchain_info() {
            Ok(_) => {
                debug!("bitcoind ready after {attempt} attempts");
                return;
            }
            Err(e) => {
                if attempt == max_attempts {
                    panic!("bitcoind failed to become ready after {max_attempts} attempts: {e}");
                }
                debug!("bitcoind not ready, attempt {attempt}/{max_attempts}: {e}");
                std::thread::sleep(delay);
            }
        }
    }
}

pub fn generate_blocks(bitcoind: &Bitcoind, num: usize) {
    let address = bitcoind.client.new_address().unwrap();
    let _block_hashes = bitcoind
        .client
        .generate_to_address(num, &address)
        .unwrap_or_else(|_| panic!("failed to generate {num} blocks"));
}

fn create_config(zmq: u16, rpc_url: String) -> mempool_radar::Config {
    mempool_radar::Config {
        network: Network::Regtest,
        telegram_token: None,
        telegram_chat_id: None,
        nostr_private_key: None,
        nostr_relays: vec![],
        twitter_consumer_key: None,
        twitter_consumer_secret: None,
        twitter_access_token: None,
        twitter_access_token_secret: None,
        rpc_url,
        rpc_user: Some(RPC_USER.to_string()),
        rpc_password: Some(RPC_PASS.to_string()),
        cookie_file: None,
        zmq_endpoint: format!("tcp://127.0.0.1:{zmq}"),
        large_tx_size: 100_000,
        max_ancestors: 25,
        max_descendants: 25,
        max_package_size: 101_000,
    }
}
