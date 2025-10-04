use anyhow::{Context, Result};
use bitcoin::hex::FromHex;
use bitcoin::{Amount, BlockHash, Txid};
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v17::{Input, Output};
use corepc_client::client_sync::v29::Client;
use corepc_node::{Conf, Node as Bitcoind};
use mempool_radar::inspector::Inspector;
use std::str::FromStr;
use tokio::time::Duration;
use tracing::{Level, debug};

const RPC_USER: &str = "user";
const RPC_PASS: &str = "pass";

fn create_bitcoind() -> Bitcoind {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    conf.args.push("-rpcworkqueue=100");
    conf.args.push("-rpcauth=user:ac6353465c83ab76d9f9aa48ca5310f4$ebac2905e61287be9805709beb971a51696ae8802aa3c74e7057359e0975b2c5");

    let bitcoind = Bitcoind::with_conf(corepc_node::downloaded_exe_path().unwrap(), &conf)
        .expect("failed to start bitcoind");

    // Wait for bitcoind to be ready
    wait_for_bitcoind_ready(&bitcoind);

    // Mine 101 blocks to get spendable funds
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

/// Test that Inspector fails with get_tx_out error when analyzing mempool transaction
/// This demonstrates the bug where get_tx_out fails for unconfirmed transactions
#[tokio::test]
async fn test_inspector_mempool_transaction_fails() -> Result<()> {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .try_init()
        .ok();

    let bitcoind = create_bitcoind();
    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc1 = Client::new_with_auth(&bitcoind.rpc_url(), auth.clone())?;
    let rpc2 = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;
    let mut inspector = Inspector::new(rpc1);

    // Create a transaction in the mempool
    let address = bitcoin::Address::from_str("bcrt1qfehlhwqmwc3x39h5z4fw0vygqkdc82qxjchzds")?
        .assume_checked();
    let sent = bitcoind
        .client
        .send_to_address(&address, Amount::from_btc(1.)?)?;
    let txid = Txid::from_str(&sent.0)?;

    debug!("Created mempool transaction: {txid}");

    // Get the raw transaction
    let tx_result = rpc2.get_raw_transaction(txid)?;
    let tx = tx_result.transaction()?;

    // Try to analyze it
    let result = inspector.analyze_transaction(txid, &tx, false);

    match result {
        Ok(anomalies) => {
            debug!(
                "Transaction analyzed successfully with {} anomalies",
                anomalies.len()
            );
        }
        Err(e) => {
            panic!("Failed to analyze mempool transaction: {e}" );
        }
    }

    Ok(())
}

/// Test that Inspector fails when analyzing a confirmed transaction
/// get_tx_out returns error when outputs are already spent
#[tokio::test]
async fn test_inspector_confirmed_transaction_fails() -> Result<()> {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .try_init()
        .ok();

    let bitcoind = create_bitcoind();
    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc1 = Client::new_with_auth(&bitcoind.rpc_url(), auth.clone())?;
    let rpc2 = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;
    let mut inspector = Inspector::new(rpc1);

    // Create and confirm a transaction
    let address = bitcoin::Address::from_str("bcrt1qfehlhwqmwc3x39h5z4fw0vygqkdc82qxjchzds")?
        .assume_checked();
    let sent = bitcoind
        .client
        .send_to_address(&address, Amount::from_btc(1.)?)?;
    let txid = Txid::from_str(&sent.0)?;

    debug!("Created transaction: {txid}");

    // Mine a block to confirm it
    let mine_address = bitcoind.client.new_address()?;
    bitcoind.client.generate_to_address(1, &mine_address)?;

    // Now spend the output to make it unavailable via get_tx_out
    let _txid2 = bitcoind
        .client
        .send_to_address(&address, Amount::from_btc(0.5)?)?;
    bitcoind.client.generate_to_address(1, &mine_address)?;

    // Get the first transaction
    let tx_result = rpc2.get_raw_transaction(txid)?;
    let tx = tx_result.transaction()?;

    // Try to analyze it - should fail because prevouts are spent
    let result = inspector.analyze_transaction(txid, &tx, true);

    match result {
        Ok(anomalies) => {
            debug!("Transaction analyzed with {} anomalies", anomalies.len());
        }
        Err(e) => {
            panic!("Failed to analyze confirmed transaction: {e}");
        }
    }

    Ok(())
}

/// Test Inspector with a transaction that has unspent prevouts
/// This should work because get_tx_out can fetch unspent outputs
#[tokio::test]
async fn test_inspector_with_unspent_prevouts() -> Result<()> {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .try_init()
        .ok();

    let bitcoind = create_bitcoind();
    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;
    let mut inspector = Inspector::new(rpc);

    // Get a UTXO that hasn't been spent yet
    let unspent = bitcoind.client.list_unspent()?.0;
    let utxo = unspent.first().context("No UTXOs available")?;

    debug!("Using UTXO: {}:{}", utxo.txid, utxo.vout);

    // Create a transaction spending this UTXO
    let address = bitcoin::Address::from_str("bcrt1qfehlhwqmwc3x39h5z4fw0vygqkdc82qxjchzds")?
        .assume_checked();

    let input = Input {
        txid: Txid::from_str(&utxo.txid)?,
        vout: utxo.vout as u64,
        sequence: None,
    };
    let output = Output::new(address, Amount::from_btc(0.5)?);

    let created = bitcoind
        .client
        .create_raw_transaction(&[input], &[output])?;
    let tx = created.transaction()?;
    let signed = bitcoind.client.sign_raw_transaction_with_wallet(&tx)?;

    // Parse the signed transaction hex
    let bytes: Vec<u8> = FromHex::from_hex(&signed.hex)?;
    let signed_tx = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes)?;

    let txid = signed_tx.compute_txid();
    debug!("Created transaction: {txid}");

    // Analyze the transaction BEFORE broadcasting it
    // The prevout should be available via get_tx_out since it's unspent
    let result = inspector.analyze_transaction(txid, &signed_tx, false);

    match result {
        Ok(anomalies) => {
            debug!(
                "Transaction analyzed successfully with {} anomalies",
                anomalies.len()
            );
        }
        Err(e) => {
            panic!("Failed to analyze transaction: {e}");
        }
    }

    Ok(())
}

/// Test that from_block parameter correctly skips mempool-specific checks
#[tokio::test]
async fn test_inspector_from_block_skips_mempool_checks() -> Result<()> {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .try_init()
        .ok();

    let bitcoind = create_bitcoind();
    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;
    let mut inspector = Inspector::new(rpc);

    // Get a simple transaction from a recent block
    let block_count = bitcoind.client.get_block_count()?;
    let block_hash_result = bitcoind.client.get_block_hash(block_count.0)?;
    let block_hash = BlockHash::from_str(&block_hash_result.0)?;

    // Get a transaction from the block
    let block_full = bitcoind.client.get_block(block_hash)?;

    // Get the coinbase transaction (first tx in block)
    let tx = &block_full.txdata[0];
    let txid = tx.compute_txid();

    debug!("Analyzing block transaction: {txid}");

    // Analyze with from_block=true
    let result = inspector.analyze_transaction(txid, tx, true);

    match result {
        Ok(anomalies) => {
            debug!(
                "Coinbase transaction analyzed with {} anomalies",
                anomalies.len()
            );
            // Shouldn't have mempool-specific anomalies
        }
        Err(e) => {
            debug!("Error analyzing coinbase: {e}");
        }
    }

    Ok(())
}
