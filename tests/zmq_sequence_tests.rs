use anyhow::Result;
use bitcoin::{Amount, Network};
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client;
use corepc_node::{Conf, Node as Bitcoind, get_available_port};
use mempool_radar::ZmqListener;
use std::str::FromStr;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{Instrument, Level, debug};

const RPC_USER: &str = "user";
const RPC_PASS: &str = "pass";

#[tokio::test]
async fn test_zmq_listener() -> Result<()> {
    // Initialize tracing subscriber that works with tokio::spawn
    let _guard = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(Level::DEBUG)
        .init();

    let zmq = get_available_port()?;
    let bitcoind = create_bitcoind(zmq);
    let config = create_config(zmq, bitcoind.rpc_url());

    let auth = Auth::UserPass(RPC_USER.to_string(), RPC_PASS.to_string());
    let rpc = Client::new_with_auth(&bitcoind.rpc_url(), auth)?;

    let (tx_sender, mut tx_receiver) = mpsc::channel(1000);
    let zmq_listener = ZmqListener::new(config.zmq_endpoint.clone(), rpc);

    // Start the ZMQ listener in the current task context to maintain tracing
    let tx_sender_clone = tx_sender.clone();
    tokio::spawn(
        async move {
            if let Err(e) = zmq_listener.start(tx_sender_clone).await {
                tracing::error!("ZMQ listener error: {e}");
            }
        }
        .instrument(tracing::info_span!("zmq_listener")),
    );

    // Give some time for the ZMQ listener to start
    tokio::time::sleep(Duration::from_secs(1)).await;

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
    let received_tx = tokio::time::timeout(Duration::from_secs(10), tx_receiver.recv()).await?;

    assert!(!tx_receiver.is_closed());
    assert_eq!(received_tx.unwrap().output.len(), 2);

    // Generate a block to confirm the transaction and trigger another sequence message
    generate_blocks(&bitcoind, 1);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // We should not receive any more transactions since it is in a block.
    assert_eq!(tx_receiver.len(), 0);

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

    // mine 101 blocks to get some spendable funds, split it up into multiple calls
    // to avoid potentially hitting RPC timeouts on slower CI systems
    let address = bitcoind.client.new_address().unwrap();
    for _ in 0..101 {
        let _block_hashes = bitcoind.client.generate_to_address(1, &address).unwrap();
    }

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
        .expect(&format!("failed to generate {num} blocks"));
}

fn create_config(zmq: u16, rpc_url: String) -> mempool_radar::Config {
    mempool_radar::Config {
        network: Network::Regtest,
        telegram_token: None,
        telegram_chat_id: None,
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
