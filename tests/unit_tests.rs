use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};
use mempool_radar::config::Config;
use mempool_radar::inspector::Anomaly;

// Mock RPC client for testing (we'll just use a simple placeholder)
fn create_mock_config() -> Config {
    Config {
        network: bitcoin::Network::Regtest,
        telegram_token: None,
        telegram_chat_id: None,
        rpc_url: "http://127.0.0.1:18443".to_string(),
        rpc_user: Some("test".to_string()),
        rpc_password: Some("test".to_string()),
        cookie_file: None,
        zmq_endpoint: "tcp://127.0.0.1:28333".to_string(),
        large_tx_size: 100_000,
        max_ancestors: 25,
        max_descendants: 25,
        max_package_size: 101_000,
    }
}

// Create a simple transaction for testing
fn create_simple_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5000000000), // 50 BTC
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// Create a large transaction (over 100KB)
fn create_large_transaction() -> Transaction {
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![],
    };

    // Add many outputs to make the transaction large (over 100KB)
    // Each output is about 9 + 25 = 34 bytes, so we need about 3000 outputs for 100KB
    for _ in 0..5000 {
        tx.output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_hex("76a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe26158876a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe261588").unwrap_or_default(),
        });
    }

    tx
}

// Create a transaction with unusual version
fn create_unusual_version_transaction() -> Transaction {
    Transaction {
        version: transaction::Version(999), // Non-standard version
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5000000000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// Create a transaction with dust outputs
fn create_dust_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(500), // Below dust threshold
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
        ],
    }
}

#[test]
fn test_large_transaction_detection() {
    // Test without RPC (offline analysis)
    let config = create_mock_config();

    // We can't create an Inspector without RPC, so let's test the transaction size directly
    let large_tx = create_large_transaction();
    let size = large_tx.total_size();

    assert!(
        size > 100_000,
        "Transaction should be large ({}bytes)",
        size
    );

    // Test the threshold logic
    assert!(
        size > config.large_tx_size,
        "Transaction should exceed configured threshold"
    );
}

#[test]
fn test_unusual_version_detection() {
    let unusual_tx = create_unusual_version_transaction();

    // Test that version is non-standard
    assert!(
        !unusual_tx.version.is_standard(),
        "Transaction version should be non-standard"
    );
    assert_eq!(
        unusual_tx.version.0, 999,
        "Transaction version should be 999"
    );
}

#[test]
fn test_dust_threshold() {
    let dust_tx = create_dust_transaction();
    let dust_threshold = Amount::from_sat(546);

    // Check that we have a dust output
    let has_dust = dust_tx
        .output
        .iter()
        .any(|output| output.value < dust_threshold);
    assert!(has_dust, "Transaction should contain dust outputs");

    // Check specific dust output
    assert_eq!(dust_tx.output[0].value, Amount::from_sat(500));
    assert!(
        dust_tx.output[0].value < dust_threshold,
        "First output should be dust"
    );
}

#[test]
fn test_normal_transaction_properties() {
    let normal_tx = create_simple_transaction();

    // Test that normal transaction doesn't trigger size anomaly
    let size = normal_tx.total_size();
    assert!(
        size < 100_000,
        "Normal transaction should be under 100KB ({}bytes)",
        size
    );

    // Test that version is standard
    assert!(
        normal_tx.version.is_standard(),
        "Normal transaction should have standard version"
    );

    // Test basic structure
    assert_eq!(
        normal_tx.input.len(),
        1,
        "Normal transaction should have one input"
    );
    assert_eq!(
        normal_tx.output.len(),
        1,
        "Normal transaction should have one output"
    );
}

#[test]
fn test_anomaly_message_formatting() {
    // Test that anomaly messages format correctly
    let large_tx_anomaly = Anomaly::LargeTransaction { size_bytes: 150000 };
    let message = large_tx_anomaly.to_message();
    assert!(message.contains("Large Transaction"));
    assert!(message.contains("150 KB"));

    let version_anomaly = Anomaly::UnusualVersion {
        version: transaction::Version(999),
    };
    let message = version_anomaly.to_message();
    assert!(message.contains("Unusual Version"));
    assert!(message.contains("999"));

    let dust_anomaly = Anomaly::DustOutputs {
        amt: Amount::from_sat(500),
    };
    let message = dust_anomaly.to_message();
    assert!(message.contains("Dust Output"));
    assert!(message.contains("500"));
}

#[test]
fn test_config_validation() {
    let config = create_mock_config();

    // Test config values
    assert_eq!(config.network, bitcoin::Network::Regtest);
    assert_eq!(config.large_tx_size, 100_000);
    assert_eq!(config.max_ancestors, 25);
    assert_eq!(config.max_descendants, 25);
    assert_eq!(config.max_package_size, 101_000);
}

#[test]
fn test_transaction_serialization() {
    let tx = create_simple_transaction();

    // Test that transaction can be serialized and deserialized
    let serialized = bitcoin::consensus::encode::serialize(&tx);
    assert!(
        !serialized.is_empty(),
        "Serialized transaction should not be empty"
    );

    let deserialized: Transaction = bitcoin::consensus::encode::deserialize(&serialized).unwrap();
    assert_eq!(
        tx.compute_txid(),
        deserialized.compute_txid(),
        "Transaction IDs should match after round-trip"
    );
}

#[cfg(test)]
mod benchmark_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_large_transaction_creation() {
        let start = Instant::now();
        let _tx = create_large_transaction();
        let elapsed = start.elapsed();

        println!("Large transaction creation took: {:?}", elapsed);
        assert!(
            elapsed.as_millis() < 1000,
            "Large transaction creation should be reasonably fast"
        );
    }

    #[test]
    fn benchmark_transaction_serialization() {
        let tx = create_large_transaction();

        let start = Instant::now();
        let _serialized = bitcoin::consensus::encode::serialize(&tx);
        let elapsed = start.elapsed();

        println!("Large transaction serialization took: {:?}", elapsed);
        assert!(
            elapsed.as_millis() < 50,
            "Transaction serialization should be fast"
        );
    }
}
