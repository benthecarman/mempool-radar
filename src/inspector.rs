use anyhow::Context;
use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Opcode, Script, Transaction, TxOut, Txid};
use corepc_client::client_sync::v29::Client;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tracing::info;

// Size thresholds (in bytes)
const MIN_TRANSACTION_SIZE: usize = 65;
const MAX_SCRIPTSIG_SIZE: usize = 1650;
const MAX_OP_RETURN_SIZE: usize = 100_000;

// SigOps limits
const MAX_LEGACY_SIGOPS: usize = 15;

// P2WSH limits
const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;

// Tapscript limits
const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;

// Dust threshold
const DUST_THRESHOLD: Amount = Amount::from_sat(546);

// P2A script bytes
const P2A_SCRIPT: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

// Witness version limits
const MAX_STANDARD_WITNESS_VERSION: u8 = 1;

// Chain and package limits
const MAX_ANCESTORS: usize = 64;
const MAX_DESCENDANTS: usize = 64;
const MAX_PACKAGE_SIZE: i64 = 101_000;
const LARGE_TX_SIZE: usize = 100_000;

#[derive(Debug, Clone)]
pub enum Anomaly {
    LargeTransaction { size_bytes: usize },
    TooSmallTransaction { size_bytes: usize },
    LargeScriptSig { size_bytes: usize },
    NonPushOnlyScriptSig { idx: usize },
    LegacySigOpsLimitExceeded { count: usize },
    MultipleOpReturns { count: usize },
    UnusualScript { script_type: String },
    UnusualVersion { version: Version },
    ExcessiveAncestors { ancestor_count: usize },
    ExcessiveDescendants { descendant_count: usize },
    PackageSizeViolation { package_size: usize },
    DustOutputs { amt: Amount },
    HasAnnex { idx: u32 },
    HasOpSuccess { idx: u32, opcode: Opcode },
    UnknownLeafVersion { idx: u32, version: u8 },
    UnknownInputScriptType { idx: u32, script_type: String },
    ExcessiveP2wshStackItems { idx: u32, count: usize },
    OversizedP2wshStackItem { idx: u32, size: usize },
    OversizedTapscriptStackItem { idx: u32, size: usize },
    OversizedP2wshScript { size: usize },
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_message())
    }
}

impl Anomaly {
    pub fn to_message(&self) -> String {
        match self {
            Anomaly::LargeTransaction { size_bytes } => {
                format!("🐋 Large Transaction\nSize: {} vKB", size_bytes / 1_000)
            }
            Anomaly::TooSmallTransaction { size_bytes } => {
                format!("🐁 Too Small Transaction\nSize: {size_bytes} vb")
            }
            Anomaly::LargeScriptSig { size_bytes } => {
                format!("📝 Large ScriptSig\nSize: {size_bytes} bytes")
            }
            Anomaly::NonPushOnlyScriptSig { idx } => {
                format!("🚫 Non-Push-Only ScriptSig\nInput Index: {idx}")
            }
            Anomaly::LegacySigOpsLimitExceeded { count } => {
                format!("⚠️ Legacy SigOps Limit Exceeded\nCount: {count}")
            }
            Anomaly::UnusualScript { script_type } => {
                format!("🔍 Unusual Script\nType: {script_type}",)
            }
            Anomaly::UnusualVersion { version } => {
                format!("⚠️ Unusual Version\nVersion: {version}")
            }
            Anomaly::ExcessiveAncestors { ancestor_count } => {
                format!("🔗 Excessive Ancestors\nAncestors: {ancestor_count}")
            }
            Anomaly::ExcessiveDescendants { descendant_count } => {
                format!("🌳 Excessive Descendants\nDescendants: {descendant_count}")
            }
            Anomaly::PackageSizeViolation { package_size } => {
                format!(
                    "📦 Package Size Violation\nPackage Size: {} KB",
                    package_size / 1_000
                )
            }
            Anomaly::DustOutputs { amt } => {
                format!("💰 Dust Output\nAmount: {amt}")
            }
            Anomaly::HasAnnex { idx } => {
                format!("📎 Transaction Has Annex\nInput Index: {idx}")
            }
            Anomaly::HasOpSuccess { idx, opcode } => {
                format!("🛑 Transaction Has OP_SUCCESS\nInput Index: {idx}, Opcode: {opcode}")
            }
            Anomaly::UnknownLeafVersion { idx, version } => {
                format!("❓ Unknown Taproot Leaf Version\nInput Index: {idx}, Version: {version}")
            }
            Anomaly::UnknownInputScriptType { idx, script_type } => {
                format!(
                    "❓ Unknown Input Script Type\nInput Index: {idx}, Script Type: {script_type}"
                )
            }
            Anomaly::MultipleOpReturns { count } => {
                format!("📦 Multiple OP_RETURN Outputs\nCount: {count}")
            }
            Anomaly::ExcessiveP2wshStackItems { idx, count } => {
                format!("📚 Excessive P2WSH Stack Items\nInput Index: {idx}, Count: {count}")
            }
            Anomaly::OversizedP2wshStackItem { idx, size } => {
                format!("📏 Oversized P2WSH Stack Item\nInput Index: {idx}, Size: {size} bytes")
            }
            Anomaly::OversizedTapscriptStackItem { idx, size } => {
                format!("📏 Oversized Tapscript Stack Item\nInput Index: {idx}, Size: {size} bytes")
            }
            Anomaly::OversizedP2wshScript { size } => {
                format!("📜 Oversized P2WSH Script\nSize: {size} bytes")
            }
        }
    }
}

pub struct Inspector {
    rpc: Arc<Client>,
}

impl Inspector {
    pub fn new(rpc: Client) -> Self {
        Self { rpc: Arc::new(rpc) }
    }

    pub async fn analyze_transaction(
        &self,
        txid: Txid,
        tx: &Transaction,
        from_block: bool,
    ) -> anyhow::Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();

        // Collect input data first to avoid lifetime issues
        let input_data: Vec<(usize, Txid, u32)> = tx
            .input
            .iter()
            .enumerate()
            .map(|(idx, input)| (idx, input.previous_output.txid, input.previous_output.vout))
            .collect();

        // Fetch prevouts in parallel with a concurrency limit of 4
        let prevouts = stream::iter(input_data)
            .map(|(idx, prev_txid, vout)| {
                let rpc = Arc::clone(&self.rpc);

                async move {
                    tokio::task::spawn_blocking(move || {
                        let raw = rpc
                            .get_raw_transaction(prev_txid)
                            .context("Failed to fetch previous transaction")?;

                        let prev_tx = raw
                            .transaction()
                            .context("Failed to parse previous transaction")?;

                        let vout_idx = vout as usize;
                        if vout_idx >= prev_tx.output.len() {
                            anyhow::bail!("Invalid vout index in input");
                        }

                        Ok::<_, anyhow::Error>((idx, prev_tx.output[vout_idx].clone()))
                    })
                    .await
                    .context("Task join error")?
                }
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;

        // Check for errors and reconstruct the prevouts vector in correct order
        let mut prevouts_vec: Vec<(usize, TxOut)> = Vec::with_capacity(tx.input.len());
        for result in prevouts {
            prevouts_vec.push(result?);
        }
        prevouts_vec.sort_by_key(|(idx, _)| *idx);
        let prevouts: Vec<TxOut> = prevouts_vec.into_iter().map(|(_, txout)| txout).collect();

        if let Some(anomaly) = self.check_large_transaction(txid, tx) {
            anomalies.push(anomaly);
        }

        if let Some(anomaly) = self.check_small_transaction(txid, tx) {
            anomalies.push(anomaly);
        }

        if let Some(anomaly) = self.check_unusual_version(tx) {
            anomalies.push(anomaly);
        }

        // Skip mempool-specific checks for transactions from blocks
        if !from_block {
            if let Some(anomaly) = self.check_ancestor_chains(txid)? {
                anomalies.push(anomaly);
            }

            if let Some(anomaly) = self.check_descendant_chains(txid)? {
                anomalies.push(anomaly);
            }

            if let Some(anomaly) = self.check_package_violations(txid)? {
                anomalies.push(anomaly);
            }
        }

        let script_sigs = self.check_script_sigs(tx);
        anomalies.extend(script_sigs);

        let scripts = self.check_unusual_output_scripts(tx);
        anomalies.extend(scripts);

        let dusts = Self::check_dust_outputs(&prevouts, tx);
        anomalies.extend(dusts);

        let inputs = self.check_witnesses(&prevouts, tx);
        anomalies.extend(inputs);

        Ok(anomalies)
    }

    fn check_large_transaction(&self, txid: Txid, tx: &Transaction) -> Option<Anomaly> {
        let size = tx.vsize();

        if size > LARGE_TX_SIZE {
            info!("Large transaction detected: {txid} (size: {size} bytes)");
            return Some(Anomaly::LargeTransaction { size_bytes: size });
        }
        None
    }

    fn check_small_transaction(&self, txid: Txid, tx: &Transaction) -> Option<Anomaly> {
        let size = tx.base_size();

        if size < MIN_TRANSACTION_SIZE {
            info!("Too small transaction detected: {txid} (size: {size} bytes)",);
            return Some(Anomaly::TooSmallTransaction { size_bytes: size });
        }
        None
    }

    fn check_unusual_output_scripts(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.output
            .iter()
            .filter_map(|output| {
                let script = &output.script_pubkey;

                if script.is_op_return() && script.len() > MAX_OP_RETURN_SIZE {
                    Some(Anomaly::UnusualScript {
                        script_type: format!("OP_RETURN ({} bytes)", script.len()),
                    })
                } else if !script.is_p2pkh()
                    && !script.is_p2sh()
                    && !script.is_p2wpkh()
                    && !script.is_p2pk()
                    && !script.is_p2wsh()
                    && !script.is_p2tr()
                    && !script.is_op_return()
                    && !script.is_multisig()
                    && !is_p2a(script)
                {
                    match script.witness_version() {
                        None => Some(Anomaly::UnusualScript {
                            script_type: "Non-standard".to_string(),
                        }),
                        Some(_) => None, // unknown witness version are standard
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    fn check_unusual_version(&self, tx: &Transaction) -> Option<Anomaly> {
        if !tx.version.is_standard() && tx.version != Version::non_standard(3) {
            Some(Anomaly::UnusualVersion {
                version: tx.version,
            })
        } else {
            None
        }
    }

    fn check_dust_outputs(prevouts: &[TxOut], tx: &Transaction) -> Vec<Anomaly> {
        let input_amt: Amount = prevouts.iter().map(|out| out.value).sum();
        let output_amt: Amount = tx.output.iter().map(|out| out.value).sum();

        let is_zero_fee = input_amt == output_amt;

        // Dust by Bitcoin Core's formula. OP_RETURN is not dust (unspendable,
        // threshold 0). Pay-to-Anchor still is: the generic witness formula
        // assumes a signature and prices `OP_1 <0x4e73>` at 240 sats.
        let dust_outputs: Vec<&TxOut> = tx
            .output
            .iter()
            .filter(|output| is_dust_output(output))
            .collect();

        // A zero-fee transaction with exactly one dust output is ephemeral
        // dust, which is standard. Anchors count, so an anchor plus another
        // dust output is two dust outputs and is not exempt.
        if is_zero_fee && dust_outputs.len() == 1 {
            return vec![];
        }

        // P2A is the standard ephemeral anchor (bc1pfeessrawgf) and is created
        // at 0 value on purpose for TRUC/v3 package relay, including LN
        // commitment transactions. Alerting on it is a false positive. Other
        // dust in the same transaction is still reported.
        dust_outputs
            .into_iter()
            .filter(|output| !is_p2a(&output.script_pubkey))
            .map(|output| Anomaly::DustOutputs { amt: output.value })
            .collect()
    }

    fn check_ancestor_chains(&self, txid: Txid) -> anyhow::Result<Option<Anomaly>> {
        match self.rpc.get_mempool_ancestors(txid) {
            Ok(ancestors) => {
                let ancestor_count = ancestors.0.len();
                if ancestor_count > MAX_ANCESTORS {
                    info!("Excessive ancestors detected: {txid} (ancestors: {ancestor_count})");
                    Ok(Some(Anomaly::ExcessiveAncestors { ancestor_count }))
                } else {
                    Ok(None)
                }
            }
            Err(_) => {
                // Transaction might not be in mempool anymore, or other error
                // This is not necessarily an anomaly, just return None
                Ok(None)
            }
        }
    }

    fn check_descendant_chains(&self, txid: Txid) -> anyhow::Result<Option<Anomaly>> {
        match self.rpc.get_mempool_descendants(txid) {
            Ok(descendants) => {
                let descendant_count = descendants.0.len();
                if descendant_count > MAX_DESCENDANTS {
                    info!(
                        "Excessive descendants detected: {txid} (descendants: {descendant_count})"
                    );
                    Ok(Some(Anomaly::ExcessiveDescendants { descendant_count }))
                } else {
                    Ok(None)
                }
            }
            Err(_) => {
                // Transaction might not be in mempool anymore, or other error
                // This is not necessarily an anomaly, just return None
                Ok(None)
            }
        }
    }

    fn check_package_violations(&self, txid: Txid) -> anyhow::Result<Option<Anomaly>> {
        // Get the entry for this transaction to get its size
        match self.rpc.get_mempool_entry(txid) {
            Ok(entry) => {
                // Calculate total package size: ancestor_size + descendant_size
                // minus the size of the transaction itself (vsize) because it's counted in both
                let total_package_size =
                    entry.0.ancestor_size + entry.0.descendant_size - entry.0.vsize;

                if total_package_size > MAX_PACKAGE_SIZE {
                    info!(
                        "Package size violation detected: {txid} (package size: {total_package_size} bytes)"
                    );
                    Ok(Some(Anomaly::PackageSizeViolation {
                        package_size: total_package_size as usize,
                    }))
                } else {
                    Ok(None)
                }
            }
            Err(_) => {
                // Transaction might not be in mempool anymore, or other error
                // This is not necessarily an anomaly, just return None
                Ok(None)
            }
        }
    }

    fn check_script_sigs(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.input
            .iter()
            .enumerate()
            .flat_map(|(idx, input)| {
                let script_sig_size = input.script_sig.len();
                let mut init = if script_sig_size > MAX_SCRIPTSIG_SIZE {
                    vec![Anomaly::LargeScriptSig {
                        size_bytes: script_sig_size,
                    }]
                } else {
                    vec![]
                };

                if !input.script_sig.is_push_only() {
                    init.push(Anomaly::NonPushOnlyScriptSig { idx });
                }

                let legacy_sig_ops = input.script_sig.count_sigops_legacy();

                if legacy_sig_ops > MAX_LEGACY_SIGOPS {
                    init.push(Anomaly::LegacySigOpsLimitExceeded {
                        count: legacy_sig_ops,
                    });
                }

                init
            })
            .collect()
    }

    fn check_witnesses(&self, prevouts: &[TxOut], tx: &Transaction) -> Vec<Anomaly> {
        tx.input
            .iter()
            .zip(prevouts)
            .enumerate()
            .flat_map(|(idx, (input, prevout))| {
                let leaf_script = input.witness.taproot_leaf_script();
                let annex = input.witness.taproot_annex();

                let prevout_script = &prevout.script_pubkey;

                let is_p2tr = prevout_script.is_p2tr();
                let is_p2wsh = prevout_script.is_p2wsh();

                let witness_version = prevout_script.witness_version();
                if witness_version.is_some_and(|v| v.to_num() > MAX_STANDARD_WITNESS_VERSION) {
                    return vec![Anomaly::UnknownInputScriptType {
                        idx: idx as u32,
                        script_type: format!(
                            "Spent Unknown SegWit v{}",
                            witness_version.unwrap().to_num()
                        ),
                    }];
                }

                let mut anomalies = Vec::new();

                // P2WSH checks
                if is_p2wsh && !input.witness.is_empty() {
                    let witness_items = &input.witness;

                    // Check number of stack items, make sure to exclude the witnessScript which is the last item
                    if witness_items.len() - 1 > MAX_STANDARD_P2WSH_STACK_ITEMS {
                        anomalies.push(Anomaly::ExcessiveP2wshStackItems {
                            idx: idx as u32,
                            count: witness_items.len(),
                        });
                    }

                    // Check size of each stack item (excluding the witnessScript which is the last item)
                    if witness_items.len() > 1 {
                        for item in witness_items.iter().take(witness_items.len() - 1) {
                            if item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE {
                                anomalies.push(Anomaly::OversizedP2wshStackItem {
                                    idx: idx as u32,
                                    size: item.len(),
                                });
                                break; // Only report once per input
                            }
                        }
                    }

                    // Check witnessScript size (last item in P2WSH witness)
                    if let Some(witness_script) = witness_items.last()
                        && witness_script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE
                    {
                        anomalies.push(Anomaly::OversizedP2wshScript {
                            size: witness_script.len(),
                        });
                    }
                }

                // Taproot checks
                if is_p2tr && !input.witness.is_empty() {
                    if let Some(leaf_script) = leaf_script {
                        if leaf_script.version != LeafVersion::TapScript {
                            anomalies.push(Anomaly::UnknownLeafVersion {
                                idx: idx as u32,
                                version: leaf_script.version.to_consensus(),
                            })
                        }

                        for i in leaf_script.script.instructions() {
                            if i.is_err() {
                                break;
                            }
                            if let Ok(bitcoin::blockdata::script::Instruction::Op(opcode)) = i
                                && opcode.classify(ClassifyContext::TapScript) == Class::SuccessOp
                            {
                                anomalies.push(Anomaly::HasOpSuccess {
                                    idx: idx as u32,
                                    opcode,
                                });
                            }
                        }

                        // Check Tapscript stack item sizes
                        // Witness format: [stack items...] [script] [control block] [annex (optional)]
                        // We need to exclude script, control block, and annex from size checks
                        let witness_items = &input.witness;
                        if witness_items.len() >= 2 {
                            let num_items_to_check = if annex.is_some() {
                                // Exclude script, control block, and annex (last 3 items)
                                witness_items.len().saturating_sub(3)
                            } else {
                                // Exclude script and control block (last 2 items)
                                witness_items.len().saturating_sub(2)
                            };

                            for item in witness_items.iter().take(num_items_to_check) {
                                if item.len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE {
                                    anomalies.push(Anomaly::OversizedTapscriptStackItem {
                                        idx: idx as u32,
                                        size: item.len(),
                                    });
                                    break; // Only report once per input
                                }
                            }
                        }
                    }

                    if annex.is_some() {
                        anomalies.push(Anomaly::HasAnnex { idx: idx as u32 });
                    }
                }

                anomalies
            })
            .collect()
    }
}

/// Bitcoin Core treats an output as dust when its value is below the fee to
/// spend it at the dust relay rate. OP_RETURN is unspendable, so its threshold
/// is 0 and a 0-value `OP_RETURN` is standard rather than dust.
fn is_dust_output(output: &TxOut) -> bool {
    let amt = output.value;
    if amt >= DUST_THRESHOLD || output.script_pubkey.is_op_return() {
        return false;
    }

    output.script_pubkey.minimal_non_dust() > amt
}

fn is_p2a(script: &Script) -> bool {
    script.as_bytes() == P2A_SCRIPT
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::FromHex;
    use bitcoin::{
        OutPoint, PubkeyHash, ScriptBuf, Sequence, TxIn, WPubkeyHash, Witness, absolute,
    };
    use std::str::FromStr;

    #[test]
    fn test_is_p2a() {
        let address = bitcoin::Address::from_str("bc1pfeessrawgf")
            .unwrap()
            .assume_checked();

        assert!(is_p2a(&address.script_pubkey()));
        assert!(is_p2a(&ScriptBuf::new_p2a()));
        assert_eq!(ScriptBuf::new_p2a().as_bytes(), &P2A_SCRIPT);
    }

    fn p2wpkh() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20]))
    }

    fn p2pkh() -> ScriptBuf {
        ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x22; 20]))
    }

    fn tx_with_outputs(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        }
    }

    fn prevout(sats: u64) -> Vec<TxOut> {
        vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: p2wpkh(),
        }]
    }

    fn dust_amounts(anomalies: &[Anomaly]) -> Vec<Amount> {
        anomalies
            .iter()
            .map(|anomaly| match anomaly {
                Anomaly::DustOutputs { amt } => *amt,
                other => panic!("unexpected anomaly: {other}"),
            })
            .collect()
    }

    /// f2f03d3e52f336c386c3a39cfce8ef88c75e66e0df84c0c71182e0986b1e9546
    ///
    /// Input of 1000 sats, a 750-sat P2WPKH output, and a 0-value P2A anchor
    /// (`51024e73`). Fee is 250 sats, so the zero-fee ephemeral exemption does
    /// not apply. The anchor is what the dust detector used to report.
    #[test]
    fn p2a_anchor_with_fee_is_not_dust() {
        let raw = Vec::<u8>::from_hex(
            "02000000000101dfd4d1fa805b2b1b3b66fb3cdfd88d552a41eb9d456a2ae1c52d0b91658bbff10000000000fdffffff02ee02000000000000160014c855c9d70c76ee9d58d240756103011089f29ff400000000000000000451024e730247304402200e1db96bf7e6ea6f67e779e495f79ee072aba5452646f6240dc0f80e197f2bf7022066953631d7e72e38ef0282621173be2016b11bbbf6de31cc24eeac118f7bafb5012102c4ea309366eecb3bf468670c9281ec8c75ecde8094318e665dec49b5cb6d025100000000",
        )
        .unwrap();
        let tx: Transaction = deserialize(&raw).unwrap();
        assert_eq!(
            tx.compute_txid().to_string(),
            "f2f03d3e52f336c386c3a39cfce8ef88c75e66e0df84c0c71182e0986b1e9546"
        );

        let p2wpkh_out = &tx.output[0];
        assert_eq!(p2wpkh_out.value, Amount::from_sat(750));
        assert!(p2wpkh_out.script_pubkey.is_p2wpkh());
        assert!(p2wpkh_out.value >= DUST_THRESHOLD);
        assert!(p2wpkh_out.script_pubkey.minimal_non_dust() <= p2wpkh_out.value);

        let anchor = &tx.output[1];
        assert_eq!(anchor.value, Amount::ZERO);
        assert_eq!(anchor.script_pubkey.as_bytes(), &P2A_SCRIPT);
        assert!(is_p2a(&anchor.script_pubkey));
        // The generic witness dust formula still prices this spend as if it
        // carried a signature, which is why a plain threshold check flags it.
        assert!(anchor.script_pubkey.minimal_non_dust() > anchor.value);

        // Real prevout value was 1000 sats, so the transaction paid a 250-sat fee.
        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert!(
            anomalies.is_empty(),
            "0-value P2A anchor should not be reported as dust: {anomalies:?}"
        );
    }

    #[test]
    fn sub_dust_p2wpkh_is_still_flagged() {
        // One sat under the P2WPKH minimal non-dust amount, and under the
        // legacy 546-sat floor. Non-zero fee, so ephemeral dust does not apply.
        let script = p2wpkh();
        let amt = script.minimal_non_dust() - Amount::ONE_SAT;
        assert!(amt < DUST_THRESHOLD);

        let tx = tx_with_outputs(vec![TxOut {
            value: amt,
            script_pubkey: script,
        }]);
        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert_eq!(dust_amounts(&anomalies), vec![amt]);
    }

    #[test]
    fn p2wpkh_between_witness_and_legacy_thresholds_is_not_dust() {
        // 330 sats is below the 546-sat legacy floor but above the P2WPKH
        // threshold (294). The 750-sat output in the reported transaction is
        // in this same class and is not what produced the alert.
        let script = p2wpkh();
        let amt = Amount::from_sat(330);
        assert!(amt < DUST_THRESHOLD);
        assert!(script.minimal_non_dust() <= amt);

        let tx = tx_with_outputs(vec![TxOut {
            value: amt,
            script_pubkey: script,
        }]);
        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn anchor_does_not_hide_genuine_dust() {
        let dust = Amount::from_sat(200);
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(750),
                script_pubkey: p2wpkh(),
            },
            TxOut {
                value: dust,
                script_pubkey: p2wpkh(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_p2a(),
            },
        ]);

        let anomalies = Inspector::check_dust_outputs(&prevout(2000), &tx);
        assert_eq!(dust_amounts(&anomalies), vec![dust]);
    }

    #[test]
    fn zero_fee_anchor_plus_genuine_dust_is_still_flagged() {
        // Core allows one dust output only when the fee is zero. A 0-value
        // anchor plus another dust output is two dust outputs, so the
        // non-anchor output stays an anomaly.
        let dust = Amount::from_sat(200);
        let tx = tx_with_outputs(vec![
            TxOut {
                value: dust,
                script_pubkey: p2wpkh(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_p2a(),
            },
        ]);

        let anomalies = Inspector::check_dust_outputs(&prevout(dust.to_sat()), &tx);
        assert_eq!(dust_amounts(&anomalies), vec![dust]);
    }

    #[test]
    fn zero_fee_single_dust_output_remains_exempt() {
        let dust = Amount::from_sat(200);
        let tx = tx_with_outputs(vec![TxOut {
            value: dust,
            script_pubkey: p2wpkh(),
        }]);

        let anomalies = Inspector::check_dust_outputs(&prevout(dust.to_sat()), &tx);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn multiple_genuine_dust_outputs_are_all_flagged() {
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: p2pkh(),
            },
            TxOut {
                value: Amount::from_sat(200),
                script_pubkey: p2wpkh(),
            },
        ]);

        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert_eq!(
            dust_amounts(&anomalies),
            vec![Amount::from_sat(100), Amount::from_sat(200)]
        );
    }

    #[test]
    fn zero_value_op_return_is_not_dust() {
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(750),
                script_pubkey: p2wpkh(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from(vec![0x6a, 0x01, 0x01]),
            },
        ]);
        assert!(tx.output[1].script_pubkey.is_op_return());

        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn zero_value_non_anchor_witness_program_is_still_dust() {
        // Same shape as P2A (OP_1 <2 bytes>) but not the anchor program 0x4e73.
        let script = ScriptBuf::from(vec![0x51, 0x02, 0x00, 0x01]);
        assert!(!is_p2a(&script));

        let tx = tx_with_outputs(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }]);
        let anomalies = Inspector::check_dust_outputs(&prevout(1000), &tx);
        assert_eq!(dust_amounts(&anomalies), vec![Amount::ZERO]);
    }
}
