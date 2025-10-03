use anyhow::Context;
use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Opcode, ScriptBuf, Transaction, TxOut, Txid};
use corepc_client::client_sync::v29::Client;
use tracing::info;

// Size thresholds (in bytes)
const MIN_TRANSACTION_SIZE: usize = 65;
const MAX_SCRIPTSIG_SIZE: usize = 1650;
const MAX_OP_RETURN_SIZE: usize = 83;

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

// OP_RETURN limits
const MAX_OP_RETURNS: usize = 1;

// P2A script bytes
const P2A_SCRIPT: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

// Witness version limits
const MAX_STANDARD_WITNESS_VERSION: u8 = 1;

// Chain and package limits
const MAX_ANCESTORS: usize = 25;
const MAX_DESCENDANTS: usize = 25;
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
    rpc: Client,
}

impl Inspector {
    pub fn new(rpc: Client) -> Self {
        Self { rpc }
    }

    pub fn analyze_transaction(
        &mut self,
        txid: Txid,
        tx: &Transaction,
        from_block: bool,
    ) -> anyhow::Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();

        let prevouts = tx
            .input
            .iter()
            .map(|input| {
                let raw = self
                    .rpc
                    .get_raw_transaction(input.previous_output.txid)
                    .context("Failed to fetch previous transaction")?;

                let prev_tx = raw
                    .transaction()
                    .context("Failed to parse previous transaction")?;
                let vout = input.previous_output.vout as usize;
                if vout >= prev_tx.output.len() {
                    anyhow::bail!("Invalid vout index in input");
                }
                Ok(prev_tx.output[vout].clone())
            })
            .collect::<Result<Vec<_>, _>>()?;

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

        let dusts = self.check_dust_outputs(&prevouts, tx);
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
        let mut res: Vec<Anomaly> = tx
            .output
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
            .collect();

        let op_return_count = tx
            .output
            .iter()
            .filter(|output| output.script_pubkey.is_op_return())
            .count();
        if op_return_count > MAX_OP_RETURNS {
            res.push(Anomaly::MultipleOpReturns {
                count: op_return_count,
            });
        }
        res
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

    fn check_dust_outputs(&self, prevouts: &[TxOut], tx: &Transaction) -> Vec<Anomaly> {
        let input_amt: Amount = prevouts.iter().map(|out| out.value).sum();
        let output_amt: Amount = tx.output.iter().map(|out| out.value).sum();

        let is_zero_fee = input_amt == output_amt;

        let res = tx
            .output
            .iter()
            .filter_map(|output| {
                let amt = output.value;

                // shortcircuit for non-dust
                if amt >= DUST_THRESHOLD || output.script_pubkey.is_op_return() {
                    return None;
                }

                if output.script_pubkey.minimal_non_dust() > amt {
                    Some(Anomaly::DustOutputs { amt })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // If the transaction has zero fee and only one dust output, ignore it
        // this is an Ephemeral dust transaction which is now standard
        if is_zero_fee && res.len() == 1 {
            vec![]
        } else {
            res
        }
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

fn is_p2a(script: &ScriptBuf) -> bool {
    script.as_bytes() == P2A_SCRIPT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_p2a() {
        let address = bitcoin::Address::from_str("bc1pfeessrawgf")
            .unwrap()
            .assume_checked();

        assert!(is_p2a(&address.script_pubkey()));
    }
}
