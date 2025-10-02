use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Opcode, ScriptBuf, Transaction, Txid};
use corepc_client::client_sync::v29::Client;
use tracing::info;

use crate::config::Config;

#[derive(Debug, Clone)]
pub enum Anomaly {
    LargeTransaction { size_bytes: usize },
    UnusualScript { script_type: String },
    UnusualVersion { version: Version },
    ExcessiveAncestors { ancestor_count: usize },
    ExcessiveDescendants { descendant_count: usize },
    PackageSizeViolation { package_size: usize },
    ChainDepthIssue { depth: usize },
    DustOutputs { amt: Amount },
    HasAnnex { idx: u32 },
    HasOpSuccess { idx: u32, opcode: Opcode },
    UnknownLeafVersion { idx: u32, version: u8 },
    UnknownInputScriptType { idx: u32, script_type: String },
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
                format!("🐋 Large Transaction\nSize: {} vKB", size_bytes / 1000)
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
                    package_size / 1000
                )
            }
            Anomaly::ChainDepthIssue { depth } => {
                format!("⛓️ Chain Depth Issue\nChain Depth: {depth}")
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
        }
    }
}

pub struct Inspector {
    config: Config,
    rpc: Client,
}

impl Inspector {
    pub fn new(config: Config, rpc: Client) -> Self {
        Self { config, rpc }
    }

    pub fn analyze_transaction(
        &mut self,
        tx: &Transaction,
        from_block: bool,
    ) -> anyhow::Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();
        let txid = tx.compute_txid();

        if let Some(anomaly) = self.check_large_transaction(txid, tx) {
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

            if let Some(anomaly) = self.check_chain_depth(txid)? {
                anomalies.push(anomaly);
            }
        }

        let scripts = self.check_unusual_output_scripts(tx);
        if !scripts.is_empty() {
            anomalies.extend(scripts);
        }

        let dusts = self.check_dust_outputs(tx);
        if !dusts.is_empty() {
            anomalies.extend(dusts);
        }

        let inputs = self.check_inputs(tx);
        if !inputs.is_empty() {
            anomalies.extend(inputs);
        }

        Ok(anomalies)
    }

    fn check_large_transaction(&self, txid: Txid, tx: &Transaction) -> Option<Anomaly> {
        let size = tx.vsize();

        if size > self.config.large_tx_size {
            info!("Large transaction detected: {txid} (size: {size} bytes)",);
            return Some(Anomaly::LargeTransaction { size_bytes: size });
        }
        None
    }

    fn check_unusual_output_scripts(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.output
            .iter()
            .filter_map(|output| {
                let script = &output.script_pubkey;

                if script.is_op_return() && script.len() > 83 {
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

    fn check_dust_outputs(&self, tx: &Transaction) -> Vec<Anomaly> {
        const DUST_THRESHOLD: Amount = Amount::from_sat(546);

        tx.output
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
            .collect()
    }

    fn check_ancestor_chains(&self, txid: Txid) -> anyhow::Result<Option<Anomaly>> {
        match self.rpc.get_mempool_ancestors(txid) {
            Ok(ancestors) => {
                let ancestor_count = ancestors.0.len();
                if ancestor_count > self.config.max_ancestors as usize {
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
                if descendant_count > self.config.max_descendants as usize {
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

                if total_package_size > self.config.max_package_size as i64 {
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

    fn check_chain_depth(&self, txid: Txid) -> anyhow::Result<Option<Anomaly>> {
        if let Ok(ancestors) = self.rpc.get_mempool_ancestors(txid) {
            let depth = ancestors.0.len();
            if depth > self.config.max_ancestors as usize {
                info!("Chain depth issue detected: {txid} (depth: {depth})");
                return Ok(Some(Anomaly::ChainDepthIssue { depth }));
            }
        }
        Ok(None)
    }

    fn check_inputs(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.input
            .iter()
            .enumerate()
            .flat_map(|(idx, input)| {
                let leaf_script = input.witness.taproot_leaf_script();
                let annex = input.witness.taproot_annex();

                let prevout = self.rpc.get_tx_out(
                    input.previous_output.txid,
                    input.previous_output.vout as u64,
                );

                if prevout.is_err() {
                    return vec![];
                }

                let prevout_script = {
                    let prevout = prevout.unwrap();
                    ScriptBuf::from_hex(&prevout.script_pubkey.hex)
                };
                if prevout_script.is_err() {
                    return vec![Anomaly::UnknownInputScriptType {
                        idx: idx as u32,
                        script_type: "Unable to parse previous output script".to_string(),
                    }];
                }
                let prevout_script = prevout_script.unwrap();

                let is_p2tr = prevout_script.is_p2tr();

                let witness_version = prevout_script.witness_version();
                if witness_version.is_some_and(|v| v.to_num() > 1) {
                    return vec![Anomaly::UnknownInputScriptType {
                        idx: idx as u32,
                        script_type: format!(
                            "Spent Unknown SegWit v{}",
                            witness_version.unwrap().to_num()
                        ),
                    }];
                }

                // Shortcircuit if not P2TR
                if !is_p2tr {
                    return vec![];
                }

                let mut anomalies = Vec::new();
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
                }

                if annex.is_some() {
                    anomalies.push(Anomaly::HasAnnex { idx: idx as u32 });
                }

                anomalies
            })
            .collect()
    }
}

fn is_p2a(script: &ScriptBuf) -> bool {
    script.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
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
