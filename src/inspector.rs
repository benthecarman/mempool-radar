use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Transaction, Txid};
use corepc_client::client_sync::v29::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    HasOpSuccess { idx: u32, opcode: u8 },
    UnknownLeafVersion { idx: u32, version: u8 },
}

impl Anomaly {
    pub fn to_message(&self) -> String {
        match self {
            Anomaly::LargeTransaction { size_bytes } => {
                format!("🐋 Large Transaction\nSize: {} KB", size_bytes / 1000,)
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

    pub fn analyze_transaction(&mut self, tx: &Transaction) -> anyhow::Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();
        let txid = tx.compute_txid();

        if let Some(anomaly) = self.check_large_transaction(txid, tx) {
            anomalies.push(anomaly);
        }

        if let Some(anomaly) = self.check_unusual_version(tx) {
            anomalies.push(anomaly);
        }

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

        let scripts = self.check_unusual_output_scripts(tx);
        if !scripts.is_empty() {
            anomalies.extend(scripts);
        }

        let dusts = self.check_dust_outputs(tx);
        if !dusts.is_empty() {
            anomalies.extend(dusts);
        }

        let annexes = self.check_has_annex(tx);
        if !annexes.is_empty() {
            anomalies.extend(annexes);
        }

        let tapscripts = self.check_tapscripts(tx);
        if !tapscripts.is_empty() {
            anomalies.extend(tapscripts);
        }

        Ok(anomalies)
    }

    fn check_large_transaction(&self, txid: Txid, tx: &Transaction) -> Option<Anomaly> {
        let size = tx.total_size();

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
                    && !script.is_p2wsh()
                    && !script.is_p2tr()
                    && !script.is_op_return()
                    && !script.is_multisig()
                {
                    Some(Anomaly::UnusualScript {
                        script_type: "Non-standard".to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn check_unusual_version(&self, tx: &Transaction) -> Option<Anomaly> {
        if !tx.version.is_standard() {
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
        let mut total_package_size = 0i64;

        // Get the entry for this transaction to get its size
        match self.rpc.get_mempool_entry(txid) {
            Ok(entry) => {
                total_package_size += entry.0.vsize;

                // Get ancestors and add their sizes
                if let Ok(ancestors) = self.rpc.get_mempool_ancestors(txid) {
                    for ancestor_txid_str in ancestors.0 {
                        if let Ok(ancestor_txid) = ancestor_txid_str.parse()
                            && let Ok(ancestor_entry) = self.rpc.get_mempool_entry(ancestor_txid)
                        {
                            total_package_size += ancestor_entry.0.vsize;
                        }
                    }
                }

                // Get descendants and add their sizes
                if let Ok(descendants) = self.rpc.get_mempool_descendants(txid) {
                    for descendant_txid_str in descendants.0 {
                        if let Ok(descendant_txid) = descendant_txid_str.parse()
                            && let Ok(descendant_entry) =
                                self.rpc.get_mempool_entry(descendant_txid)
                        {
                            total_package_size += descendant_entry.0.vsize;
                        }
                    }
                }

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

    fn check_has_annex(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.input
            .iter()
            .enumerate()
            .filter_map(|(idx, input)| {
                if input.witness.taproot_annex().is_some() {
                    info!("Transaction has annex in input index {idx}");
                    return Some(Anomaly::HasAnnex { idx: idx as u32 });
                }
                None
            })
            .collect()
    }

    fn check_tapscripts(&self, tx: &Transaction) -> Vec<Anomaly> {
        tx.input
            .iter()
            .enumerate()
            .flat_map(|(idx, input)| {
                let leaf_script = input.witness.taproot_leaf_script();
                let annex = input.witness.taproot_annex();

                // Shortcircuit if neither leaf_script nor annex is present
                if leaf_script.is_none() && annex.is_none() {
                    return vec![];
                }

                let prevout = self.rpc.get_tx_out(
                    input.previous_output.txid,
                    input.previous_output.vout as u64,
                );

                if prevout.is_err() {
                    return vec![];
                }

                let is_p2tr = {
                    let prevout = prevout.unwrap();
                    ScriptBuf::from_hex(&prevout.script_pubkey.hex)
                        .is_ok_and(|script| script.is_p2tr())
                };

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
                                opcode: opcode.to_u8(),
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
