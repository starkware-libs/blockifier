use std::collections::HashMap;

use papyrus_gateway::transaction::Transaction as GatewayTransaction;
use serde::{Deserialize, Serialize};
use starknet_api::core::ClassHash;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WrappedTransactionWithType {
    pub tx: GatewayTransaction,
    pub time_created: u64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TxIdToTxFile {
    pub map: HashMap<usize, WrappedTransactionWithType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TxIdToDeprecatedContractClass {
    pub map: HashMap<usize, DeprecatedContractClass>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ContractMap {
    pub map: HashMap<ClassHash, DeprecatedContractClass>,
}
