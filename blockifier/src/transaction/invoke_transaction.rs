use serde::{Deserialize, Serialize};
use starknet_api::core::{EntryPointSelector, Nonce};
use starknet_api::hash::StarkHash;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{
    CallData, Fee, TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::execution::entry_point::CallEntryPoint;
use crate::transaction::constants::{EXECUTE_ENTRY_POINT_SELECTOR, VALIDATE_ENTRY_POINT_SELECTOR};
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionInfo};
use crate::transaction::transaction_utils::{
    calculate_transaction_fee, execute_fee_transfer, get_contract_class, verify_transaction_version,
};
use crate::transaction::ExecuteTransaction;

#[cfg(test)]
#[path = "invoke_transaction_test.rs"]
mod test;

// TODO(Adi, 23/12/2022): Use the definition from starknet_api instead, once 'contract_address' is
// used in CallEntryPoint.
/// An invoke transaction in StarkNet.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct InvokeTransaction {
    pub transaction_hash: TransactionHash,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    // Temporarily replaces contract_address.
    pub contract_file_path: String,
    pub entry_point_selector: Option<EntryPointSelector>,
    pub calldata: CallData,
}

impl ExecuteTransaction for InvokeTransaction {
    fn execute(&self) -> Result<TransactionExecutionInfo, TransactionExecutionError> {
        // TODO(Adi, 10/12/2022): Consider moving the transaction version verification to the
        // TransactionVersion constructor.
        verify_transaction_version(self.version)?;
        let contract_class = get_contract_class(&self.contract_file_path);

        // Validate transaction.
        let validate_call = CallEntryPoint {
            contract_class,
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(StarkHash::try_from(
                VALIDATE_ENTRY_POINT_SELECTOR,
            )?),
            // '__validate__' is expected to get the same calldata as '__execute__'.
            calldata: self.calldata.clone(),
        };
        let validate_info = validate_call.execute()?;

        // Execute transaction.
        let execute_call = CallEntryPoint {
            entry_point_selector: EntryPointSelector(StarkHash::try_from(
                EXECUTE_ENTRY_POINT_SELECTOR,
            )?),
            ..validate_call
        };
        let execute_info = execute_call.execute()?;

        let actual_resources = ResourcesMapping::default();

        // Charge fee.
        let actual_fee = calculate_transaction_fee();
        let fee_transfer_info = execute_fee_transfer(actual_fee, self.max_fee)?;

        Ok(TransactionExecutionInfo {
            validate_info,
            execute_info: Some(execute_info),
            fee_transfer_info,
            actual_fee,
            actual_resources,
        })
    }
}
