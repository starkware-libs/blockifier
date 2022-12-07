use std::path::PathBuf;

use starknet_api::{Fee, StarkFelt, TransactionVersion};

use crate::execution::contract_class::ContractClass;
use crate::transaction::execution_objects::CallInfo;
use crate::transaction::transaction_errors::TransactionExecutionError;

// TODO(Adi, 10/12/2022): Remove this function once the transaction structs contain
// 'contract_address' instead of 'contract_path'.
pub fn get_contract_class(contract_path: &str) -> ContractClass {
    let path = PathBuf::from(contract_path);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

pub fn calculate_transaction_fee() -> Fee {
    Fee(1)
}

pub fn execute_fee_transfer(
    actual_fee: &Fee,
    max_fee: &Fee,
) -> Result<CallInfo, TransactionExecutionError> {
    if actual_fee > max_fee {
        return Err(TransactionExecutionError::from("Actual fee exceeded max fee."));
    }

    Ok(CallInfo::new())
}

// TODO(Adi, 10/12/2022): Replace Result error with StarkAssert error.
pub fn verify_transaction_version(version: TransactionVersion) -> Result<(), String> {
    // TODO(Adi, 10/12/2022): Consider using the lazy_static crate or some other solution, so the
    // supported_versions variable will only be constructed once.
    let supported_versions: [TransactionVersion; 1] = [TransactionVersion(StarkFelt::from_u64(1))];
    if supported_versions.contains(&version) {
        Ok(())
    } else {
        Err(format!(
            "Transaction version {:?} is not supported. Supported versions: {:?}.",
            version, supported_versions
        ))
    }
}
