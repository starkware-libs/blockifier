use starknet_api::transaction::TransactionVersion;

use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::ContractClass;
use crate::transaction::errors::TransactionExecutionError;

pub fn update_remaining_gas(remaining_gas: &mut u64, call_info: &CallInfo) {
    *remaining_gas -= call_info.execution.gas_consumed;
}

pub fn verify_contract_class_version(
    contract_class: &ContractClass,
    declare_version: TransactionVersion,
) -> Result<(), TransactionExecutionError> {
    match contract_class {
        // TODO: Make TransactionVersion an enum and use match here.
        ContractClass::V0(_) => {
            if declare_version == TransactionVersion::ZERO
                || declare_version == TransactionVersion::ONE
            {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 0,
            })
        }
        ContractClass::V1(_) => {
            if declare_version == TransactionVersion::TWO
                || declare_version == TransactionVersion::THREE
            {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 1,
            })
        }
    }
}
