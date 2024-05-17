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
        ContractClass::V0(_) => {
            if let TransactionVersion::ZERO | TransactionVersion::ONE = declare_version {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 0,
            })
        }
        ContractClass::V1(_) => {
            if let TransactionVersion::TWO | TransactionVersion::THREE = declare_version {
                return Ok(());
            }
            Err(TransactionExecutionError::ContractClassVersionMismatch {
                declare_version,
                cairo_version: 1,
            })
        }
        ContractClass::V1Sierra(_) => todo!("Sierra verify contract class version"),
    }
}
