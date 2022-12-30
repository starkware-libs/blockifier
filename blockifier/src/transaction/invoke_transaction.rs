use starknet_api::core::{ClassHash, EntryPointSelector};
use starknet_api::hash::StarkHash;
use starknet_api::shash;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Fee, InvokeTransaction};

use crate::execution::entry_point::{CallEntryPoint, CallInfo};
use crate::state::cached_state::CachedState;
use crate::state::state_reader::StateReader;
use crate::test_utils::TEST_ACCOUNT_CONTRACT_CLASS_HASH;
use crate::transaction::constants::{EXECUTE_ENTRY_POINT_SELECTOR, VALIDATE_ENTRY_POINT_SELECTOR};
use crate::transaction::objects::{
    AccountTransactionContext, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult,
};
use crate::transaction::transaction_utils::{
    calculate_tx_fee, execute_fee_transfer, verify_tx_version,
};
use crate::transaction::ExecuteTransaction;

#[cfg(test)]
#[path = "invoke_transaction_test.rs"]
mod test;

pub fn validate_tx<SR: StateReader>(
    tx: &InvokeTransaction,
    state: &mut CachedState<SR>,
    account_tx_context: &AccountTransactionContext,
    class_hash: ClassHash,
) -> TransactionExecutionResult<CallInfo> {
    let validate_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkHash::try_from(
            VALIDATE_ENTRY_POINT_SELECTOR,
        )?),
        // Gets the same calldata as the execution itself.
        calldata: tx.calldata.clone(),
        class_hash,
        storage_address: tx.sender_address,
    };

    Ok(validate_call.execute(state, account_tx_context)?)
}

pub fn execute_tx<SR: StateReader>(
    tx: &InvokeTransaction,
    state: &mut CachedState<SR>,
    account_tx_context: &AccountTransactionContext,
    class_hash: ClassHash,
) -> TransactionExecutionResult<CallInfo> {
    let execute_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkHash::try_from(
            EXECUTE_ENTRY_POINT_SELECTOR,
        )?),
        calldata: tx.calldata.clone(),
        class_hash,
        storage_address: tx.sender_address,
    };

    Ok(execute_call.execute(state, account_tx_context)?)
}

pub fn charge_fee(tx: InvokeTransaction) -> TransactionExecutionResult<(Fee, CallInfo)> {
    let actual_fee = calculate_tx_fee();
    let fee_transfer_call_info = execute_fee_transfer(actual_fee, tx.max_fee)?;

    Ok((actual_fee, fee_transfer_call_info))
}

impl<SR: StateReader> ExecuteTransaction<SR> for InvokeTransaction {
    fn execute(
        self,
        state: &mut CachedState<SR>,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        // TODO(Adi, 10/12/2022): Consider moving the transaction version verification to the
        // TransactionVersion constructor.
        verify_tx_version(self.version)?;
        // TODO (Adi, 25/12/2022): Replace with 'get_class_hash_at' once it is implemented.
        let class_hash = ClassHash(shash!(TEST_ACCOUNT_CONTRACT_CLASS_HASH));

        let account_tx_context = AccountTransactionContext {
            transaction_hash: self.transaction_hash,
            max_fee: self.max_fee,
            version: self.version,
            signature: self.signature.clone(),
            nonce: self.nonce,
            sender_address: self.sender_address,
        };

        // Validate transaction.
        let validate_call_info = validate_tx(&self, state, &account_tx_context, class_hash)?;

        // Execute transaction.
        let execute_call_info = execute_tx(&self, state, &account_tx_context, class_hash)?;

        // Charge fee.
        // TODO(Adi, 25/12/2022): Get actual resources.
        let actual_resources = ResourcesMapping::default();
        let (actual_fee, fee_transfer_call_info) = charge_fee(self)?;

        Ok(TransactionExecutionInfo {
            validate_call_info,
            execute_call_info: Some(execute_call_info),
            fee_transfer_call_info,
            actual_fee,
            actual_resources,
        })
    }
}
