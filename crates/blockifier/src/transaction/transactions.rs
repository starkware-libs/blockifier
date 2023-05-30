use std::sync::Arc;

use cairo_felt::Felt252;
use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::transaction::{Calldata, DeployAccountTransaction, Fee, InvokeTransaction};

use super::transaction_utils::update_remaining_gas;
use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, ConstructorContext, ExecutionContext,
};
use crate::execution::execution_utils::execute_deployment;
use crate::state::cached_state::{CachedState, MutRefState, TransactionalState};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transaction_utils::verify_no_calls_to_other_contracts;

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

pub trait ExecutableTransaction<S: StateReader>: Sized {
    /// Executes the transaction in a transactional manner
    /// (if it fails, given state does not modify).
    fn execute(
        self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        log::debug!("Executing Transaction...");
        let mut transactional_state = CachedState::new(MutRefState::new(state));
        let mut initial_gas = Transaction::initial_gas();
        let execution_result =
            self.execute_raw(&mut transactional_state, block_context, &mut initial_gas);

        match execution_result {
            Ok(value) => {
                transactional_state.commit();
                log::debug!("Transaction execution complete and committed.");
                Ok(value)
            }
            Err(error) => {
                log::warn!("Transaction execution failed with: {error}");
                transactional_state.abort();
                Err(error)
            }
        }
    }

    /// Executes the transaction in a transactional manner
    /// (if it fails, given state might become corrupted; i.e., changes until failure will appear).
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>;
}

pub trait Executable<S: State> {
    fn run_execute(
        &self,
        state: &mut S,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

#[derive(Debug)]
pub struct DeclareTransaction {
    tx: starknet_api::transaction::DeclareTransaction,
    contract_class: ContractClass,
}

impl DeclareTransaction {
    pub fn new(
        declare_tx: starknet_api::transaction::DeclareTransaction,
        contract_class: ContractClass,
    ) -> TransactionExecutionResult<Self> {
        let declare_version = declare_tx.version();
        match declare_tx {
            starknet_api::transaction::DeclareTransaction::V0(tx) => {
                let ContractClass::V0(contract_class) = contract_class
                else {
                    return Err(TransactionExecutionError::ContractClassVersionMismatch
                        {declare_version, cairo_version: 0})
                };
                Ok(Self {
                    tx: starknet_api::transaction::DeclareTransaction::V0(tx),
                    contract_class: contract_class.into(),
                })
            }
            starknet_api::transaction::DeclareTransaction::V1(tx) => {
                let ContractClass::V0(contract_class) = contract_class
                else {
                    return Err(TransactionExecutionError::ContractClassVersionMismatch
                        {declare_version, cairo_version: 0})

                };
                Ok(Self {
                    tx: starknet_api::transaction::DeclareTransaction::V1(tx),
                    contract_class: contract_class.into(),
                })
            }
            starknet_api::transaction::DeclareTransaction::V2(tx) => {
                let ContractClass::V1(contract_class) = contract_class
                else {
                    return Err(TransactionExecutionError::ContractClassVersionMismatch
                        {declare_version, cairo_version: 1})

                };
                Ok(Self {
                    tx: starknet_api::transaction::DeclareTransaction::V2(tx),
                    contract_class: contract_class.into(),
                })
            }
        }
    }

    pub fn tx(&self) -> &starknet_api::transaction::DeclareTransaction {
        &self.tx
    }

    pub fn contract_class(&self) -> ContractClass {
        self.contract_class.clone()
    }
}

impl<S: State> Executable<S> for DeclareTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        _ctx: &mut ExecutionContext,
        _remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let class_hash = self.tx.class_hash();

        match &self.tx {
            // No class commitment, so no need to check if the class is already declared.
            starknet_api::transaction::DeclareTransaction::V0(_)
            | starknet_api::transaction::DeclareTransaction::V1(_) => {
                state.set_contract_class(&class_hash, self.contract_class.clone())?;
                Ok(None)
            }
            starknet_api::transaction::DeclareTransaction::V2(tx) => {
                match state.get_compiled_contract_class(&class_hash) {
                    Err(StateError::UndeclaredClassHash(_)) => {
                        // Class is undeclared; declare it.
                        state.set_contract_class(&class_hash, self.contract_class.clone())?;
                        state.set_compiled_class_hash(class_hash, tx.compiled_class_hash)?;
                        Ok(None)
                    }
                    Err(error) => Err(error).map_err(TransactionExecutionError::from),
                    Ok(_) => {
                        // Class is already declared, cannot redeclare
                        // (i.e., make sure the leaf is uninitialized).
                        Err(TransactionExecutionError::DeclareTransactionError { class_hash })
                    }
                }
            }
        }
    }
}

impl<S: State> Executable<S> for DeployAccountTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let constructor_context = ConstructorContext {
            class_hash: self.class_hash,
            code_address: None,
            storage_address: self.contract_address,
            caller_address: ContractAddress::default(),
        };
        let deployment_result = execute_deployment(
            state,
            context,
            constructor_context,
            self.constructor_calldata.clone(),
            remaining_gas.clone(),
        );
        let call_info = deployment_result
            .map_err(TransactionExecutionError::ContractConstructorExecutionFailed)?;
        update_remaining_gas(remaining_gas, &call_info);
        verify_no_calls_to_other_contracts(&call_info, String::from("an account constructor"))?;

        Ok(Some(call_info))
    }
}

impl<S: State> Executable<S> for InvokeTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let entry_point_selector = match self {
            InvokeTransaction::V0(tx) => tx.entry_point_selector,
            InvokeTransaction::V1(_) => selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
        };
        let storage_address = self.sender_address();
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector,
            calldata: self.calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: remaining_gas.clone(),
        };

        let call_info = execute_call
            .execute(state, context)
            .map_err(TransactionExecutionError::ExecutionError)?;
        update_remaining_gas(remaining_gas, &call_info);

        Ok(Some(call_info))
    }
}

#[derive(Debug)]
pub struct L1HandlerTransaction {
    pub tx: starknet_api::transaction::L1HandlerTransaction,
    pub paid_fee_on_l1: Fee,
}

impl<S: State> Executable<S> for L1HandlerTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        context: &mut ExecutionContext,
        remaining_gas: &mut Felt252,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let tx = &self.tx;
        let storage_address = tx.contract_address;
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: tx.entry_point_selector,
            calldata: Calldata(Arc::clone(&tx.calldata.0)),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: remaining_gas.clone(),
        };

        execute_call
            .execute(state, context)
            .map(Some)
            .map_err(TransactionExecutionError::ExecutionError)
    }
}
