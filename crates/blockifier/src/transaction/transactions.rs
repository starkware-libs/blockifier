use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::calldata;
use starknet_api::core::{
    calculate_contract_address, ClassHash, CompiledClassHash, ContractAddress, Nonce,
};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, ContractAddressSalt, DeclareTransactionV2,
    DeclareTransactionV3, Fee, Transaction as StarknetApiTransaction, TransactionHash,
    TransactionSignature, TransactionVersion,
};
use starknet_types_core::felt::Felt;

use crate::abi::abi_utils::selector_from_name;
use crate::bouncer::verify_tx_weights_in_bounds;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::{ClassInfo, ContractClass};
use crate::execution::entry_point::{
    CallEntryPoint, CallType, ConstructorContext, EntryPointExecutionContext,
};
use crate::execution::execution_utils::execute_deployment;
use crate::fee::actual_cost::TransactionReceipt;
use crate::state::cached_state::TransactionalState;
use crate::state::errors::StateError;
use crate::state::state_api::{State, UpdatableState};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::constants;
use crate::transaction::errors::{TransactionExecutionError, TransactionFeeError};
use crate::transaction::objects::{
    CommonAccountFields, CurrentTransactionInfo, DeprecatedTransactionInfo, HasRelatedFeeType,
    TransactionExecutionInfo, TransactionExecutionResult, TransactionInfo, TransactionInfoCreator,
};
use crate::transaction::transaction_utils::{update_remaining_gas, verify_contract_class_version};

#[cfg(test)]
#[path = "transactions_test.rs"]
mod test;

macro_rules! implement_inner_tx_getter_calls {
    ($(($field:ident, $field_type:ty)),*) => {
        $(pub fn $field(&self) -> $field_type {
            self.tx.$field().clone()
        })*
    };
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionFlags {
    pub charge_fee: bool,
    pub validate: bool,
    pub concurrency_mode: bool,
}
pub trait ExecutableTransaction<U: UpdatableState>: Sized {
    /// Executes the transaction in a transactional manner
    /// (if it fails, given state does not modify).
    fn execute(
        &self,
        state: &mut U,
        block_context: &BlockContext,
        charge_fee: bool,
        validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        log::debug!("Executing Transaction...");
        let mut transactional_state = TransactionalState::create_transactional(state);
        let execution_flags = ExecutionFlags { charge_fee, validate, concurrency_mode: false };
        let execution_result =
            self.execute_raw(&mut transactional_state, block_context, execution_flags);

        match execution_result {
            Ok(value) => {
                transactional_state.commit();
                log::debug!("Transaction execution complete and committed.");
                Ok(value)
            }
            Err(error) => {
                log::debug!("Transaction execution failed with: {error}");
                transactional_state.abort();
                Err(error)
            }
        }
    }

    /// Note: In case of execution failure, the state may become corrupted. This means that
    /// any changes made up to the point of failure will persist in the state. To revert these
    /// changes, you should call `state.abort()`. Alternatively, consider using `execute`
    /// for automatic handling of such cases.
    fn execute_raw(
        &self,
        state: &mut TransactionalState<'_, U>,
        block_context: &BlockContext,
        execution_flags: ExecutionFlags,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>;
}

pub trait Executable<S: State> {
    fn run_execute(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

/// Intended for use in sequencer pre-execution flows, like in a gateway service.
pub trait ValidatableTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut u64,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>>;
}

#[derive(Debug)]
pub struct DeclareTransaction {
    pub tx: starknet_api::transaction::DeclareTransaction,
    pub tx_hash: TransactionHash,
    // Indicates the presence of the only_query bit in the version.
    only_query: bool,
    pub class_info: ClassInfo,
}

impl DeclareTransaction {
    fn create(
        declare_tx: starknet_api::transaction::DeclareTransaction,
        tx_hash: TransactionHash,
        class_info: ClassInfo,
        only_query: bool,
    ) -> TransactionExecutionResult<Self> {
        let declare_version = declare_tx.version();
        verify_contract_class_version(&class_info.contract_class(), declare_version)?;
        Ok(Self { tx: declare_tx, tx_hash, class_info, only_query })
    }

    pub fn new(
        declare_tx: starknet_api::transaction::DeclareTransaction,
        tx_hash: TransactionHash,
        class_info: ClassInfo,
    ) -> TransactionExecutionResult<Self> {
        Self::create(declare_tx, tx_hash, class_info, false)
    }

    pub fn new_for_query(
        declare_tx: starknet_api::transaction::DeclareTransaction,
        tx_hash: TransactionHash,
        class_info: ClassInfo,
    ) -> TransactionExecutionResult<Self> {
        Self::create(declare_tx, tx_hash, class_info, true)
    }

    implement_inner_tx_getter_calls!((class_hash, ClassHash), (signature, TransactionSignature));

    pub fn tx(&self) -> &starknet_api::transaction::DeclareTransaction {
        &self.tx
    }

    pub fn tx_hash(&self) -> TransactionHash {
        self.tx_hash
    }

    pub fn contract_class(&self) -> ContractClass {
        self.class_info.contract_class()
    }

    pub fn only_query(&self) -> bool {
        self.only_query
    }

    fn try_declare<S: State>(
        &self,
        state: &mut S,
        class_hash: ClassHash,
        compiled_class_hash: Option<CompiledClassHash>,
    ) -> TransactionExecutionResult<()> {
        match state.get_compiled_contract_class(class_hash) {
            Err(StateError::UndeclaredClassHash(_)) => {
                // Class is undeclared; declare it.
                state.set_contract_class(class_hash, self.contract_class())?;
                if let Some(compiled_class_hash) = compiled_class_hash {
                    state.set_compiled_class_hash(class_hash, compiled_class_hash)?;
                }
                Ok(())
            }
            Err(error) => Err(error)?,
            Ok(_) => {
                // Class is already declared, cannot redeclare.
                Err(TransactionExecutionError::DeclareTransactionError { class_hash })
            }
        }
    }
}

impl<S: State> Executable<S> for DeclareTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        _resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        _remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let class_hash = self.class_hash();
        match &self.tx {
            starknet_api::transaction::DeclareTransaction::V0(_)
            | starknet_api::transaction::DeclareTransaction::V1(_) => {
                if context.tx_context.block_context.versioned_constants.disable_cairo0_redeclaration
                {
                    self.try_declare(state, class_hash, None)?
                } else {
                    // We allow redeclaration of the class for backward compatibility.
                    // In the past, we allowed redeclaration of Cairo 0 contracts since there was
                    // no class commitment (so no need to check if the class is already declared).
                    state.set_contract_class(class_hash, self.contract_class())?;
                }
            }
            starknet_api::transaction::DeclareTransaction::V2(DeclareTransactionV2 {
                compiled_class_hash,
                ..
            })
            | starknet_api::transaction::DeclareTransaction::V3(DeclareTransactionV3 {
                compiled_class_hash,
                ..
            }) => self.try_declare(state, class_hash, Some(*compiled_class_hash))?,
        }
        Ok(None)
    }
}

impl TransactionInfoCreator for DeclareTransaction {
    fn create_tx_info(&self) -> TransactionInfo {
        // TODO(Nir, 01/11/2023): Consider to move this (from all get_tx_info methods).
        let common_fields = CommonAccountFields {
            transaction_hash: self.tx_hash(),
            version: self.tx.version(),
            signature: self.tx.signature(),
            nonce: self.tx.nonce(),
            sender_address: self.tx.sender_address(),
            only_query: self.only_query,
        };

        match &self.tx {
            starknet_api::transaction::DeclareTransaction::V0(tx)
            | starknet_api::transaction::DeclareTransaction::V1(tx) => {
                TransactionInfo::Deprecated(DeprecatedTransactionInfo {
                    common_fields,
                    max_fee: tx.max_fee,
                })
            }
            starknet_api::transaction::DeclareTransaction::V2(tx) => {
                TransactionInfo::Deprecated(DeprecatedTransactionInfo {
                    common_fields,
                    max_fee: tx.max_fee,
                })
            }
            starknet_api::transaction::DeclareTransaction::V3(tx) => {
                TransactionInfo::Current(CurrentTransactionInfo {
                    common_fields,
                    resource_bounds: tx.resource_bounds.clone(),
                    tip: tx.tip,
                    nonce_data_availability_mode: tx.nonce_data_availability_mode,
                    fee_data_availability_mode: tx.fee_data_availability_mode,
                    paymaster_data: tx.paymaster_data.clone(),
                    account_deployment_data: tx.account_deployment_data.clone(),
                })
            }
        }
    }
}
#[derive(Debug, Clone)]
pub struct DeployAccountTransaction {
    pub tx: starknet_api::transaction::DeployAccountTransaction,
    pub tx_hash: TransactionHash,
    pub contract_address: ContractAddress,
    // Indicates the presence of the only_query bit in the version.
    pub only_query: bool,
}

impl DeployAccountTransaction {
    pub fn new(
        deploy_account_tx: starknet_api::transaction::DeployAccountTransaction,
        tx_hash: TransactionHash,
        contract_address: ContractAddress,
    ) -> Self {
        Self { tx: deploy_account_tx, tx_hash, contract_address, only_query: false }
    }

    pub fn new_for_query(
        deploy_account_tx: starknet_api::transaction::DeployAccountTransaction,
        tx_hash: TransactionHash,
        contract_address: ContractAddress,
    ) -> Self {
        Self { tx: deploy_account_tx, tx_hash, contract_address, only_query: true }
    }

    implement_inner_tx_getter_calls!(
        (class_hash, ClassHash),
        (constructor_calldata, Calldata),
        (contract_address_salt, ContractAddressSalt),
        (nonce, Nonce),
        (signature, TransactionSignature)
    );

    pub fn tx(&self) -> &starknet_api::transaction::DeployAccountTransaction {
        &self.tx
    }
}

impl<S: State> Executable<S> for DeployAccountTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let class_hash = self.class_hash();
        let ctor_context = ConstructorContext {
            class_hash,
            code_address: None,
            storage_address: self.contract_address,
            caller_address: ContractAddress::default(),
        };
        let call_info = execute_deployment(
            state,
            resources,
            context,
            ctor_context,
            self.constructor_calldata(),
            *remaining_gas,
        )?;
        update_remaining_gas(remaining_gas, &call_info);

        Ok(Some(call_info))
    }
}

impl TransactionInfoCreator for DeployAccountTransaction {
    fn create_tx_info(&self) -> TransactionInfo {
        let common_fields = CommonAccountFields {
            transaction_hash: self.tx_hash,
            version: self.tx.version(),
            signature: self.tx.signature(),
            nonce: self.tx.nonce(),
            sender_address: self.contract_address,
            only_query: self.only_query,
        };

        match &self.tx {
            starknet_api::transaction::DeployAccountTransaction::V1(tx) => {
                TransactionInfo::Deprecated(DeprecatedTransactionInfo {
                    common_fields,
                    max_fee: tx.max_fee,
                })
            }
            starknet_api::transaction::DeployAccountTransaction::V3(tx) => {
                TransactionInfo::Current(CurrentTransactionInfo {
                    common_fields,
                    resource_bounds: tx.resource_bounds.clone(),
                    tip: tx.tip,
                    nonce_data_availability_mode: tx.nonce_data_availability_mode,
                    fee_data_availability_mode: tx.fee_data_availability_mode,
                    paymaster_data: tx.paymaster_data.clone(),
                    account_deployment_data: AccountDeploymentData::default(),
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvokeTransaction {
    pub tx: starknet_api::transaction::InvokeTransaction,
    pub tx_hash: TransactionHash,
    // Indicates the presence of the only_query bit in the version.
    pub only_query: bool,
}

impl InvokeTransaction {
    pub fn new(
        invoke_tx: starknet_api::transaction::InvokeTransaction,
        tx_hash: TransactionHash,
    ) -> Self {
        Self { tx: invoke_tx, tx_hash, only_query: false }
    }

    pub fn new_for_query(
        invoke_tx: starknet_api::transaction::InvokeTransaction,
        tx_hash: TransactionHash,
    ) -> Self {
        Self { tx: invoke_tx, tx_hash, only_query: true }
    }

    implement_inner_tx_getter_calls!(
        (calldata, Calldata),
        (signature, TransactionSignature),
        (sender_address, ContractAddress)
    );
}

impl<S: State> Executable<S> for InvokeTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let entry_point_selector = match &self.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => tx.entry_point_selector,
            starknet_api::transaction::InvokeTransaction::V1(_)
            | starknet_api::transaction::InvokeTransaction::V3(_) => {
                selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME)
            }
        };
        let storage_address = context.tx_context.tx_info.sender_address();
        let class_hash = state.get_class_hash_at(storage_address)?;
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector,
            calldata: self.calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: *remaining_gas,
        };

        let call_info = execute_call.execute(state, resources, context).map_err(|error| {
            TransactionExecutionError::ExecutionError {
                error,
                class_hash,
                storage_address,
                selector: entry_point_selector,
            }
        })?;
        update_remaining_gas(remaining_gas, &call_info);

        Ok(Some(call_info))
    }
}

impl TransactionInfoCreator for InvokeTransaction {
    fn create_tx_info(&self) -> TransactionInfo {
        let common_fields = CommonAccountFields {
            transaction_hash: self.tx_hash,
            version: self.tx.version(),
            signature: self.tx.signature(),
            nonce: self.tx.nonce(),
            sender_address: self.tx.sender_address(),
            only_query: self.only_query,
        };

        match &self.tx {
            starknet_api::transaction::InvokeTransaction::V0(tx) => {
                TransactionInfo::Deprecated(DeprecatedTransactionInfo {
                    common_fields,
                    max_fee: tx.max_fee,
                })
            }
            starknet_api::transaction::InvokeTransaction::V1(tx) => {
                TransactionInfo::Deprecated(DeprecatedTransactionInfo {
                    common_fields,
                    max_fee: tx.max_fee,
                })
            }
            starknet_api::transaction::InvokeTransaction::V3(tx) => {
                TransactionInfo::Current(CurrentTransactionInfo {
                    common_fields,
                    resource_bounds: tx.resource_bounds.clone(),
                    tip: tx.tip,
                    nonce_data_availability_mode: tx.nonce_data_availability_mode,
                    fee_data_availability_mode: tx.fee_data_availability_mode,
                    paymaster_data: tx.paymaster_data.clone(),
                    account_deployment_data: tx.account_deployment_data.clone(),
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct L1HandlerTransaction {
    pub tx: starknet_api::transaction::L1HandlerTransaction,
    pub tx_hash: TransactionHash,
    pub paid_fee_on_l1: Fee,
}

impl L1HandlerTransaction {
    pub fn payload_size(&self) -> usize {
        // The calldata includes the "from" field, which is not a part of the payload.
        self.tx.calldata.0.len() - 1
    }

    pub fn create_for_testing(l1_fee: Fee, contract_address: ContractAddress) -> Self {
        let calldata = calldata![
            Felt::from(0x123), // from_address.
            Felt::from(0x876), // key.
            Felt::from(0x44)   // value.
        ];
        let tx = starknet_api::transaction::L1HandlerTransaction {
            version: TransactionVersion::ZERO,
            nonce: Nonce::default(),
            contract_address,
            entry_point_selector: selector_from_name("l1_handler_set_value"),
            calldata,
        };
        let tx_hash = TransactionHash::default();
        Self { tx, tx_hash, paid_fee_on_l1: l1_fee }
    }
}

impl HasRelatedFeeType for L1HandlerTransaction {
    fn version(&self) -> TransactionVersion {
        self.tx.version
    }

    fn is_l1_handler(&self) -> bool {
        true
    }
}

impl<S: State> Executable<S> for L1HandlerTransaction {
    fn run_execute(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let tx = &self.tx;
        let storage_address = tx.contract_address;
        let class_hash = state.get_class_hash_at(storage_address)?;
        let selector = tx.entry_point_selector;
        let execute_call = CallEntryPoint {
            entry_point_type: EntryPointType::L1Handler,
            entry_point_selector: selector,
            calldata: Calldata(Arc::clone(&tx.calldata.0)),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: *remaining_gas,
        };

        execute_call.execute(state, resources, context).map(Some).map_err(|error| {
            TransactionExecutionError::ExecutionError {
                error,
                class_hash,
                storage_address,
                selector,
            }
        })
    }
}

impl TransactionInfoCreator for L1HandlerTransaction {
    fn create_tx_info(&self) -> TransactionInfo {
        TransactionInfo::Deprecated(DeprecatedTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash: self.tx_hash,
                version: self.tx.version,
                signature: TransactionSignature::default(),
                nonce: self.tx.nonce,
                sender_address: self.tx.contract_address,
                only_query: false,
            },
            max_fee: Fee::default(),
        })
    }
}

#[derive(Debug, derive_more::From)]
pub enum Transaction {
    AccountTransaction(AccountTransaction),
    L1HandlerTransaction(L1HandlerTransaction),
}

impl Transaction {
    pub fn from_api(
        tx: StarknetApiTransaction,
        tx_hash: TransactionHash,
        class_info: Option<ClassInfo>,
        paid_fee_on_l1: Option<Fee>,
        deployed_contract_address: Option<ContractAddress>,
        only_query: bool,
    ) -> TransactionExecutionResult<Self> {
        match tx {
            StarknetApiTransaction::L1Handler(l1_handler) => {
                Ok(Self::L1HandlerTransaction(L1HandlerTransaction {
                    tx: l1_handler,
                    tx_hash,
                    paid_fee_on_l1: paid_fee_on_l1
                        .expect("L1Handler should be created with the fee paid on L1"),
                }))
            }
            StarknetApiTransaction::Declare(declare) => {
                let non_optional_class_info =
                    class_info.expect("Declare should be created with a ClassInfo.");
                let declare_tx = match only_query {
                    true => {
                        DeclareTransaction::new_for_query(declare, tx_hash, non_optional_class_info)
                    }
                    false => DeclareTransaction::new(declare, tx_hash, non_optional_class_info),
                };
                Ok(Self::AccountTransaction(AccountTransaction::Declare(declare_tx?)))
            }
            StarknetApiTransaction::DeployAccount(deploy_account) => {
                let contract_address = match deployed_contract_address {
                    Some(address) => address,
                    None => calculate_contract_address(
                        deploy_account.contract_address_salt(),
                        deploy_account.class_hash(),
                        &deploy_account.constructor_calldata(),
                        ContractAddress::default(),
                    )?,
                };
                let deploy_account_tx = match only_query {
                    true => DeployAccountTransaction::new_for_query(
                        deploy_account,
                        tx_hash,
                        contract_address,
                    ),
                    false => {
                        DeployAccountTransaction::new(deploy_account, tx_hash, contract_address)
                    }
                };
                Ok(Self::AccountTransaction(AccountTransaction::DeployAccount(deploy_account_tx)))
            }
            StarknetApiTransaction::Invoke(invoke) => {
                let invoke_tx = match only_query {
                    true => InvokeTransaction::new_for_query(invoke, tx_hash),
                    false => InvokeTransaction::new(invoke, tx_hash),
                };
                Ok(Self::AccountTransaction(AccountTransaction::Invoke(invoke_tx)))
            }
            _ => unimplemented!(),
        }
    }
}

impl TransactionInfoCreator for Transaction {
    fn create_tx_info(&self) -> TransactionInfo {
        match self {
            Self::AccountTransaction(account_tx) => account_tx.create_tx_info(),
            Self::L1HandlerTransaction(l1_handler_tx) => l1_handler_tx.create_tx_info(),
        }
    }
}

impl<U: UpdatableState> ExecutableTransaction<U> for L1HandlerTransaction {
    fn execute_raw(
        &self,
        state: &mut TransactionalState<'_, U>,
        block_context: &BlockContext,
        _execution_flags: ExecutionFlags,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_context = Arc::new(block_context.to_tx_context(self));

        let mut execution_resources = ExecutionResources::default();
        let mut context = EntryPointExecutionContext::new_invoke(tx_context.clone(), true)?;
        let mut remaining_gas = block_context.versioned_constants.tx_initial_gas();
        let execute_call_info =
            self.run_execute(state, &mut execution_resources, &mut context, &mut remaining_gas)?;
        let l1_handler_payload_size = self.payload_size();

        let TransactionReceipt {
            fee: actual_fee,
            da_gas,
            resources: actual_resources,
            gas: total_gas,
        } = TransactionReceipt::from_l1_handler(
            &tx_context,
            l1_handler_payload_size,
            execute_call_info.iter(),
            &state.get_actual_state_changes()?,
            &execution_resources,
        )?;

        let paid_fee = self.paid_fee_on_l1;
        // For now, assert only that any amount of fee was paid.
        // The error message still indicates the required fee.
        if paid_fee == Fee(0) {
            return Err(TransactionFeeError::InsufficientL1Fee { paid_fee, actual_fee })?;
        }

        Ok(TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info,
            fee_transfer_call_info: None,
            transaction_receipt: TransactionReceipt {
                fee: Fee::default(),
                da_gas,
                resources: actual_resources,
                gas: total_gas,
            },
            revert_error: None,
        })
    }
}

impl<U: UpdatableState> ExecutableTransaction<U> for Transaction {
    fn execute_raw(
        &self,
        state: &mut TransactionalState<'_, U>,
        block_context: &BlockContext,
        execution_flags: ExecutionFlags,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        // TODO(Yoni, 1/8/2024): consider unimplementing the ExecutableTransaction trait for inner
        // types, since now running Transaction::execute_raw is not identical to
        // AccountTransaction::execute_raw.
        let concurrency_mode = execution_flags.concurrency_mode;
        let tx_execution_info = match self {
            Self::AccountTransaction(account_tx) => {
                account_tx.execute_raw(state, block_context, execution_flags)?
            }
            Self::L1HandlerTransaction(tx) => {
                tx.execute_raw(state, block_context, execution_flags)?
            }
        };

        // Check if the transaction is too large to fit any block.
        // TODO(Yoni, 1/8/2024): consider caching these two.
        let tx_execution_summary = tx_execution_info.summarize();
        let mut tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
        tx_state_changes_keys.update_sequencer_key_in_storage(
            &block_context.to_tx_context(self),
            &tx_execution_info,
            concurrency_mode,
        );
        verify_tx_weights_in_bounds(
            state,
            &tx_execution_summary,
            &tx_execution_info.transaction_receipt.resources,
            &tx_state_changes_keys,
            &block_context.bouncer_config,
        )?;

        Ok(tx_execution_info)
    }
}
