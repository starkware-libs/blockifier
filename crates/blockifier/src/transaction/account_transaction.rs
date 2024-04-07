use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::concat;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee, ResourceBounds, TransactionVersion};

use crate::abi::abi_utils::selector_from_name;
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::{CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{CallEntryPoint, CallType, EntryPointExecutionContext};
use crate::fee::actual_cost::{ActualCost, ActualCostBuilder};
use crate::fee::fee_checks::{FeeCheckReportFields, PostExecutionReport};
use crate::fee::fee_utils::{get_fee_by_gas_vector, verify_can_pay_committed_bounds};
use crate::fee::gas_usage::{compute_discounted_gas_from_gas_vector, estimate_minimal_gas_vector};
use crate::retdata;
use crate::state::cached_state::{CachedState, TransactionalState};
use crate::state::state_api::{State, StateReader};
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::transaction::objects::{
    DeprecatedTransactionInfo, HasRelatedFeeType, ResourcesMapping, TransactionExecutionInfo,
    TransactionExecutionResult, TransactionInfo, TransactionInfoCreator,
    TransactionPreValidationResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::update_remaining_gas;
use crate::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, Executable, ExecutableTransaction,
    InvokeTransaction, ValidatableTransaction,
};

#[cfg(test)]
#[path = "account_transactions_test.rs"]
mod test;

#[cfg(test)]
#[path = "execution_flavors_test.rs"]
mod flavors_test;

#[cfg(test)]
#[path = "post_execution_test.rs"]
mod post_execution_test;

/// Represents a paid Starknet transaction.
#[derive(Debug)]
pub enum AccountTransaction {
    Declare(DeclareTransaction),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
}

impl HasRelatedFeeType for AccountTransaction {
    fn version(&self) -> TransactionVersion {
        match self {
            Self::Declare(tx) => tx.tx.version(),
            Self::DeployAccount(tx) => tx.tx.version(),
            Self::Invoke(tx) => match tx.tx {
                starknet_api::transaction::InvokeTransaction::V0(_) => TransactionVersion::ZERO,
                starknet_api::transaction::InvokeTransaction::V1(_) => TransactionVersion::ONE,
                starknet_api::transaction::InvokeTransaction::V3(_) => TransactionVersion::THREE,
            },
        }
    }

    fn is_l1_handler(&self) -> bool {
        false
    }
}

impl AccountTransaction {
    // TODO(nir, 01/11/2023): Consider instantiating CommonAccountFields in AccountTransaction.
    pub fn tx_type(&self) -> TransactionType {
        match self {
            AccountTransaction::Declare(_) => TransactionType::Declare,
            AccountTransaction::DeployAccount(_) => TransactionType::DeployAccount,
            AccountTransaction::Invoke(_) => TransactionType::InvokeFunction,
        }
    }

    fn validate_entry_point_selector(&self) -> EntryPointSelector {
        let validate_entry_point_name = match self {
            Self::Declare(_) => constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            Self::DeployAccount(_) => constants::VALIDATE_DEPLOY_ENTRY_POINT_NAME,
            Self::Invoke(_) => constants::VALIDATE_ENTRY_POINT_NAME,
        };
        selector_from_name(validate_entry_point_name)
    }

    // Calldata for validation contains transaction fields that cannot be obtained by calling
    // `et_tx_info()`.
    fn validate_entrypoint_calldata(&self) -> Calldata {
        match self {
            Self::Declare(tx) => calldata![tx.class_hash().0],
            Self::DeployAccount(tx) => {
                let validate_calldata = concat(vec![
                    vec![tx.class_hash().0, tx.contract_address_salt().0],
                    (*tx.constructor_calldata().0).clone(),
                ]);
                Calldata(validate_calldata.into())
            }
            // Calldata for validation is the same calldata as for the execution itself.
            Self::Invoke(tx) => tx.calldata(),
        }
    }

    pub fn calldata_length(&self) -> usize {
        let calldata = match self {
            Self::Declare(_tx) => calldata![],
            Self::DeployAccount(tx) => tx.constructor_calldata(),
            Self::Invoke(tx) => tx.calldata(),
        };

        calldata.0.len()
    }

    pub fn signature_length(&self) -> usize {
        let signature = match self {
            Self::Declare(tx) => tx.signature(),
            Self::DeployAccount(tx) => tx.signature(),
            Self::Invoke(tx) => tx.signature(),
        };

        signature.0.len()
    }

    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions: Vec<TransactionVersion> = match self {
            // Support `Declare` of version 0 in order to allow bootstrapping of a new system.
            Self::Declare(_) => {
                vec![
                    TransactionVersion::ZERO,
                    TransactionVersion::ONE,
                    TransactionVersion::TWO,
                    TransactionVersion::THREE,
                ]
            }
            Self::DeployAccount(_) => {
                vec![TransactionVersion::ONE, TransactionVersion::THREE]
            }
            Self::Invoke(_) => {
                vec![TransactionVersion::ZERO, TransactionVersion::ONE, TransactionVersion::THREE]
            }
        };
        if allowed_versions.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion { version, allowed_versions })
        }
    }

    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
        charge_fee: bool,
        strict_nonce_check: bool,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, strict_nonce_check)?;

        if charge_fee && tx_info.enforce_fee()? {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context)?;
        }

        Ok(())
    }

    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_l1_gas_amount_vector =
            estimate_minimal_gas_vector(&tx_context.block_context, self)?;
        // TODO(Aner, 30/01/24): modify once data gas limit is enforced.
        let minimal_l1_gas_amount =
            compute_discounted_gas_from_gas_vector(&minimal_l1_gas_amount_vector, tx_context);

        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let ResourceBounds {
                    max_amount: max_l1_gas_amount,
                    max_price_per_unit: max_l1_gas_price,
                } = context.l1_resource_bounds()?;

                let max_l1_gas_amount_as_u128: u128 = max_l1_gas_amount.into();
                if max_l1_gas_amount_as_u128 < minimal_l1_gas_amount {
                    return Err(TransactionFeeError::MaxL1GasAmountTooLow {
                        max_l1_gas_amount,
                        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why
                        // the convertion works.
                        minimal_l1_gas_amount: (minimal_l1_gas_amount
                            .try_into()
                            .expect("Failed to convert u128 to u64.")),
                    })?;
                }

                let actual_l1_gas_price = block_info.gas_prices.get_gas_price_by_fee_type(fee_type);
                if max_l1_gas_price < actual_l1_gas_price.into() {
                    return Err(TransactionFeeError::MaxL1GasPriceTooLow {
                        max_l1_gas_price,
                        actual_l1_gas_price: actual_l1_gas_price.into(),
                    })?;
                }
            }
            TransactionInfo::Deprecated(context) => {
                let max_fee = context.max_fee;
                let min_fee =
                    get_fee_by_gas_vector(block_info, minimal_l1_gas_amount_vector, fee_type);
                if max_fee < min_fee {
                    return Err(TransactionFeeError::MaxFeeTooLow { min_fee, max_fee })?;
                }
            }
        };
        Ok(())
    }

    fn handle_nonce(
        state: &mut dyn State,
        tx_info: &TransactionInfo,
        strict: bool,
    ) -> TransactionPreValidationResult<()> {
        if tx_info.is_v0() {
            return Ok(());
        }

        let address = tx_info.sender_address();
        let account_nonce = state.get_nonce_at(address)?;
        let incoming_tx_nonce = tx_info.nonce();
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
        Err(TransactionPreValidationError::InvalidNonce {
            address,
            account_nonce,
            incoming_tx_nonce,
        })
    }

    fn handle_validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut u64,
        validate: bool,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if validate {
            self.validate_tx(state, resources, tx_context, remaining_gas, limit_steps_by_resources)
        } else {
            Ok(None)
        }
    }

    fn assert_actual_fee_in_bounds(
        tx_context: &Arc<TransactionContext>,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<()> {
        match &tx_context.tx_info {
            TransactionInfo::Current(context) => {
                let ResourceBounds {
                    max_amount: max_l1_gas_amount,
                    max_price_per_unit: max_l1_gas_price,
                } = context.l1_resource_bounds()?;
                if actual_fee > Fee(u128::from(max_l1_gas_amount) * max_l1_gas_price) {
                    panic!(
                        "Actual fee {:#?} exceeded bounds; max amount is {:#?}, max price is 
                         {:#?}.",
                        actual_fee, max_l1_gas_amount, max_l1_gas_price
                    );
                }
            }
            TransactionInfo::Deprecated(DeprecatedTransactionInfo { max_fee, .. }) => {
                if actual_fee > *max_fee {
                    panic!(
                        "Actual fee {:#?} exceeded bounds; max fee is {:#?}.",
                        actual_fee, max_fee
                    );
                }
            }
        }
        Ok(())
    }

    fn handle_fee(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        actual_fee: Fee,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !charge_fee || actual_fee == Fee(0) {
            // Fee charging is not enforced in some transaction simulations and tests.
            return Ok(None);
        }

        // TODO(Amos, 8/04/2024): Add test for this assert.
        Self::assert_actual_fee_in_bounds(&tx_context, actual_fee)?;

        // Charge fee.
        let fee_transfer_call_info = Self::execute_fee_transfer(state, tx_context, actual_fee)?;

        Ok(Some(fee_transfer_call_info))
    }

    fn execute_fee_transfer(
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        // The least significant 128 bits of the amount transferred.
        let lsb_amount = StarkFelt::from(actual_fee.0);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = StarkFelt::from(0_u8);

        let TransactionContext { block_context, tx_info } = tx_context.as_ref();

        // TODO(Gilad): add test that correct fee address is taken, once we add V3 test support.
        let storage_address = block_context.chain_info.fee_token_address(&tx_info.fee_type());
        let fee_transfer_call = CallEntryPoint {
            class_hash: None,
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *block_context.block_info.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address,
            caller_address: tx_info.sender_address(),
            call_type: CallType::Call,
            // The fee-token contract is a Cairo 0 contract, hence the initial gas is irrelevant.
            initial_gas: block_context.versioned_constants.gas_cost("initial_gas_cost"),
        };

        let mut context = EntryPointExecutionContext::new_invoke(tx_context, true)?;

        Ok(fee_transfer_call
            .execute(state, &mut ExecutionResources::default(), &mut context)
            .map_err(TransactionFeeError::ExecuteFeeTransferError)?)
    }

    fn run_execute<S: State>(
        &self,
        state: &mut S,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
        remaining_gas: &mut u64,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        match &self {
            Self::Declare(tx) => tx.run_execute(state, resources, context, remaining_gas),
            Self::DeployAccount(tx) => tx.run_execute(state, resources, context, remaining_gas),
            Self::Invoke(tx) => tx.run_execute(state, resources, context, remaining_gas),
        }
    }

    fn run_non_revertible<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut u64,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let validate_call_info: Option<CallInfo>;
        let execute_call_info: Option<CallInfo>;
        if matches!(self, Self::DeployAccount(_)) {
            // Handle `DeployAccount` transactions separately, due to different order of things.
            // Also, the execution context required form the `DeployAccount` execute phase is
            // validation context.
            let mut execution_context =
                EntryPointExecutionContext::new_validate(tx_context.clone(), charge_fee)?;
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                tx_context.clone(),
                remaining_gas,
                validate,
                charge_fee,
            )?;
        } else {
            let mut execution_context =
                EntryPointExecutionContext::new_invoke(tx_context.clone(), charge_fee)?;
            validate_call_info = self.handle_validate_tx(
                state,
                &mut resources,
                tx_context.clone(),
                remaining_gas,
                validate,
                charge_fee,
            )?;
            execute_call_info =
                self.run_execute(state, &mut resources, &mut execution_context, remaining_gas)?;
        }

        let (actual_cost, bouncer_resources) = self
            .to_actual_cost_builder(tx_context.clone())
            .with_validate_call_info(&validate_call_info)
            .with_execute_call_info(&execute_call_info)
            .try_add_state_changes(state)?
            .build(&resources)?;

        let post_execution_report =
            PostExecutionReport::new(state, &tx_context, &actual_cost, charge_fee)?;
        match post_execution_report.error() {
            Some(error) => Err(error.into()),
            None => Ok(ValidateExecuteCallInfo::new_accepted(
                validate_call_info,
                execute_call_info,
                actual_cost,
                bouncer_resources,
            )),
        }
    }

    fn run_revertible<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut u64,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        let mut resources = ExecutionResources::default();
        let mut execution_context =
            EntryPointExecutionContext::new_invoke(tx_context.clone(), charge_fee)?;
        // Run the validation, and if execution later fails, only keep the validation diff.
        let validate_call_info = self.handle_validate_tx(
            state,
            &mut resources,
            tx_context.clone(),
            remaining_gas,
            validate,
            charge_fee,
        )?;

        let n_allotted_execution_steps = execution_context.subtract_validation_and_overhead_steps(
            &validate_call_info,
            &self.tx_type(),
            self.calldata_length(),
        );

        // Save the state changes resulting from running `validate_tx`, to be used later for
        // resource and fee calculation.
        let actual_cost_builder_with_validation_changes = self
            .to_actual_cost_builder(tx_context.clone())
            .with_validate_call_info(&validate_call_info)
            .try_add_state_changes(state)?;

        // Create copies of state and resources for the execution.
        // Both will be rolled back if the execution is reverted or committed upon success.
        let mut execution_resources = resources.clone();
        let mut execution_state = CachedState::create_transactional(state);

        let execution_result = self.run_execute(
            &mut execution_state,
            &mut execution_resources,
            &mut execution_context,
            remaining_gas,
        );

        // Pre-compute cost in case of revert.
        let execution_steps_consumed =
            n_allotted_execution_steps - execution_context.n_remaining_steps();
        let (revert_cost, bouncer_revert_resources) = actual_cost_builder_with_validation_changes
            .clone()
            .with_reverted_steps(execution_steps_consumed)
            .build(&resources)?;

        match execution_result {
            Ok(execute_call_info) => {
                // When execution succeeded, calculate the actual required fee before committing the
                // transactional state. If max_fee is insufficient, revert the `run_execute` part.
                let (actual_cost, bouncer_resources) = actual_cost_builder_with_validation_changes
                    .with_execute_call_info(&execute_call_info)
                    // Fee is determined by the sum of `validate` and `execute` state changes.
                    // Since `execute_state_changes` are not yet committed, we merge them manually
                    // with `validate_state_changes` to count correctly.
                    .try_add_state_changes(&mut execution_state)?
                    .build(&execution_resources)?;

                // Post-execution checks.
                let post_execution_report = PostExecutionReport::new(
                    &mut execution_state,
                    &tx_context,
                    &actual_cost,
                    charge_fee,
                )?;
                match post_execution_report.error() {
                    Some(post_execution_error) => {
                        // Post-execution check failed. Revert the execution, compute the final fee
                        // to charge and recompute resources used (to be consistent with other
                        // revert case, compute resources by adding consumed execution steps to
                        // validation resources).
                        execution_state.abort();
                        Ok(ValidateExecuteCallInfo::new_reverted(
                            validate_call_info,
                            post_execution_error.to_string(),
                            ActualCost {
                                actual_fee: post_execution_report.recommended_fee(),
                                ..revert_cost
                            },
                            bouncer_revert_resources,
                        ))
                    }
                    None => {
                        // Post-execution check passed, commit the execution.
                        execution_state.commit();
                        Ok(ValidateExecuteCallInfo::new_accepted(
                            validate_call_info,
                            execute_call_info,
                            actual_cost,
                            bouncer_resources,
                        ))
                    }
                }
            }
            Err(_) => {
                // Error during execution. Revert, even if the error is sequencer-related.
                execution_state.abort();
                let post_execution_report =
                    PostExecutionReport::new(state, &tx_context, &revert_cost, charge_fee)?;
                Ok(ValidateExecuteCallInfo::new_reverted(
                    validate_call_info,
                    execution_context.error_trace(),
                    ActualCost {
                        actual_fee: post_execution_report.recommended_fee(),
                        ..revert_cost
                    },
                    bouncer_revert_resources,
                ))
            }
        }
    }

    fn is_non_revertible(&self, tx_info: &TransactionInfo) -> bool {
        // Reverting a Declare or Deploy transaction is not currently supported in the OS.
        match self {
            Self::Declare(_) => true,
            Self::DeployAccount(_) => true,
            Self::Invoke(_) => {
                // V0 transactions do not have validation; we cannot deduct fee for execution. Thus,
                // invoke transactions of are non-revertible iff they are of version 0.
                tx_info.is_v0()
            }
        }
    }

    /// Runs validation and execution.
    fn run_or_revert<S: StateReader>(
        &self,
        state: &mut TransactionalState<'_, S>,
        remaining_gas: &mut u64,
        tx_context: Arc<TransactionContext>,
        validate: bool,
        charge_fee: bool,
    ) -> TransactionExecutionResult<ValidateExecuteCallInfo> {
        if self.is_non_revertible(&tx_context.tx_info) {
            return self.run_non_revertible(state, tx_context, remaining_gas, validate, charge_fee);
        }

        self.run_revertible(state, tx_context, remaining_gas, validate, charge_fee)
    }

    pub fn to_actual_cost_builder(
        &self,
        tx_context: Arc<TransactionContext>,
    ) -> ActualCostBuilder<'_> {
        let mut actual_cost_builder = ActualCostBuilder::new(
            tx_context,
            self.tx_type(),
            self.calldata_length(),
            self.signature_length(),
        );
        if let Self::Declare(tx) = self {
            actual_cost_builder = actual_cost_builder.with_class_info(tx.class_info.clone());
        }
        actual_cost_builder
    }
}

impl<S: StateReader> ExecutableTransaction<S> for AccountTransaction {
    fn execute_raw(
        self,
        state: &mut TransactionalState<'_, S>,
        block_context: &BlockContext,
        charge_fee: bool,
        validate: bool,
    ) -> TransactionExecutionResult<TransactionExecutionInfo> {
        let tx_context = Arc::new(block_context.to_tx_context(&self));
        self.verify_tx_version(tx_context.tx_info.version())?;

        // Nonce and fee check should be done before running user code.
        let strict_nonce_check = true;
        self.perform_pre_validation_stage(state, &tx_context, charge_fee, strict_nonce_check)?;

        // Run validation and execution.
        let mut remaining_gas = block_context.versioned_constants.tx_initial_gas();
        let ValidateExecuteCallInfo {
            validate_call_info,
            execute_call_info,
            revert_error,
            final_cost:
                ActualCost {
                    actual_fee: final_fee,
                    da_gas: final_da_gas,
                    actual_resources: final_resources,
                },
            bouncer_resources,
        } = self.run_or_revert(
            state,
            &mut remaining_gas,
            tx_context.clone(),
            validate,
            charge_fee,
        )?;

        let fee_transfer_call_info = self.handle_fee(state, tx_context, final_fee, charge_fee)?;

        let tx_execution_info = TransactionExecutionInfo {
            validate_call_info,
            execute_call_info,
            fee_transfer_call_info,
            actual_fee: final_fee,
            da_gas: final_da_gas,
            actual_resources: final_resources,
            revert_error,
            bouncer_resources,
        };
        Ok(tx_execution_info)
    }
}

impl TransactionInfoCreator for AccountTransaction {
    fn create_tx_info(&self) -> TransactionInfo {
        match self {
            Self::Declare(tx) => tx.create_tx_info(),
            Self::DeployAccount(tx) => tx.create_tx_info(),
            Self::Invoke(tx) => tx.create_tx_info(),
        }
    }
}

/// Represents a bundle of validate-execute stage execution effects.
struct ValidateExecuteCallInfo {
    validate_call_info: Option<CallInfo>,
    execute_call_info: Option<CallInfo>,
    revert_error: Option<String>,
    final_cost: ActualCost,
    bouncer_resources: ResourcesMapping,
}

impl ValidateExecuteCallInfo {
    pub fn new_accepted(
        validate_call_info: Option<CallInfo>,
        execute_call_info: Option<CallInfo>,
        final_cost: ActualCost,
        bouncer_resources: ResourcesMapping,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info,
            revert_error: None,
            final_cost,
            bouncer_resources,
        }
    }

    pub fn new_reverted(
        validate_call_info: Option<CallInfo>,
        revert_error: String,
        final_cost: ActualCost,
        bouncer_resources: ResourcesMapping,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info: None,
            revert_error: Some(revert_error),
            final_cost,
            bouncer_resources,
        }
    }
}

impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut u64,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        let mut context =
            EntryPointExecutionContext::new_validate(tx_context, limit_steps_by_resources)?;
        let tx_info = &context.tx_context.tx_info;
        if tx_info.is_v0() {
            return Ok(None);
        }

        let storage_address = tx_info.sender_address();
        let validate_call = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.validate_entry_point_selector(),
            calldata: self.validate_entrypoint_calldata(),
            class_hash: None,
            code_address: None,
            storage_address,
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: *remaining_gas,
        };

        let validate_call_info = validate_call
            .execute(state, resources, &mut context)
            .map_err(TransactionExecutionError::ValidateTransactionError)?;

        // Validate return data.
        let class_hash = state.get_class_hash_at(storage_address)?;
        let contract_class = state.get_compiled_contract_class(class_hash)?;
        if let ContractClass::V1(_) = contract_class {
            // The account contract class is a Cairo 1.0 contract; the `validate` entry point should
            // return `VALID`.
            let expected_retdata = retdata![StarkFelt::try_from(constants::VALIDATE_RETDATA)?];
            if validate_call_info.execution.retdata != expected_retdata {
                return Err(TransactionExecutionError::InvalidValidateReturnData {
                    actual: validate_call_info.execution.retdata,
                });
            }
        }

        update_remaining_gas(remaining_gas, &validate_call_info);

        Ok(Some(validate_call_info))
    }
}
