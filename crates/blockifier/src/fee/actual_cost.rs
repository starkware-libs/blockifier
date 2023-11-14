use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;
use thiserror::Error;

use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::fee_utils::{
    calculate_tx_l1_gas_usage, get_balance_and_if_covers_fee, get_fee_by_l1_gas_usage,
};
use crate::state::cached_state::{CachedState, StateChanges, StateChangesCount};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, HasRelatedFeeType, ResourcesMapping,
    TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{calculate_l1_gas_usage, calculate_tx_resources};

#[derive(Clone, Copy, Debug, Error)]
pub enum FeeCheckError {
    #[error("Insufficient max L1 gas: max amount: {max_amount}, actual used: {actual_amount}.")]
    MaxL1GasAmountExceeded { max_amount: u128, actual_amount: u128 },
    #[error("Insufficient max fee: max fee: {max_fee:?}, actual fee: {actual_fee:?}")]
    MaxFeeExceeded { max_fee: Fee, actual_fee: Fee },
    #[error(
        "Insufficient fee token balance. Fee: {fee:?}, balance: low/high \
         {balance_low:?}/{balance_high:?}."
    )]
    InsufficientFeeTokenBalance { fee: Fee, balance_low: StarkFelt, balance_high: StarkFelt },
}

// TODO(Gilad): Use everywhere instead of passing the `actual_{fee,resources}` tuple, which often
// get passed around together.
pub struct ActualCost {
    pub actual_fee: Fee,
    pub actual_resources: ResourcesMapping,
}

impl ActualCost {
    pub fn builder_for_l1_handler(
        block_context: &BlockContext,
        tx_context: AccountTransactionContext,
        l1_handler_payload_size: usize,
    ) -> ActualCostBuilder<'_> {
        ActualCostBuilder::new(block_context, tx_context, TransactionType::L1Handler)
            .without_sender_address()
            .with_l1_payload_size(l1_handler_payload_size)
    }
}

#[derive(Debug, Clone)]
// Invariant: private fields initialized after `new` is called via dedicated methods.
pub struct ActualCostBuilder<'a> {
    pub account_tx_context: AccountTransactionContext,
    pub tx_type: TransactionType,
    pub block_context: BlockContext,
    validate_call_info: Option<&'a CallInfo>,
    execute_call_info: Option<&'a CallInfo>,
    state_changes: StateChanges,
    sender_address: Option<ContractAddress>,
    l1_payload_size: Option<usize>,
    n_reverted_steps: usize,
}

impl<'a> ActualCostBuilder<'a> {
    // Recommendation: use constructor from account transaction, or from actual cost, to build this.
    pub fn new(
        block_context: &BlockContext,
        account_tx_context: AccountTransactionContext,
        tx_type: TransactionType,
    ) -> Self {
        Self {
            block_context: block_context.clone(),
            sender_address: Some(account_tx_context.sender_address()),
            account_tx_context,
            tx_type,
            validate_call_info: None,
            execute_call_info: None,
            state_changes: StateChanges::default(),
            l1_payload_size: None,
            n_reverted_steps: 0,
        }
    }

    pub fn without_sender_address(mut self) -> Self {
        self.sender_address = None;
        self
    }

    // Call the `build` method to construct the actual cost object, after feeding the builder
    // using the setters below.
    pub fn build(
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<ActualCost> {
        self.calculate_actual_fee_and_resources(execution_resources, self.n_reverted_steps)
    }

    // Setters.

    pub fn with_validate_call_info(mut self, validate_call_info: &'a Option<CallInfo>) -> Self {
        self.validate_call_info = validate_call_info.as_ref();
        self
    }

    pub fn with_execute_call_info(mut self, execute_call_info: &'a Option<CallInfo>) -> Self {
        self.execute_call_info = execute_call_info.as_ref();
        self
    }

    pub fn try_add_state_changes(
        mut self,
        state: &mut CachedState<impl StateReader>,
    ) -> StateResult<Self> {
        let fee_token_address =
            self.block_context.fee_token_address(&self.account_tx_context.fee_type());

        let new_state_changes = state
            .get_actual_state_changes_for_fee_charge(fee_token_address, self.sender_address)?;
        self.state_changes = StateChanges::merge(vec![self.state_changes, new_state_changes]);
        Ok(self)
    }

    pub fn with_l1_payload_size(mut self, l1_payload_size: usize) -> Self {
        self.l1_payload_size = Some(l1_payload_size);
        self
    }

    pub fn with_reverted_steps(mut self, n_reverted_steps: usize) -> Self {
        self.n_reverted_steps = n_reverted_steps;
        self
    }

    // Private methods.

    // Construct the actual cost object using all fields that were set in the builder.
    fn calculate_actual_fee_and_resources(
        &self,
        execution_resources: &ExecutionResources,
        n_reverted_steps: usize,
    ) -> TransactionExecutionResult<ActualCost> {
        let state_changes_count = StateChangesCount::from(&self.state_changes);
        let non_optional_call_infos = vec![self.validate_call_info, self.execute_call_info]
            .into_iter()
            .flatten()
            .collect::<Vec<&CallInfo>>();
        let l1_gas_usage = calculate_l1_gas_usage(
            &non_optional_call_infos,
            state_changes_count,
            self.l1_payload_size,
        )?;
        let mut actual_resources =
            calculate_tx_resources(execution_resources, l1_gas_usage, self.tx_type)?;

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            n_reverted_steps;

        let actual_fee = if self.account_tx_context.enforce_fee()? {
            self.account_tx_context.calculate_tx_fee(&actual_resources, &self.block_context)?
        } else {
            Fee(0)
        };

        Ok(ActualCost { actual_fee, actual_resources })
    }
}

/// This struct holds the result of fee checks: recommended fee to charge (useful in post-execution
/// revert flow) and an error if the check failed.
struct FeeCheckReport {
    recommended_fee: Fee,
    error: Option<FeeCheckError>,
}

pub trait FeeCheckReportFields {
    fn recommended_fee(&self) -> Fee;
    fn error(&self) -> Option<FeeCheckError>;
}

impl FeeCheckReportFields for FeeCheckReport {
    fn recommended_fee(&self) -> Fee {
        self.recommended_fee
    }

    fn error(&self) -> Option<FeeCheckError> {
        self.error
    }
}

impl FeeCheckReport {
    pub fn success_report(actual_fee: Fee) -> Self {
        Self { recommended_fee: actual_fee, error: None }
    }

    /// Given a fee error and the current context, constructs and returns a report.
    pub fn from_fee_check_error(
        actual_fee: Fee,
        error: FeeCheckError,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Self> {
        let recommended_fee = match error {
            FeeCheckError::InsufficientFeeTokenBalance { .. } => actual_fee,
            FeeCheckError::MaxFeeExceeded { .. } | FeeCheckError::MaxL1GasAmountExceeded { .. } => {
                match account_tx_context {
                    AccountTransactionContext::Current(context) => get_fee_by_l1_gas_usage(
                        block_context,
                        context.l1_resource_bounds()?.max_amount as u128,
                        &FeeType::Strk,
                    ),
                    AccountTransactionContext::Deprecated(context) => context.max_fee,
                }
            }
        };
        Ok(Self { recommended_fee, error: Some(error) })
    }

    /// If the actual cost exceeds the resource bounds on the transaction, returns a fee check
    /// error.
    fn check_actual_cost_within_bounds(
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        let ActualCost { actual_fee, actual_resources } = actual_cost;

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        match account_tx_context {
            AccountTransactionContext::Current(context) => {
                // Check L1 gas limit.
                let max_l1_gas = context.l1_resource_bounds()?.max_amount as u128;
                let actual_used_l1_gas =
                    calculate_tx_l1_gas_usage(actual_resources, block_context)?;
                if actual_used_l1_gas > max_l1_gas {
                    return Err(FeeCheckError::MaxL1GasAmountExceeded {
                        max_amount: max_l1_gas,
                        actual_amount: actual_used_l1_gas,
                    })?;
                }
            }
            AccountTransactionContext::Deprecated(context) => {
                // Check max fee.
                let max_fee = context.max_fee;
                if actual_fee > &max_fee {
                    return Err(FeeCheckError::MaxFeeExceeded {
                        max_fee,
                        actual_fee: *actual_fee,
                    })?;
                }
            }
        }

        Ok(())
    }

    /// If the actual cost exceeds the sender's balance, returns a fee check error.
    fn check_can_pay_fee<S: StateReader>(
        state: &mut S,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        let ActualCost { actual_fee, .. } = actual_cost;
        let (balance_low, balance_high, can_pay) =
            get_balance_and_if_covers_fee(state, account_tx_context, block_context, *actual_fee)?;
        if can_pay {
            return Ok(());
        }
        Err(FeeCheckError::InsufficientFeeTokenBalance {
            fee: *actual_fee,
            balance_low,
            balance_high,
        })?
    }
}

pub struct PostExecutionReport(FeeCheckReport);

impl FeeCheckReportFields for PostExecutionReport {
    fn recommended_fee(&self) -> Fee {
        self.0.recommended_fee()
    }

    fn error(&self) -> Option<FeeCheckError> {
        self.0.error()
    }
}

impl PostExecutionReport {
    /// Verifies the actual cost can be paid by the account. If not, reports an error and the fee
    /// that should be charged in revert flow.
    pub fn new<S: StateReader>(
        state: &mut S,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Self> {
        let ActualCost { actual_fee, .. } = actual_cost;

        // If fee is not enforced, no need to check post-execution.
        if !charge_fee || !account_tx_context.enforce_fee()? {
            return Ok(Self(FeeCheckReport::success_report(*actual_fee)));
        }

        for fee_check_result in [
            // First, compare the actual resources used against the upper bound(s) defined by the
            // sender.
            FeeCheckReport::check_actual_cost_within_bounds(
                block_context,
                account_tx_context,
                actual_cost,
            ),
            // Next, compare resource bounds cover the actual cost, and are covered by
            // pre-execution balance (verified in pre-validation phase).
            // Verify against the account balance, which may have changed after execution.
            FeeCheckReport::check_can_pay_fee(
                state,
                block_context,
                account_tx_context,
                actual_cost,
            ),
        ] {
            match fee_check_result {
                Ok(_) => continue,
                Err(TransactionExecutionError::FeeCheckError(fee_check_error)) => {
                    // Found an error; set the recommended fee based on the error variant and
                    // current context, and return the report.
                    return Ok(Self(FeeCheckReport::from_fee_check_error(
                        *actual_fee,
                        fee_check_error,
                        block_context,
                        account_tx_context,
                    )?));
                }
                Err(other_error) => return Err(other_error),
            }
        }

        Ok(Self(FeeCheckReport::success_report(actual_cost.actual_fee)))
    }
}
