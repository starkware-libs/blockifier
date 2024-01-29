use std::cell::RefCell;
use std::cmp::min;
use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::{
    ExecutionResources as VmExecutionResources, ResourceTracker, RunResources,
};
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, TransactionVersion};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::context::TransactionContext;
use crate::execution::call_info::CallInfo;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::fee::os_resources::OS_RESOURCES;
use crate::state::state_api::State;
use crate::transaction::objects::{HasRelatedFeeType, TransactionExecutionResult, TransactionInfo};
use crate::transaction::transaction_types::TransactionType;
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "entry_point_test.rs"]
pub mod test;

pub const FAULTY_CLASS_HASH: &str =
    "0x1A7820094FEAF82D53F53F214B81292D717E7BB9A92BB2488092CD306F3993F";

pub type EntryPointExecutionResult<T> = Result<T, EntryPointExecutionError>;

/// Represents a the type of the call (used for debugging).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CallType {
    #[default]
    Call = 0,
    Delegate = 1,
}
/// Represents a call to an entry point of a Starknet contract.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CallEntryPoint {
    // The class hash is not given if it can be deduced from the storage address.
    pub class_hash: Option<ClassHash>,
    // Optional, since there is no address to the code implementation in a library call.
    // and for outermost calls (triggered by the transaction itself).
    // TODO: BACKWARD-COMPATIBILITY.
    pub code_address: Option<ContractAddress>,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: Calldata,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
    pub call_type: CallType,
    // We can assume that the initial gas is less than 2^64.
    pub initial_gas: u64,
}

impl CallEntryPoint {
    pub fn execute(
        mut self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
    ) -> EntryPointExecutionResult<CallInfo> {
        let tx_context = &context.tx_context;
        let mut decrement_when_dropped = RecursionDepthGuard::new(
            context.current_recursion_depth.clone(),
            tx_context.block_context.versioned_constants.max_recursion_depth,
        );
        decrement_when_dropped.try_increment_and_check_depth()?;

        // Validate contract is deployed.
        let storage_address = self.storage_address;
        let storage_class_hash = state.get_class_hash_at(self.storage_address)?;
        if storage_class_hash == ClassHash::default() {
            return Err(PreExecutionError::UninitializedStorageAddress(self.storage_address).into());
        }

        let class_hash = match self.class_hash {
            Some(class_hash) => class_hash,
            None => storage_class_hash, // If not given, take the storage contract class hash.
        };
        // Hack to prevent version 0 attack on argent accounts.
        if tx_context.tx_info.version() == TransactionVersion::ZERO
            && class_hash
                == ClassHash(
                    StarkFelt::try_from(FAULTY_CLASS_HASH).expect("A class hash must be a felt."),
                )
        {
            return Err(PreExecutionError::FraudAttempt.into());
        }
        // Add class hash to the call, that will appear in the output (call info).
        self.class_hash = Some(class_hash);
        let contract_class = state.get_compiled_contract_class(class_hash)?;

        execute_entry_point_call(self, contract_class, state, resources, context).map_err(|error| {
            match error {
                // On VM error, pack the stack trace into the propagated error.
                EntryPointExecutionError::VirtualMachineExecutionError(error) => {
                    context.error_stack.push((storage_address, error.try_to_vm_trace()));
                    // TODO(Dori, 1/5/2023): Call error_trace only in the top call; as it is
                    //   right now, each intermediate VM error is wrapped in a
                    //   VirtualMachineExecutionErrorWithTrace error with the stringified trace
                    //   of all errors below it.
                    //   When that's done, remove the 10000 character limitation.
                    let error_trace = context.error_trace();
                    EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace {
                        trace: error_trace[..min(10000, error_trace.len())].to_string(),
                        source: error,
                    }
                }
                other_error => {
                    context.error_stack.push((storage_address, format!("{}\n", &other_error)));
                    other_error
                }
            }
        })
    }
}

pub struct ConstructorContext {
    pub class_hash: ClassHash,
    // Only relevant in deploy syscall.
    pub code_address: Option<ContractAddress>,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionResources {
    pub vm_resources: VmExecutionResources,
    pub syscall_counter: SyscallCounter,
}

#[derive(Debug)]
pub struct EntryPointExecutionContext {
    // We use `Arc` to avoid the clone of this potentially large object, as inner calls
    // are created during execution.
    pub tx_context: Arc<TransactionContext>,
    // VM execution limits.
    pub vm_run_resources: RunResources,
    /// Used for tracking events order during the current execution.
    pub n_emitted_events: usize,
    /// Used for tracking L2-to-L1 messages order during the current execution.
    pub n_sent_messages_to_l1: usize,
    /// Used to track error stack for call chain.
    pub error_stack: Vec<(ContractAddress, String)>,

    // Managed by dedicated guard object.
    current_recursion_depth: Arc<RefCell<usize>>,

    // The execution mode affects the behavior of the hint processor.
    pub execution_mode: ExecutionMode,
}

impl EntryPointExecutionContext {
    pub fn new(
        tx_context: Arc<TransactionContext>,
        mode: ExecutionMode,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Self> {
        let max_steps = Self::max_steps(&tx_context, &mode, limit_steps_by_resources)?;
        Ok(Self {
            vm_run_resources: RunResources::new(max_steps),
            n_emitted_events: 0,
            n_sent_messages_to_l1: 0,
            error_stack: vec![],
            tx_context: tx_context.clone(),
            current_recursion_depth: Default::default(),
            execution_mode: mode,
        })
    }

    pub fn new_validate(
        tx_context: Arc<TransactionContext>,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Self> {
        Self::new(tx_context, ExecutionMode::Validate, limit_steps_by_resources)
    }

    pub fn new_invoke(
        tx_context: Arc<TransactionContext>,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<Self> {
        Self::new(tx_context, ExecutionMode::Execute, limit_steps_by_resources)
    }

    /// Returns the maximum number of cairo steps allowed, given the max fee, gas price and the
    /// execution mode.
    /// If fee is disabled, returns the global maximum.
    fn max_steps(
        tx_context: &TransactionContext,
        mode: &ExecutionMode,
        limit_steps_by_resources: bool,
    ) -> TransactionExecutionResult<usize> {
        let block_info = &tx_context.block_context.block_info;
        let constants = &tx_context.block_context.versioned_constants;
        let default_versioned_constants = VersionedConstants::latest_constants();
        let block_upper_bound = match mode {
            ExecutionMode::Validate => min(
                constants.validate_max_n_steps,
                default_versioned_constants.validate_max_n_steps,
            ),
            ExecutionMode::Execute => min(
                constants.invoke_tx_max_n_steps,
                default_versioned_constants.invoke_tx_max_n_steps,
            ),
        };
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        let block_upper_bound =
            usize::try_from(block_upper_bound).expect("Failed to convert u32 to usize.");

        let tx_info = &tx_context.tx_info;
        if !limit_steps_by_resources || !tx_info.enforce_fee()? {
            return Ok(block_upper_bound);
        }

        let gas_per_step =
            constants.vm_resource_fee_cost().get(constants::N_STEPS_RESOURCE).unwrap_or_else(
                || panic!("{} must appear in `vm_resource_fee_cost`.", constants::N_STEPS_RESOURCE),
            );

        // New transactions derive the step limit by the L1 gas resource bounds; deprecated
        // transactions derive this value from the `max_fee`.
        let tx_gas_upper_bound = match tx_info {
            TransactionInfo::Deprecated(context) => {
                let max_cairo_steps = context.max_fee.0
                    / block_info.gas_prices.get_gas_price_by_fee_type(&tx_info.fee_type());
                // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                // conversion works.
                usize::try_from(max_cairo_steps).expect("Failed to convert u128 to usize")
            }
            TransactionInfo::Current(context) => {
                // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                // convertion works.
                context
                    .l1_resource_bounds()?
                    .max_amount
                    .try_into()
                    .expect("Failed to convert u64 to usize.")
            }
        };

        let tx_upper_bound = (tx_gas_upper_bound as f64 / gas_per_step).floor() as usize;
        Ok(min(tx_upper_bound, block_upper_bound))
    }

    /// Returns the available steps in run resources.
    pub fn n_remaining_steps(&self) -> usize {
        self.vm_run_resources.get_n_steps().expect("The number of steps must be initialized.")
    }

    /// Subtracts the given number of steps from the currently available run resources.
    /// Used for limiting the number of steps available during the execution stage, to leave enough
    /// steps available for the fee transfer stage.
    /// Returns the remaining number of steps.
    pub fn subtract_steps(&mut self, steps_to_subtract: usize) -> usize {
        // If remaining steps is less than the number of steps to subtract, attempting to subtrace
        // would cause underflow error.
        // Logically, we update remaining steps to `max(0, remaining_steps - steps_to_subtract)`.
        let remaining_steps = self.n_remaining_steps();
        let new_remaining_steps = if remaining_steps < steps_to_subtract {
            0
        } else {
            remaining_steps - steps_to_subtract
        };
        self.vm_run_resources = RunResources::new(new_remaining_steps);
        self.n_remaining_steps()
    }

    /// From the total amount of steps available for execution, deduct the steps consumed during
    /// validation and the overhead steps required for fee transfer.
    /// Returns the remaining steps (after the subtraction).
    pub fn subtract_validation_and_overhead_steps(
        &mut self,
        validate_call_info: &Option<CallInfo>,
        tx_type: &TransactionType,
        _calldata_length: usize,
    ) -> usize {
        let validate_steps = validate_call_info
            .as_ref()
            .map(|call_info| call_info.vm_resources.n_steps)
            .unwrap_or_default();

        let overhead_steps = OS_RESOURCES.resources_for_tx_type(tx_type).n_steps;
        self.subtract_steps(validate_steps + overhead_steps)
    }

    /// Combines individual errors into a single stack trace string, with contract addresses printed
    /// alongside their respective trace.
    pub fn error_trace(&self) -> String {
        self.error_stack
            .iter()
            .rev()
            .map(|(contract_address, trace_string)| {
                format!(
                    "Error in the called contract ({}):\n{}",
                    contract_address.0.key(),
                    trace_string
                )
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    pub fn get_gas_cost(&self, name: &str) -> u64 {
        self.tx_context.block_context.versioned_constants.gas_cost(name)
    }
}

pub fn execute_constructor_entry_point(
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    ctor_context: ConstructorContext,
    calldata: Calldata,
    remaining_gas: u64,
) -> EntryPointExecutionResult<CallInfo> {
    // Ensure the class is declared (by reading it).
    let contract_class = state.get_compiled_contract_class(ctor_context.class_hash)?;
    let Some(constructor_selector) = contract_class.constructor_selector() else {
        // Contract has no constructor.
        return handle_empty_constructor(ctor_context, calldata, remaining_gas);
    };

    let constructor_call = CallEntryPoint {
        class_hash: None,
        code_address: ctor_context.code_address,
        entry_point_type: EntryPointType::Constructor,
        entry_point_selector: constructor_selector,
        calldata,
        storage_address: ctor_context.storage_address,
        caller_address: ctor_context.caller_address,
        call_type: CallType::Call,
        initial_gas: remaining_gas,
    };

    constructor_call.execute(state, resources, context)
}

pub fn handle_empty_constructor(
    ctor_context: ConstructorContext,
    calldata: Calldata,
    remaining_gas: u64,
) -> EntryPointExecutionResult<CallInfo> {
    // Validate no calldata.
    if !calldata.0.is_empty() {
        return Err(EntryPointExecutionError::InvalidExecutionInput {
            input_descriptor: "constructor_calldata".to_string(),
            info: "Cannot pass calldata to a contract with no constructor.".to_string(),
        });
    }

    let empty_constructor_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(ctor_context.class_hash),
            code_address: ctor_context.code_address,
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: selector_from_name(constants::CONSTRUCTOR_ENTRY_POINT_NAME),
            calldata: Calldata::default(),
            storage_address: ctor_context.storage_address,
            caller_address: ctor_context.caller_address,
            call_type: CallType::Call,
            initial_gas: remaining_gas,
        },
        ..Default::default()
    };

    Ok(empty_constructor_call_info)
}

// Ensure that the recursion depth does not exceed the maximum allowed depth.
struct RecursionDepthGuard {
    current_depth: Arc<RefCell<usize>>,
    max_depth: usize,
}

impl RecursionDepthGuard {
    fn new(current_depth: Arc<RefCell<usize>>, max_depth: usize) -> Self {
        Self { current_depth, max_depth }
    }

    // Tries to increment the current recursion depth and returns an error if the maximum depth
    // would be exceeded.
    fn try_increment_and_check_depth(&mut self) -> EntryPointExecutionResult<()> {
        *self.current_depth.borrow_mut() += 1;
        if *self.current_depth.borrow() > self.max_depth {
            return Err(EntryPointExecutionError::RecursionDepthExceeded);
        }
        Ok(())
    }
}

// Implementing the Drop trait to decrement the recursion depth when the guard goes out of scope.
impl Drop for RecursionDepthGuard {
    fn drop(&mut self) {
        *self.current_depth.borrow_mut() -= 1;
    }
}
