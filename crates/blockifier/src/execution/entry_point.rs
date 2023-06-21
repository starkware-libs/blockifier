use std::collections::HashSet;

use cairo_felt::Felt252;
use cairo_vm::vm::runners::cairo_runner::{
    ExecutionResources as VmExecutionResources, RunResources,
};
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, EthAddress, EventContent, Fee, L2ToL1Payload, TransactionVersion,
};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::state::state_api::State;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

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
/// Represents a call to an entry point of a StarkNet contract.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
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
    pub initial_gas: Felt252,
}

pub struct ConstructorContext {
    pub class_hash: ClassHash,
    // Only relevant in deploy syscall.
    pub code_address: Option<ContractAddress>,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ExecutionResources {
    pub vm_resources: VmExecutionResources,
    pub syscall_counter: SyscallCounter,
}

#[derive(Debug, Clone)]
pub struct EntryPointExecutionContext {
    pub block_context: BlockContext,
    pub account_tx_context: AccountTransactionContext,
    // VM execution limits.
    pub vm_run_resources: RunResources,
    /// Used for tracking events order during the current execution.
    pub n_emitted_events: usize,
    /// Used for tracking L2-to-L1 messages order during the current execution.
    pub n_sent_messages_to_l1: usize,
    /// Used to track error stack for call chain.
    pub error_stack: Vec<(ContractAddress, String)>,

    recursion_depth: usize,
}
impl EntryPointExecutionContext {
    pub fn new(
        block_context: BlockContext,
        account_tx_context: AccountTransactionContext,
        max_n_steps: u32,
    ) -> Self {
        Self {
            vm_run_resources: RunResources::new(max_n_steps as usize),
            n_emitted_events: 0,
            n_sent_messages_to_l1: 0,
            error_stack: vec![],
            block_context,
            account_tx_context,
            recursion_depth: 0,
        }
    }

    /// Returns the maximum number of cairo steps allowed, given the max fee and gas price.
    /// If fee is disabled, returns the global maximum.
    pub fn max_steps(&self) -> usize {
        if self.account_tx_context.max_fee == Fee(0) {
            constants::MAX_STEPS_PER_TX
        } else {
            let gas_per_step = self
                .block_context
                .vm_resource_fee_cost
                .get(constants::N_STEPS_RESOURCE)
                .unwrap_or_else(|| {
                    panic!("{} must appear in `vm_resource_fee_cost`.", constants::N_STEPS_RESOURCE)
                });
            let max_gas = self.account_tx_context.max_fee.0 / self.block_context.gas_price;
            ((max_gas as f64 / gas_per_step).floor() as usize).min(constants::MAX_STEPS_PER_TX)
        }
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
}

impl CallEntryPoint {
    pub fn execute(
        mut self,
        state: &mut dyn State,
        resources: &mut ExecutionResources,
        context: &mut EntryPointExecutionContext,
    ) -> EntryPointExecutionResult<CallInfo> {
        context.recursion_depth += 1;
        if context.recursion_depth > constants::MAX_ENTRY_POINT_RECURSION_DEPTH {
            return Err(EntryPointExecutionError::RecursionDepthExceeded);
        }

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
        if context.account_tx_context.version == TransactionVersion(StarkFelt::from(0_u8))
            && class_hash
                == ClassHash(
                    StarkFelt::try_from(FAULTY_CLASS_HASH).expect("A class hash must be a felt."),
                )
        {
            return Err(PreExecutionError::FraudAttempt().into());
        }
        // Add class hash to the call, that will appear in the output (call info).
        self.class_hash = Some(class_hash);
        let contract_class = state.get_compiled_contract_class(&class_hash)?;

        let result = execute_entry_point_call(self, contract_class, state, resources, context)
            .map_err(|error| {
                match error {
                    // On VM error, pack the stack trace into the propagated error.
                    EntryPointExecutionError::VirtualMachineExecutionError(error) => {
                        context.error_stack.push((storage_address, error.try_to_vm_trace()));
                        // TODO(Dori, 1/5/2023): Call error_trace only in the top call; as it is
                        // right now,  each intermediate VM error is wrapped
                        // in a VirtualMachineExecutionErrorWithTrace  error
                        // with the stringified trace of all errors below
                        // it.
                        EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace {
                            trace: context.error_trace(),
                            source: error,
                        }
                    }
                    other_error => other_error,
                }
            });

        context.recursion_depth -= 1;
        result
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Retdata(pub Vec<StarkFelt>);

#[macro_export]
macro_rules! retdata {
    ( $( $x:expr ),* ) => {
        Retdata(vec![$($x),*])
    };
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct OrderedEvent {
    pub order: usize,
    pub event: EventContent,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct MessageToL1 {
    pub to_address: EthAddress,
    pub payload: L2ToL1Payload,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct OrderedL2ToL1Message {
    pub order: usize,
    pub message: MessageToL1,
}
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallExecution {
    pub retdata: Retdata,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub failed: bool,
    pub gas_consumed: StarkFelt,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    pub vm_resources: VmExecutionResources,
    pub inner_calls: Vec<CallInfo>,

    // Additional information gathered during execution.
    pub storage_read_values: Vec<StarkFelt>,
    pub accessed_storage_keys: HashSet<StorageKey>,
}

impl CallInfo {
    /// Returns the set of class hashes that were executed during this call execution.
    // TODO: Add unit test for this method
    pub fn get_executed_class_hashes(&self) -> HashSet<ClassHash> {
        let mut class_hashes = HashSet::<ClassHash>::from([self
            .call
            .class_hash
            .expect("Class hash must be set after execution.")]);

        // The first call in the iterator is self (it follows a pre-order traversal),
        // which is added separately as the base case for the recursion.
        let inner_calls = self.into_iter().skip(1);

        for call in inner_calls {
            class_hashes.extend(call.get_executed_class_hashes());
        }

        class_hashes
    }

    /// Returns a list of StarkNet L2ToL1Payload length collected during the execution, sorted
    /// by the order in which they were sent.
    pub fn get_sorted_l2_to_l1_payloads_length(&self) -> TransactionExecutionResult<Vec<usize>> {
        let n_messages = self.into_iter().map(|call| call.execution.l2_to_l1_messages.len()).sum();
        let mut starknet_l2_to_l1_payloads_length: Vec<Option<usize>> = vec![None; n_messages];

        for call in self.into_iter() {
            for ordered_message_content in &call.execution.l2_to_l1_messages {
                let message_order = ordered_message_content.order;
                if message_order >= n_messages {
                    return Err(TransactionExecutionError::InvalidOrder {
                        object: "L2-to-L1 message".to_string(),
                        order: message_order,
                        max_order: n_messages,
                    });
                }
                starknet_l2_to_l1_payloads_length[message_order] =
                    Some(ordered_message_content.message.payload.0.len());
            }
        }

        starknet_l2_to_l1_payloads_length.into_iter().enumerate().try_fold(
            Vec::new(),
            |mut acc, (i, option)| match option {
                Some(value) => {
                    acc.push(value);
                    Ok(acc)
                }
                None => Err(TransactionExecutionError::UnexpectedHoles {
                    object: "L2-to-L1 message".to_string(),
                    order: i,
                }),
            },
        )
    }
}

pub struct CallInfoIter<'a> {
    call_infos: Vec<&'a CallInfo>,
}

impl<'a> Iterator for CallInfoIter<'a> {
    type Item = &'a CallInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(call_info) = self.call_infos.pop() else {
            return None;
        };

        // Push order is right to left.
        self.call_infos.extend(call_info.inner_calls.iter().rev());
        Some(call_info)
    }
}

impl<'a> IntoIterator for &'a CallInfo {
    type Item = &'a CallInfo;
    type IntoIter = CallInfoIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        CallInfoIter { call_infos: vec![self] }
    }
}

pub fn execute_constructor_entry_point(
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    ctor_context: ConstructorContext,
    calldata: Calldata,
    remaining_gas: Felt252,
) -> EntryPointExecutionResult<CallInfo> {
    // Ensure the class is declared (by reading it).
    let contract_class = state.get_compiled_contract_class(&ctor_context.class_hash)?;
    let Some(constructor_selector) = contract_class.constructor_selector() else {
        // Contract has no constructor.
        return handle_empty_constructor(ctor_context, calldata,remaining_gas);
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
    remaining_gas: Felt252,
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
