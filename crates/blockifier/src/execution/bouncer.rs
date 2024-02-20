use std::collections::HashMap;

use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;

use crate::abi::constants;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};

#[derive(Clone, Default)]
pub struct BouncerInfo {
    pub state_diff_size: usize, // The number of felts needed to store the state diff.
    pub gas_weight: usize,
    pub message_segment_length: usize, // The number of felts needed to store L1<>L2 messages.
    pub execution_resources: VmExecutionResources,
    pub n_events: usize,
}

impl BouncerInfo {
    pub fn calculate(
        tx_actual_resources: &ResourcesMapping,
        tx_additional_os_resources: VmExecutionResources,
        message_segment_length: usize,
        state_diff_size: usize,
        n_events: usize,
    ) -> TransactionExecutionResult<Self> {
        let gas_weight = *tx_actual_resources
            .0
            .get("l1_gas_usage")
            .expect("Invalid Transaction Execution Info. Field l1_gas_usage was not found.");

        // TODO(Ayelet, 04/02/2024): Consider defining a constant list.
        let builtin_ordered_list = [
            BuiltinName::output,
            BuiltinName::pedersen,
            BuiltinName::range_check,
            BuiltinName::ecdsa,
            BuiltinName::bitwise,
            BuiltinName::ec_op,
            BuiltinName::keccak,
            BuiltinName::poseidon,
        ];
        let builtin_instance_counter: HashMap<String, usize> = builtin_ordered_list
            .iter()
            .map(|name| {
                (
                    name.name().to_string(),
                    tx_actual_resources.0.get(name.name()).copied().unwrap_or_default(),
                )
            })
            .collect();
        let tx_actual_resources = VmExecutionResources {
            n_steps: tx_actual_resources
                .0
                .get(constants::N_STEPS_RESOURCE)
                .copied()
                .unwrap_or_default(),
            n_memory_holes: tx_actual_resources
                .0
                .get("n_memory_holes")
                .copied()
                .unwrap_or_default(),
            builtin_instance_counter,
        };

        let mut merged_resources = &tx_additional_os_resources + &tx_actual_resources;
        // Memory holes are counted as steps.
        merged_resources.n_steps += merged_resources.n_memory_holes;
        merged_resources.n_memory_holes = 0;

        Ok(Self {
            state_diff_size,
            gas_weight,
            message_segment_length,
            execution_resources: merged_resources,
            n_events,
        })
    }
}
