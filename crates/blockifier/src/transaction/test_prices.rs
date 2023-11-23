use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner as vm_constants;

use crate::abi::constants;
use crate::fee::eth_gas_constants;
use crate::transaction::objects::ResourcesMapping;

#[path = "test_prices_test.rs"]
mod test_prices_test;

pub const VALIDATE_OVERHEAD_N_STEPS: usize = 21;

/// Cost of "return_result" function.
pub fn return_result_cost(with_validate: bool) -> ResourcesMapping {
    ResourcesMapping(HashMap::from([
        (constants::GAS_USAGE.to_string(), 4 * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD),
        (
            constants::N_STEPS_RESOURCE.to_string(),
            4248 + if with_validate { VALIDATE_OVERHEAD_N_STEPS } else { 0 },
        ),
        (vm_constants::RANGE_CHECK_BUILTIN_NAME.to_string(), 100 + usize::from(with_validate)),
        (vm_constants::HASH_BUILTIN_NAME.to_string(), 16),
    ]))
}
