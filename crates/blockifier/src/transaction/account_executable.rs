use starknet_api::transaction::TransactionVersion;

use super::errors::TransactionExecutionError;
use super::objects::TransactionExecutionResult;
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::os_resources::OS_RESOURCES;

pub trait AccountExecutable {
    fn verify_tx_version(&self, version: TransactionVersion) -> TransactionExecutionResult<()> {
        let allowed_versions = Self::get_supported_tx_versions();

        if allowed_versions.contains(&version) {
            Ok(())
        } else {
            Err(TransactionExecutionError::InvalidVersion { version, allowed_versions })
        }
    }

    fn get_supported_tx_versions() -> Vec<TransactionVersion>;

    fn get_minimal_state_changes_count() -> StateChangesCount;

    /// Return an estimated lower bound for the fee on an account transaction.
    pub fn estimate_minimal_fee(
        &self,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<Fee> {
        // TODO(Dori, 1/8/2023): Give names to the constant VM step estimates and regression-test
        // them.
        let os_steps_for_type = OS_RESOURCES.execute_txs_inner(&tx.tx_type()).n_steps;
        let gas_for_type: usize =
            get_onchain_data_segment_length(Self::get_minimal_state_changes_count());
        let resources = ResourcesMapping(HashMap::from([
            (
                constants::GAS_USAGE.to_string(),
                gas_for_type * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
            ),
            (constants::N_STEPS_RESOURCE.to_string(), os_steps_for_type),
        ]));

        calculate_tx_fee(&resources, block_context)
    }
}

impl AccountExecutable for DeclareTransaction {
    fn get_supported_tx_versions() -> Vec<TransactionVersion> {
        vec![
            // Support version 0 in order to allow bootstrapping of a new system.
            TransactionVersion(StarkFelt::from(0_u8)),
            TransactionVersion(StarkFelt::from(1_u8)),
            TransactionVersion(StarkFelt::from(2_u8)),
        ]
    }

    fn get_minimal_state_changes_count() -> StateChangesCount {
        StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }
    }
}
