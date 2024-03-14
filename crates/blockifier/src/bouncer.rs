use std::collections::{HashMap, HashSet};
use std::vec::IntoIter;

use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::Deserialize;
use starknet_api::core::ClassHash;

use crate::abi::constants;
use crate::blockifier::bouncer::BouncerInfo;
use crate::blockifier::transaction_executor::{
    get_casm_hash_calculation_resources, get_particia_update_resources, TransactionExecutorResult,
};
use crate::execution::call_info::{CallInfo, MessageL1CostInfo};
use crate::fee::gas_usage::{get_onchain_data_segment_length, get_starknet_gas_usage};
use crate::state::cached_state::{StateChangesKeys, StorageEntry, TransactionalState};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;
use crate::utils::usize_from_u128;

#[cfg(test)]
#[path = "bouncer_test.rs"]
mod test;

macro_rules! impl_checked_sub {
    ($($field:ident),+) => {
        pub fn checked_sub(self: Self, other: Self) -> Option<Self> {
            Some(
                Self {
                    $(
                        $field: self.$field.checked_sub(other.$field)?,
                    )+
                }
            )
        }
    };
}

pub type HashMapWrapper = HashMap<String, usize>;

#[derive(Clone, Copy, Debug)]
pub struct BouncerConfig {
    pub block_max_capacity: BouncerWeights,
    pub block_max_capacity_with_keccak: BouncerWeights,
}

#[derive(
    Clone, Copy, Debug, Default, derive_more::Add, derive_more::Sub, Deserialize, PartialEq,
)]
/// Represents the execution resources counted throughout block creation.
pub struct BouncerWeights {
    builtin_count: BuiltinCount,
    gas: usize,
    message_segment_length: usize,
    n_events: usize,
    n_steps: usize,
    state_diff_size: usize,
}

impl From<HashMapWrapper> for BouncerWeights {
    fn from(mut data: HashMapWrapper) -> Self {
        Self {
            gas: data.remove(constants::L1_GAS_USAGE).unwrap_or_default(),
            n_steps: data.remove(constants::N_STEPS_RESOURCE).unwrap_or_default()
                + data.remove(constants::N_MEMORY_HOLES).unwrap_or_default(),
            message_segment_length: data
                .remove(constants::MESSAGE_SEGMENT_LENGTH)
                .unwrap_or_default(),
            state_diff_size: data.remove(constants::STATE_DIFF_SIZE).unwrap_or_default(),
            n_events: data.remove(constants::N_EVENTS).unwrap_or_default(),
            builtin_count: BuiltinCount::from(data),
        }
    }
}

impl From<ExecutionResources> for BouncerWeights {
    fn from(val: ExecutionResources) -> Self {
        let mut weights = BouncerWeights::from(val.builtin_instance_counter);
        weights.n_steps = val.n_steps + val.n_memory_holes;
        weights
    }
}

impl From<BouncerWeights> for HashMapWrapper {
    fn from(val: BouncerWeights) -> Self {
        let mut map = HashMapWrapper::new();
        map.insert(constants::L1_GAS_USAGE.to_string(), val.gas);
        map.insert(constants::N_STEPS_RESOURCE.to_string(), val.n_steps);
        map.insert(constants::MESSAGE_SEGMENT_LENGTH.to_string(), val.message_segment_length);
        map.insert(constants::STATE_DIFF_SIZE.to_string(), val.state_diff_size);
        map.insert(constants::N_EVENTS.to_string(), val.n_events);
        map.extend::<HashMap<String, usize>>(val.builtin_count.into());
        map
    }
}

impl BouncerWeights {
    impl_checked_sub!(
        builtin_count,
        gas,
        message_segment_length,
        n_events,
        n_steps,
        state_diff_size
    );

    pub fn create_for_testing(with_keccak: bool) -> Self {
        Self {
            gas: 2500000,
            n_steps: 2500000,
            message_segment_length: 3750,
            state_diff_size: 20000,
            n_events: 10000,
            builtin_count: BuiltinCount::create_for_testing(with_keccak),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, derive_more::Add, derive_more::Sub, Deserialize, PartialEq,
)]
pub struct BuiltinCount {
    bitwise: usize,
    ecdsa: usize,
    ec_op: usize,
    keccak: usize,
    pedersen: usize,
    poseidon: usize,
    range_check: usize,
}

impl From<HashMapWrapper> for BuiltinCount {
    fn from(mut data: HashMapWrapper) -> Self {
        let builtin_count = Self {
            bitwise: data.remove(BuiltinName::bitwise.name()).unwrap_or_default(),
            ecdsa: data.remove(BuiltinName::ecdsa.name()).unwrap_or_default(),
            ec_op: data.remove(BuiltinName::ec_op.name()).unwrap_or_default(),
            keccak: data.remove(BuiltinName::keccak.name()).unwrap_or_default(),
            pedersen: data.remove(BuiltinName::pedersen.name()).unwrap_or_default(),
            poseidon: data.remove(BuiltinName::poseidon.name()).unwrap_or_default(),
            range_check: data.remove(BuiltinName::range_check.name()).unwrap_or_default(),
        };
        assert!(
            data.is_empty(),
            "The following keys do not exist in BuiltinCount: {:?} ",
            data.keys()
        );
        builtin_count
    }
}

impl From<BuiltinCount> for HashMapWrapper {
    fn from(val: BuiltinCount) -> Self {
        let mut map = HashMapWrapper::new();
        map.insert(BuiltinName::bitwise.name().to_string(), val.bitwise);
        map.insert(BuiltinName::ecdsa.name().to_string(), val.ecdsa);
        map.insert(BuiltinName::ec_op.name().to_string(), val.ec_op);
        map.insert(BuiltinName::keccak.name().to_string(), val.keccak);
        map.insert(BuiltinName::pedersen.name().to_string(), val.pedersen);
        map.insert(BuiltinName::poseidon.name().to_string(), val.poseidon);
        map.insert(BuiltinName::range_check.name().to_string(), val.range_check);
        map
    }
}

impl BuiltinCount {
    impl_checked_sub!(bitwise, ecdsa, ec_op, keccak, pedersen, poseidon, range_check);

    pub fn create_for_testing(with_keccak: bool) -> Self {
        Self {
            bitwise: 39062,
            ecdsa: 1220,
            ec_op: 2441,
            keccak: {
                if with_keccak { 1220 } else { 0 }
            },
            pedersen: 78125,
            poseidon: 78125,
            range_check: 156250,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BouncerAuxiliaryInfo {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub state_changes_keys: StateChangesKeys,
}

#[derive(Clone, Debug)]
pub struct Bouncer {
    pub auxiliary_info: BouncerAuxiliaryInfo,
    pub block_contains_keccak: bool,
    // The capacity is calculated based of the values of the other Bouncer fields.
    available_capacity: BouncerWeights,
}

impl Bouncer {
    pub fn new(capacity: BouncerWeights, block_contains_keccak: bool) -> Self {
        Bouncer {
            auxiliary_info: BouncerAuxiliaryInfo::default(),
            available_capacity: capacity,
            block_contains_keccak,
        }
    }

    pub fn new_block_bouncer(bouncer_config: BouncerConfig) -> Bouncer {
        Bouncer::new(bouncer_config.block_max_capacity, false)
    }

    pub fn available_capacity(&self) -> BouncerWeights {
        self.available_capacity
    }

    pub fn merge(&mut self, other: Bouncer) {
        println!("yael merge, old capcity {:?}", self.available_capacity);
        self.auxiliary_info
            .executed_class_hashes
            .extend(other.auxiliary_info.executed_class_hashes);
        self.auxiliary_info.state_changes_keys.extend(&other.auxiliary_info.state_changes_keys);
        self.auxiliary_info
            .visited_storage_entries
            .extend(other.auxiliary_info.visited_storage_entries);
        self.block_contains_keccak = other.block_contains_keccak;
        self.available_capacity = other.available_capacity;
    }

    pub fn update<S: StateReader>(
        &mut self,
        bouncer_config: &BouncerConfig,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<Bouncer> {
        // Creating a temporary transactional bouncer that will be merged into the Bouncer if
        // the update succeeds.
        let mut transactional_bouncer =
            Bouncer::new(self.available_capacity, self.block_contains_keccak);

        transactional_bouncer.auxiliary_info =
            self.get_tx_auxiliary_info(state, tx_execution_info)?;

        let tx_weights = self.get_tx_weights(
            state,
            &transactional_bouncer.auxiliary_info,
            tx_execution_info,
            l1_handler_payload_size,
        )?;

        if !transactional_bouncer.block_contains_keccak && tx_weights.builtin_count.keccak > 0 {
            println!(
                "yael update_available_capacity_with_keccak, old capcity {:?}",
                transactional_bouncer.available_capacity
            );
            transactional_bouncer.update_available_capacity_with_keccak(bouncer_config)?;
            println!(
                "yael update_available_capacity_with_keccak , new capcity {:?}",
                transactional_bouncer.available_capacity
            );
        }

        println!("yael update before txtoobig, tx_weights {:?}", tx_weights);
        println!(
            "yael update before txtoobig, transactional_bouncer.available_capacity {:?}",
            transactional_bouncer.available_capacity
        );
        // Check if the transaction is too large to fit any block.
        let mut max_capacity = bouncer_config.block_max_capacity;
        if transactional_bouncer.block_contains_keccak {
            max_capacity = bouncer_config.block_max_capacity_with_keccak;
        }
        println!(
            "yael update before txtoobig, keccak {} max_capacity {:?}",
            transactional_bouncer.block_contains_keccak, max_capacity
        );

        max_capacity.checked_sub(tx_weights).ok_or(TransactionExecutionError::TxTooLarge)?;

        // Check if the transaction can fit the current block available capacity.
        println!(
            "yael update before sub_checked, old capcity {:?}",
            transactional_bouncer.available_capacity
        );
        transactional_bouncer.available_capacity = transactional_bouncer
            .available_capacity
            .checked_sub(tx_weights)
            .ok_or(TransactionExecutionError::BlockFull)?;
        println!(
            "yael update after sub_checked, old capcity {:?}",
            transactional_bouncer.available_capacity
        );

        self.merge(transactional_bouncer.clone());
        println!("yael update after merge, old capcity {:?}", self.available_capacity);

        Ok(transactional_bouncer)
    }

    fn update_available_capacity_with_keccak(
        &mut self,
        bouncer_config: &BouncerConfig,
    ) -> TransactionExecutorResult<()> {
        // First zero the keccak capacity to be able to subtract the max_capacity_with_keccak from
        // max_capacity (that is without keccak).
        let mut max_capacity_with_keccak_tmp = bouncer_config.block_max_capacity_with_keccak;
        max_capacity_with_keccak_tmp.builtin_count.keccak = 0;
        // compute the diff between the max_capacity and the max_capacity_with_keccak.
        let max_capacity_with_keccak_diff = bouncer_config
            .block_max_capacity
            .checked_sub(max_capacity_with_keccak_tmp)
            .expect("max_capacity_with_keccak should be smaller than max_capacity");
        // Subtract the diff from the available capacity.
        self.available_capacity = self
            .available_capacity
            .checked_sub(max_capacity_with_keccak_diff)
            .ok_or(TransactionExecutionError::BlockFull)?;
        // Add back the keccack capacity that was reset at the beggining.
        self.available_capacity.builtin_count.keccak =
            bouncer_config.block_max_capacity_with_keccak.builtin_count.keccak;
        // Mark this block as contains keccak.
        self.block_contains_keccak = true;
        Ok(())
    }

    pub fn get_tx_weights<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_auxiliary_info: &BouncerAuxiliaryInfo,
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut additional_os_resources = get_casm_hash_calculation_resources(
            state,
            &self.auxiliary_info.executed_class_hashes,
            &tx_auxiliary_info.executed_class_hashes,
        )?;
        additional_os_resources += &get_particia_update_resources(
            &self.auxiliary_info.visited_storage_entries,
            &tx_auxiliary_info.visited_storage_entries,
        )?;
        println!("yael get_tx_weights additional_os_resources {:?}", additional_os_resources);
        let tx_execution_info_weights = Self::get_tx_execution_info_resources_weights(
            tx_execution_info,
            l1_handler_payload_size,
        )?;
        println!("yael get_tx_weights tx_execution_info_weights {:?}", tx_execution_info_weights);

        let mut tx_weights =
            BouncerWeights::from(additional_os_resources) + tx_execution_info_weights;
        println!("yael get_tx_weights tx_weights {:?}", tx_weights);
        tx_weights.state_diff_size =
            get_onchain_data_segment_length(&tx_auxiliary_info.state_changes_keys.count());
        Ok(tx_weights)
    }

    pub fn get_tx_execution_info_resources_weights(
        tx_execution_info: &TransactionExecutionInfo,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutorResult<BouncerWeights> {
        let mut execution_info_resources = tx_execution_info.bouncer_resources.0.clone();

        // The blob gas is not being limited by the bouncer, thus we don't use it here.
        // The gas is determined by the state diff size, which is limited by the bouncer.
        execution_info_resources.remove(constants::BLOB_GAS_USAGE);

        // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
        // This value is not used, instead we use the value from calc_message_l1_resources() below.
        execution_info_resources.remove(constants::L1_GAS_USAGE);

        let mut weights = BouncerWeights::from(execution_info_resources);
        (weights.message_segment_length, weights.gas) =
            calc_message_l1_resources(tx_execution_info, l1_handler_payload_size)?;
        // TODO: consider getting n_events from tx_execution_info.summarize() in the following PRs
        weights.n_events = tx_execution_info.get_number_of_events();
        Ok(weights)
    }

    pub fn get_tx_auxiliary_info<S: StateReader>(
        &mut self,
        state: &mut TransactionalState<'_, S>,
        tx_execution_info: &TransactionExecutionInfo,
    ) -> TransactionExecutorResult<BouncerAuxiliaryInfo> {
        let tx_execution_summary = tx_execution_info.summarize();
        let auxiliary_info = BouncerAuxiliaryInfo {
            executed_class_hashes: tx_execution_summary.executed_class_hashes,
            visited_storage_entries: tx_execution_summary.visited_storage_entries,
            state_changes_keys: {
                let tx_state_changes_keys = state.get_actual_state_changes()?.into_keys();
                tx_state_changes_keys.difference(&self.auxiliary_info.state_changes_keys)
            },
        };
        Ok(auxiliary_info)
    }

    // TODO : This is code for testing - remove before PR
    pub fn compare_bouncer_results(
        prev_bouncer: &Bouncer,
        bouncer_info: &BouncerInfo,
        bouncer_config: &BouncerConfig,
        transaction_bouncer: &Bouncer,
        tx_executed_class_hashes: &HashSet<ClassHash>,
        tx_visited_storage_entries: &HashSet<StorageEntry>,
        tx_unique_state_changes_keys: &StateChangesKeys,
    ) {
        println!("yael Bouncer Info {:?}", bouncer_info);
        println!(
            "yael Bouncer parent-transactional {:?}",
            prev_bouncer.available_capacity - transaction_bouncer.available_capacity
        );
        println!(
            "yael tx_executed_class_hashes {:?}, new : {:?}",
            tx_executed_class_hashes, transaction_bouncer.auxiliary_info.executed_class_hashes
        );
        println!(
            "yael tx_visited_storage_entries {:?}, new : {:?}",
            tx_visited_storage_entries, transaction_bouncer.auxiliary_info.visited_storage_entries
        );
        println!(
            "yael tx_unique_state_changes_keys {:?}, new : {:?}",
            tx_unique_state_changes_keys, transaction_bouncer.auxiliary_info.state_changes_keys
        );

        assert_eq!(
            tx_executed_class_hashes, &transaction_bouncer.auxiliary_info.executed_class_hashes,
            "yael error in executed_class_hashes"
        );
        assert_eq!(
            tx_visited_storage_entries, &transaction_bouncer.auxiliary_info.visited_storage_entries,
            "yael error in visited_storage_entries"
        );
        assert_eq!(
            tx_unique_state_changes_keys, &transaction_bouncer.auxiliary_info.state_changes_keys,
            "yael error in state_changes_keys"
        );

        assert_eq!(
            bouncer_info.gas_weight,
            prev_bouncer.available_capacity.gas - transaction_bouncer.available_capacity.gas,
            "yael error in gas_weight"
        );
        assert_eq!(
            bouncer_info.message_segment_length,
            prev_bouncer.available_capacity.message_segment_length
                - transaction_bouncer.available_capacity.message_segment_length,
            "yael error in message_segment_length"
        );
        assert_eq!(
            bouncer_info.state_diff_size,
            prev_bouncer.available_capacity.state_diff_size
                - transaction_bouncer.available_capacity.state_diff_size,
            "yael error in state_diff_size"
        );
        assert_eq!(
            bouncer_info.n_events,
            prev_bouncer.available_capacity.n_events
                - transaction_bouncer.available_capacity.n_events,
            "yael error in n_events"
        );
        assert_eq!(
            bouncer_info.execution_resources.n_steps,
            prev_bouncer.available_capacity.n_steps
                - transaction_bouncer.available_capacity.n_steps,
            "yael error in n_steps"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::bitwise.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.bitwise
                - transaction_bouncer.available_capacity.builtin_count.bitwise,
            "yael error in bitwise"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::ecdsa.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.ecdsa
                - transaction_bouncer.available_capacity.builtin_count.ecdsa,
            "yael error in ecdsa"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::ec_op.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.ec_op
                - transaction_bouncer.available_capacity.builtin_count.ec_op,
            "yael error in ec_op"
        );
        if prev_bouncer.block_contains_keccak && transaction_bouncer.block_contains_keccak {
            assert_eq!(
                *bouncer_info
                    .execution_resources
                    .builtin_instance_counter
                    .get(BuiltinName::keccak.name())
                    .unwrap(),
                prev_bouncer.available_capacity.builtin_count.keccak
                    - transaction_bouncer.available_capacity.builtin_count.keccak,
                "yael error in keccak"
            );
        } else if !prev_bouncer.block_contains_keccak && transaction_bouncer.block_contains_keccak {
            let diff = bouncer_config.block_max_capacity_with_keccak.builtin_count.keccak
                - bouncer_config.block_max_capacity.builtin_count.keccak;
            assert_eq!(
                *bouncer_info
                    .execution_resources
                    .builtin_instance_counter
                    .get(BuiltinName::keccak.name())
                    .unwrap(),
                prev_bouncer.available_capacity.builtin_count.keccak + diff
                    - transaction_bouncer.available_capacity.builtin_count.keccak,
                "yael error in keccak"
            );
        } else {
            assert_eq!(
                *bouncer_info
                    .execution_resources
                    .builtin_instance_counter
                    .get(BuiltinName::keccak.name())
                    .unwrap(),
                0
            );
            assert_eq!(transaction_bouncer.available_capacity.builtin_count.keccak, 0)
        }
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::pedersen.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.pedersen
                - transaction_bouncer.available_capacity.builtin_count.pedersen,
            "yael error in pedersen"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::poseidon.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.poseidon
                - transaction_bouncer.available_capacity.builtin_count.poseidon,
            "yael error in poseidon"
        );
        assert_eq!(
            *bouncer_info
                .execution_resources
                .builtin_instance_counter
                .get(BuiltinName::range_check.name())
                .unwrap(),
            prev_bouncer.available_capacity.builtin_count.range_check
                - transaction_bouncer.available_capacity.builtin_count.range_check,
            "yael error in range_check"
        );
    }
}

pub fn calc_message_l1_resources(
    tx_execution_info: &TransactionExecutionInfo,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutorResult<(usize, usize)> {
    let call_infos: IntoIter<&CallInfo> =
        [&tx_execution_info.validate_call_info, &tx_execution_info.execute_call_info]
            .iter()
            .filter_map(|&call_info| call_info.as_ref())
            .collect::<Vec<&CallInfo>>()
            .into_iter();
    let MessageL1CostInfo { l2_to_l1_payload_lengths, message_segment_length } =
        MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;

    let tx_starknet_gas_usage = get_starknet_gas_usage(
        message_segment_length,
        &l2_to_l1_payload_lengths,
        l1_handler_payload_size,
    );

    let gas_weight = usize_from_u128(tx_starknet_gas_usage.l1_gas)
        .expect("This conversion should not fail as the value is a converted usize.");

    Ok((message_segment_length, gas_weight))
}
