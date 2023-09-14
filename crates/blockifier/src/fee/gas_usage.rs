use std::collections::HashMap;

use starknet_api::transaction::Fee;

use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::fee::errors::GasPriceQueryError;
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::os_resources::OS_RESOURCES;
use crate::state::cached_state::StateChangesCount;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};

#[cfg(test)]
#[path = "gas_usage_test.rs"]
pub mod test;

/// Struct representing the current state of a STRK<->ETH AMM pool.
#[derive(Clone, Debug)]
pub struct PoolState {
    pub total_wei: u128,
    pub total_strk: u128,
}

impl PoolState {
    pub fn tvl_in_wei(&self) -> u128 {
        // Assumption on pool is the two pools have the same total value.
        self.total_wei * 2
    }
    pub fn get_wei_to_stark_ratio(&self) -> f64 {
        self.total_wei as f64 / self.total_strk as f64
    }
}

/// Returns the weighted median Wei / STRK ratio, given the states of a collection of  pools.
/// Pools are weighted by TVL in units of Wei. for more info on weighted median see:
/// https://en.wikipedia.org/wiki/Weighted_median
pub fn get_wei_to_strk_ratio_from_pool_states(
    pool_states: &[PoolState],
) -> Result<f64, GasPriceQueryError> {
    if pool_states.is_empty() {
        return Err(GasPriceQueryError::NoPoolStatesError);
    }

    let half_total_weight: f64 =
        pool_states.iter().map(|state| (state.tvl_in_wei())).sum::<u128>() as f64 / 2.0;
    // Create vector of pool states sorted by Wei / STRK ratio.
    let mut pool_states_sorted_by_weight: Vec<&PoolState> = pool_states.iter().collect();
    pool_states_sorted_by_weight.sort_unstable_by(|state_a, state_b| {
        state_a.get_wei_to_stark_ratio().partial_cmp(&state_b.get_wei_to_stark_ratio()).unwrap()
    });

    // Find idx of median Wei / STRK ratio.
    let mut current_weight: f64 = 0.0;
    let mut median_idx = 0;
    let mut equal_weight_partition: bool = false;
    loop {
        current_weight += pool_states_sorted_by_weight[median_idx].tvl_in_wei() as f64;
        if (current_weight - half_total_weight).abs() < f64::EPSILON {
            equal_weight_partition = true;
            break;
        }
        if current_weight > half_total_weight {
            break;
        }
        median_idx += 1;
    }

    let res: f64 = if equal_weight_partition {
        (pool_states_sorted_by_weight[median_idx].get_wei_to_stark_ratio()
            + pool_states_sorted_by_weight[median_idx + 1].get_wei_to_stark_ratio())
            / 2.0
    } else {
        pool_states_sorted_by_weight[median_idx].get_wei_to_stark_ratio()
    };
    Ok(res)
}

/// Returns an estimation of the L1 gas amount that will be used (by StarkNet's update state and
/// the verifier) following the addition of a transaction with the given parameters to a batch;
/// e.g., a message from L2 to L1 is followed by a storage write operation in StarkNet L1 contract
/// which requires gas.
pub fn calculate_tx_gas_usage(
    l2_to_l1_payloads_length: &[usize],
    state_changes_count: StateChangesCount,
    l1_handler_payload_size: Option<usize>,
) -> usize {
    // Calculate the addition of the transaction to the output messages segment.
    let residual_message_segment_length =
        get_message_segment_length(l2_to_l1_payloads_length, l1_handler_payload_size);

    // Calculate the effect of the transaction on the output data availability segment.
    let residual_onchain_data_segment_length = get_onchain_data_segment_length(state_changes_count);

    let n_l2_to_l1_messages = l2_to_l1_payloads_length.len();
    let n_l1_to_l2_messages = usize::from(l1_handler_payload_size.is_some());

    let starknet_gas_usage =
    // StarkNet's updateState gets the message segment as an argument.
    residual_message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
    // StarkNet's updateState increases a (storage) counter for each L2-to-L1 message.
    + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
    // StarkNet's updateState decreases a (storage) counter for each L1-to-L2 consumed message.
    // (Note that we will probably get a refund of 15,000 gas for each consumed message but we
    // ignore it since refunded gas cannot be used for the current transaction execution).
    + n_l1_to_l2_messages * eth_gas_constants::GAS_PER_COUNTER_DECREASE
    + get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size)
    + get_log_message_to_l1_emissions_cost(l2_to_l1_payloads_length);

    let sharp_gas_usage = residual_message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + residual_onchain_data_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;

    starknet_gas_usage + sharp_gas_usage
}

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
/// This segment consists of deployment info (of contracts deployed by the transaction) and
/// storage updates.
pub fn get_onchain_data_segment_length(state_changes_count: StateChangesCount) -> usize {
    // For each newly modified contract:
    // contract address (1 word).
    // + 1 word with the following info: A flag indicating whether the class hash was updated, the
    // number of entry updates, and the new nonce.
    let mut onchain_data_segment_length = state_changes_count.n_modified_contracts * 2;
    // For each class updated (through a deploy or a class replacement).
    onchain_data_segment_length +=
        state_changes_count.n_class_hash_updates * constants::CLASS_UPDATE_SIZE;
    // For each modified storage cell: key, new value.
    onchain_data_segment_length += state_changes_count.n_storage_updates * 2;
    // For each compiled class updated (through declare): class_hash, compiled_class_hash
    onchain_data_segment_length += state_changes_count.n_compiled_class_hash_updates * 2;

    onchain_data_segment_length
}

/// Returns the number of felts added to the output messages segment as a result of adding
/// a transaction with the given parameters to a batch. Note that constant cells - such as the one
/// that holds the segment size - are not counted.
pub fn get_message_segment_length(
    l2_to_l1_payloads_length: &[usize],
    l1_handler_payload_size: Option<usize>,
) -> usize {
    // Add L2-to-L1 message segment length; for each message, the OS outputs the following:
    // to_address, from_address, payload_size, payload.
    let mut message_segment_length = l2_to_l1_payloads_length
        .iter()
        .map(|payload_length| constants::L2_TO_L1_MSG_HEADER_SIZE + payload_length)
        .sum();

    if let Some(payload_size) = l1_handler_payload_size {
        // The corresponding transaction is of type L1 handler; add the length of the L1-to-L2
        // message sent by the sequencer (that will be outputted by the OS), which is of the
        // following format: from_address=calldata[0], to_address=contract_address,
        // nonce, selector, payload_size, payload=calldata[1:].
        message_segment_length += constants::L1_TO_L2_MSG_HEADER_SIZE + payload_size;
    }

    message_segment_length
}

/// Returns the cost of ConsumedMessageToL2 event emissions caused by an L1 handler with the given
/// payload size.
pub fn get_consumed_message_to_l2_emissions_cost(l1_handler_payload_size: Option<usize>) -> usize {
    match l1_handler_payload_size {
        None => 0, // The corresponding transaction is not an L1 handler.,
        Some(l1_handler_payload_size) => {
            get_event_emission_cost(
                constants::CONSUMED_MSG_TO_L2_N_TOPICS,
                // We're assuming the existence of one (not indexed) payload array.
                constants::CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE + l1_handler_payload_size,
            )
        }
    }
}

/// Returns the cost of LogMessageToL1 event emissions caused by the given messages payload length.
pub fn get_log_message_to_l1_emissions_cost(l2_to_l1_payloads_length: &[usize]) -> usize {
    l2_to_l1_payloads_length
        .iter()
        .map(|length| {
            get_event_emission_cost(
                constants::LOG_MSG_TO_L1_N_TOPICS,
                // We're assuming the existence of one (not indexed) payload array.
                constants::LOG_MSG_TO_L1_ENCODED_DATA_SIZE + *length,
            )
        })
        .sum()
}

fn get_event_emission_cost(n_topics: usize, data_length: usize) -> usize {
    eth_gas_constants::GAS_PER_LOG
        + (n_topics + constants::N_DEFAULT_TOPICS) * eth_gas_constants::GAS_PER_LOG_TOPIC
        + data_length * eth_gas_constants::GAS_PER_LOG_DATA_WORD
}

/// Return an estimated lower bound for the fee on an account transaction.
pub fn estimate_minimal_fee(
    block_context: &BlockContext,
    tx: &AccountTransaction,
) -> TransactionExecutionResult<Fee> {
    // TODO(Dori, 1/8/2023): Give names to the constant VM step estimates and regression-test them.
    let os_steps_for_type = OS_RESOURCES
        .execute_txs_inner()
        .get(&tx.tx_type())
        .expect("`OS_RESOURCES` must contain all transaction types.")
        .n_steps;
    let gas_for_type: usize = match tx {
        // We consider the following state changes: sender balance update (storage update) + nonce
        // increment (contract modification) (we exclude the sequencer balance update and the ERC20
        // contract modification since it occurs for every tx).
        AccountTransaction::Declare(_) => get_onchain_data_segment_length(StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }),
        AccountTransaction::Invoke(_) => get_onchain_data_segment_length(StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        }),
        // DeployAccount also updates the address -> class hash mapping.
        AccountTransaction::DeployAccount(_) => {
            get_onchain_data_segment_length(StateChangesCount {
                n_storage_updates: 1,
                n_class_hash_updates: 1,
                n_compiled_class_hash_updates: 0,
                n_modified_contracts: 1,
            })
        }
    };
    let resources = ResourcesMapping(HashMap::from([
        (
            constants::GAS_USAGE.to_string(),
            gas_for_type * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
        ),
        (constants::N_STEPS_RESOURCE.to_string(), os_steps_for_type),
    ]));

    calculate_tx_fee(&resources, block_context)
}
