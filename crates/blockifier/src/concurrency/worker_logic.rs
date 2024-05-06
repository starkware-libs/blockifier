use cairo_felt::Felt252;
use starknet_api::core::ContractAddress;
use starknet_api::transaction::Fee;

use super::versioned_state_proxy::VersionedStateProxy;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader, StateResult};

fn _finalize_commit(
    fee_token_adress: ContractAddress,
    pinned_versioned_state: &VersionedStateProxy<impl StateReader>,
    actual_fee: &Fee,
    transactional_state: &mut CachedState<impl StateReader>,
) -> StateResult<()> {
    let sequencer_balance_key = get_fee_token_var_address(fee_token_adress);
    let sequencer_balance_value =
        pinned_versioned_state.get_storage_at(fee_token_adress, sequencer_balance_key)?;
    let value = stark_felt_to_felt(sequencer_balance_value) + Felt252::from(actual_fee.0);
    transactional_state.set_storage_at(
        fee_token_adress,
        sequencer_balance_key,
        felt_to_stark_felt(&value),
    )?;
    Ok(())
}
