use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use crate::execution::call_info::Retdata;
use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::block_context::BlockContext;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, EntryPointExecutionContext, ExecutionResources,
};
use crate::retdata;
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

#[cfg(test)]
#[path = "block_execution_test.rs"]
pub mod test;

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<(BlockNumber, BlockHash)>,
    block_context: &mut BlockContext,
) {
    if let Some((block_number, block_hash)) = old_block_number_and_hash {
        state.set_storage_at(
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
            StorageKey::try_from(StarkFelt::from(block_number.0))
                .expect("Failed to convert BlockNumber to StorageKey."),
            block_hash.0,
        );

        let mut execute_call_context = EntryPointExecutionContext::new_invoke(
            &block_context,
            &AccountTransactionContext::default(),
        );
        let result = CallEntryPoint {
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name("factory"),
            calldata: calldata![],
            class_hash: Some(class_hash!(
                "0x07197021c108b0cc57ae354f5ad02222c4b3d7344664e6dd602a0e2298595434"
            )),
            code_address: Some(contract_address!(
                "0x041fd22b238fa21cfcf5dd45a8548974d8263b3a531a60388411c5e230f97023"
            )),
            storage_address: contract_address!(
                "0x041fd22b238fa21cfcf5dd45a8548974d8263b3a531a60388411c5e230f97023"
            ),
            caller_address: ContractAddress::default(),
            call_type: CallType::Call,
            initial_gas: 0,
        }
        .execute(state, &mut ExecutionResources::default(), &mut execute_call_context)
        .unwrap()
        .execution
        .retdata;
        println!("@@ before assert @@");
        assert_eq!(result, retdata![stark_felt!(0_u8)]);
        println!("@@ after assert @@");
        block_context.strk_l1_gas_price = 2;
    }
}
