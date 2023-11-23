use std::collections::HashMap;
use std::sync::Arc;

use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME,
    POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

use super::{
    CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_TIMESTAMP, DEFAULT_ETH_L1_GAS_PRICE,
    DEFAULT_STRK_L1_GAS_PRICE, TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_ADDRESS2,
    TEST_SEQUENCER_ADDRESS,
};
use crate::abi::constants;
use crate::abi::constants::{MAX_STEPS_PER_TX, MAX_VALIDATE_STEPS_PER_TX};
use crate::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::{ContractClassV0, ContractClassV1};
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult, ExecutionResources,
};
use crate::state::state_api::State;
use crate::test_utils::get_raw_contract_class;
use crate::test_utils::os_resources_fixture::MOCK_OS_RESOURCES;
use crate::transaction::objects::{AccountTransactionContext, DeprecatedAccountTransactionContext};

impl CallEntryPoint {
    /// Executes the call directly, without account context. Limits the number of steps by resource
    /// bounds.
    pub fn execute_directly(self, state: &mut dyn State) -> EntryPointExecutionResult<CallInfo> {
        self.execute_directly_given_account_context(
            state,
            AccountTransactionContext::Deprecated(DeprecatedAccountTransactionContext::default()),
            true,
        )
    }

    pub fn execute_directly_given_account_context(
        self,
        state: &mut dyn State,
        account_tx_context: AccountTransactionContext,
        limit_steps_by_resources: bool,
    ) -> EntryPointExecutionResult<CallInfo> {
        let block_context = BlockContext::create_for_testing();
        let mut context = EntryPointExecutionContext::new_invoke(
            &block_context,
            &account_tx_context,
            limit_steps_by_resources,
        )
        .unwrap();
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }

    /// Executes the call directly in validate mode, without account context. Limits the number of
    /// steps by resource bounds.
    pub fn execute_directly_in_validate_mode(
        self,
        state: &mut dyn State,
    ) -> EntryPointExecutionResult<CallInfo> {
        self.execute_directly_given_account_context_in_validate_mode(
            state,
            AccountTransactionContext::Deprecated(DeprecatedAccountTransactionContext::default()),
            true,
        )
    }

    pub fn execute_directly_given_account_context_in_validate_mode(
        self,
        state: &mut dyn State,
        account_tx_context: AccountTransactionContext,
        limit_steps_by_resources: bool,
    ) -> EntryPointExecutionResult<CallInfo> {
        let block_context = BlockContext::create_for_testing();
        let mut context = EntryPointExecutionContext::new_validate(
            &block_context,
            &account_tx_context,
            limit_steps_by_resources,
        )
        .unwrap();
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }
}

impl BlockContext {
    pub fn create_for_testing() -> BlockContext {
        BlockContext {
            chain_id: ChainId(CHAIN_ID_NAME.to_string()),
            block_number: BlockNumber(CURRENT_BLOCK_NUMBER),
            block_timestamp: BlockTimestamp(CURRENT_BLOCK_TIMESTAMP),
            sequencer_address: contract_address!(TEST_SEQUENCER_ADDRESS),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS),
                strk_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS2),
            },
            vm_resource_fee_cost: Default::default(),
            gas_prices: GasPrices {
                eth_l1_gas_price: DEFAULT_ETH_L1_GAS_PRICE,
                strk_l1_gas_price: DEFAULT_STRK_L1_GAS_PRICE,
            },
            invoke_tx_max_n_steps: MAX_STEPS_PER_TX as u32,
            validate_max_n_steps: MAX_VALIDATE_STEPS_PER_TX as u32,
            os_resources: MOCK_OS_RESOURCES.clone(),
            max_recursion_depth: 50,
        }
    }

    pub fn create_for_account_testing() -> BlockContext {
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            (constants::N_STEPS_RESOURCE.to_string(), 1_f64),
            (HASH_BUILTIN_NAME.to_string(), 1_f64),
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 1_f64),
            (SIGNATURE_BUILTIN_NAME.to_string(), 1_f64),
            (BITWISE_BUILTIN_NAME.to_string(), 1_f64),
            (POSEIDON_BUILTIN_NAME.to_string(), 1_f64),
            (OUTPUT_BUILTIN_NAME.to_string(), 1_f64),
            (EC_OP_BUILTIN_NAME.to_string(), 1_f64),
        ]));
        BlockContext { vm_resource_fee_cost, ..BlockContext::create_for_testing() }
    }
}

impl CallExecution {
    pub fn from_retdata(retdata: Retdata) -> Self {
        Self { retdata, ..Default::default() }
    }
}

// Contract loaders.

impl ContractClassV0 {
    pub fn from_file(contract_path: &str) -> Self {
        let raw_contract_class = get_raw_contract_class(contract_path);
        Self::try_from_json_string(&raw_contract_class).unwrap()
    }
}

impl ContractClassV1 {
    pub fn from_file(contract_path: &str) -> Self {
        let raw_contract_class = get_raw_contract_class(contract_path);
        Self::try_from_json_string(&raw_contract_class).unwrap()
    }
}
