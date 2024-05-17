use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde_json::Value;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

use super::update_json_value;
use crate::blockifier::block::{BlockInfo, GasPrices};
use crate::bouncer::{BouncerConfig, BouncerWeights, BuiltinCount};
use crate::context::{BlockContext, ChainInfo, FeeTokenAddresses, TransactionContext};
use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::{ContractClassV0, ContractClassV1, SierraContractClassV1};
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::state::state_api::State;
use crate::test_utils::{
    get_raw_contract_class, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_TIMESTAMP,
    DEFAULT_ETH_L1_DATA_GAS_PRICE, DEFAULT_ETH_L1_GAS_PRICE, DEFAULT_STRK_L1_DATA_GAS_PRICE,
    DEFAULT_STRK_L1_GAS_PRICE, TEST_ERC20_CONTRACT_ADDRESS, TEST_ERC20_CONTRACT_ADDRESS2,
    TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::objects::{DeprecatedTransactionInfo, TransactionInfo};
use crate::versioned_constants::{
    GasCosts, OsConstants, VersionedConstants, DEFAULT_CONSTANTS_JSON,
};

impl CallEntryPoint {
    /// Executes the call directly, without account context. Limits the number of steps by resource
    /// bounds.
    pub fn execute_directly(self, state: &mut dyn State) -> EntryPointExecutionResult<CallInfo> {
        self.execute_directly_given_tx_info(
            state,
            TransactionInfo::Deprecated(DeprecatedTransactionInfo::default()),
            true,
        )
    }

    pub fn execute_directly_given_tx_info(
        self,
        state: &mut dyn State,
        tx_info: TransactionInfo,
        limit_steps_by_resources: bool,
    ) -> EntryPointExecutionResult<CallInfo> {
        let tx_context =
            TransactionContext { block_context: BlockContext::create_for_testing(), tx_info };
        let mut context =
            EntryPointExecutionContext::new_invoke(Arc::new(tx_context), limit_steps_by_resources)
                .unwrap();
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }

    /// Executes the call directly in validate mode, without account context. Limits the number of
    /// steps by resource bounds.
    pub fn execute_directly_in_validate_mode(
        self,
        state: &mut dyn State,
    ) -> EntryPointExecutionResult<CallInfo> {
        self.execute_directly_given_tx_info_in_validate_mode(
            state,
            TransactionInfo::Deprecated(DeprecatedTransactionInfo::default()),
            true,
        )
    }

    pub fn execute_directly_given_tx_info_in_validate_mode(
        self,
        state: &mut dyn State,
        tx_info: TransactionInfo,
        limit_steps_by_resources: bool,
    ) -> EntryPointExecutionResult<CallInfo> {
        let tx_context =
            TransactionContext { block_context: BlockContext::create_for_testing(), tx_info };
        let mut context = EntryPointExecutionContext::new_validate(
            Arc::new(tx_context),
            limit_steps_by_resources,
        )
        .unwrap();
        self.execute(state, &mut ExecutionResources::default(), &mut context)
    }
}

impl VersionedConstants {
    pub fn create_for_testing() -> Self {
        Self::latest_constants().clone()
    }
}

impl GasCosts {
    pub fn create_for_testing_from_subset(subset_of_os_constants: &str) -> Self {
        let subset_of_os_constants: Value = serde_json::from_str(subset_of_os_constants).unwrap();
        let mut os_constants: Value = serde_json::from_str::<Value>(DEFAULT_CONSTANTS_JSON)
            .unwrap()
            .get("os_constants")
            .unwrap()
            .clone();
        update_json_value(&mut os_constants, subset_of_os_constants);
        let os_constants: OsConstants = serde_json::from_value(os_constants).unwrap();
        os_constants.gas_costs
    }
}

impl ChainInfo {
    pub fn create_for_testing() -> Self {
        Self {
            chain_id: ChainId(CHAIN_ID_NAME.to_string()),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS),
                strk_fee_token_address: contract_address!(TEST_ERC20_CONTRACT_ADDRESS2),
            },
        }
    }
}

impl BlockInfo {
    pub fn create_for_testing() -> Self {
        Self {
            block_number: BlockNumber(CURRENT_BLOCK_NUMBER),
            block_timestamp: BlockTimestamp(CURRENT_BLOCK_TIMESTAMP),
            sequencer_address: contract_address!(TEST_SEQUENCER_ADDRESS),
            gas_prices: GasPrices {
                eth_l1_gas_price: DEFAULT_ETH_L1_GAS_PRICE.try_into().unwrap(),
                strk_l1_gas_price: DEFAULT_STRK_L1_GAS_PRICE.try_into().unwrap(),
                eth_l1_data_gas_price: DEFAULT_ETH_L1_DATA_GAS_PRICE.try_into().unwrap(),
                strk_l1_data_gas_price: DEFAULT_STRK_L1_DATA_GAS_PRICE.try_into().unwrap(),
            },
            use_kzg_da: false,
        }
    }

    pub fn create_for_testing_with_kzg(use_kzg_da: bool) -> Self {
        Self { use_kzg_da, ..Self::create_for_testing() }
    }
}

impl BlockContext {
    pub fn create_for_testing() -> Self {
        Self {
            block_info: BlockInfo::create_for_testing(),
            chain_info: ChainInfo::create_for_testing(),
            versioned_constants: VersionedConstants::create_for_testing(),
            concurrency_mode: false,
        }
    }

    pub fn create_for_account_testing() -> Self {
        Self {
            block_info: BlockInfo::create_for_testing(),
            chain_info: ChainInfo::create_for_testing(),
            versioned_constants: VersionedConstants::create_for_account_testing(),
            concurrency_mode: false,
        }
    }

    pub fn create_for_account_testing_with_kzg(use_kzg_da: bool) -> Self {
        Self {
            block_info: BlockInfo::create_for_testing_with_kzg(use_kzg_da),
            ..Self::create_for_account_testing()
        }
    }

    pub fn create_for_account_testing_with_concurrency_mode(concurrency_mode: bool) -> Self {
        Self { concurrency_mode, ..Self::create_for_account_testing() }
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

impl SierraContractClassV1 {
    pub fn from_file(contract_path: &str) -> Self {
        let raw_contract_class = get_raw_contract_class(contract_path);
        Self::try_from_json_string(&raw_contract_class).unwrap()
    }
}

impl BouncerConfig {
    pub fn create_for_testing() -> Self {
        Self {
            block_max_capacity_with_keccak: BouncerWeights::create_for_testing(true),
            block_max_capacity: BouncerWeights::create_for_testing(false),
        }
    }
}

impl BouncerWeights {
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

impl BuiltinCount {
    pub fn create_for_testing(with_keccak: bool) -> Self {
        let keccak = if with_keccak { 1220 } else { 0 };
        Self {
            bitwise: 39062,
            ecdsa: 1220,
            ec_op: 2441,
            keccak,
            pedersen: 78125,
            poseidon: 78125,
            range_check: 156250,
        }
    }
}
