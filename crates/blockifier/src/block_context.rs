use std::collections::HashSet;

use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::transaction::errors::TransactionFeeError;
use crate::transaction::objects::{FeeType, TransactionFeeResult};

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub block_info: BlockInfo,
    pub chain_info: ChainInfo,
}

macro_rules! define_vm_resource_costs {
    ($(($field:ident, $field_type:ty)),* $(,)?) => {
        #[derive(Clone, Debug, Default)]
        pub struct VmResourceCosts {
            $(pub $field: $field_type,)*
        }

        // TODO(Dori, 1/4/2024): Once ResourceMapping is also no longer a HashMap, we may be able to
        //   remove the impl block for VmResourceCosts (and perhaps ResourcesMapping as well).
        impl VmResourceCosts {
            pub fn resource_names() -> HashSet<String> {
                HashSet::from([$(stringify!($field).to_string(),)*])
            }

            pub fn get(&self, resource_name: &str) -> TransactionFeeResult<f64> {
                match resource_name {
                    $(stringify!($field) => Ok(self.$field),)*
                    _ => Err(TransactionFeeError::CairoResourcesNotContainedInFeeCosts),
                }
            }
        }
    };
}

define_vm_resource_costs! {
    (n_steps, f64),
    (pedersen_builtin, f64),
    (range_check_builtin, f64),
    (ecdsa_builtin, f64),
    (bitwise_builtin, f64),
    (poseidon_builtin, f64),
    (output_builtin, f64),
    (ec_op_builtin, f64),
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,

    // Fee-related.
    pub sequencer_address: ContractAddress,
    pub vm_resource_fee_cost: VmResourceCosts,
    pub gas_prices: GasPrices,
    pub use_kzg_da: bool,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}

#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain_id: ChainId,
    pub fee_token_addresses: FeeTokenAddresses,
}

impl ChainInfo {
    pub fn fee_token_address(&self, fee_type: &FeeType) -> ContractAddress {
        self.fee_token_addresses.get_by_fee_type(fee_type)
    }
}

#[derive(Clone, Debug)]
pub struct FeeTokenAddresses {
    pub strk_fee_token_address: ContractAddress,
    pub eth_fee_token_address: ContractAddress,
}

impl FeeTokenAddresses {
    pub fn get_by_fee_type(&self, fee_type: &FeeType) -> ContractAddress {
        match fee_type {
            FeeType::Strk => self.strk_fee_token_address,
            FeeType::Eth => self.eth_fee_token_address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GasPrices {
    pub eth_l1_gas_price: u128,       // In wei.
    pub strk_l1_gas_price: u128,      // In fri.
    pub eth_l1_data_gas_price: u128,  // In wei.
    pub strk_l1_data_gas_price: u128, // In fri.
}

impl GasPrices {
    pub fn get_gas_price_by_fee_type(&self, fee_type: &FeeType) -> u128 {
        match fee_type {
            FeeType::Strk => self.strk_l1_gas_price,
            FeeType::Eth => self.eth_l1_gas_price,
        }
    }

    pub fn get_data_gas_price_by_fee_type(&self, fee_type: &FeeType) -> u128 {
        match fee_type {
            FeeType::Strk => self.strk_l1_data_gas_price,
            FeeType::Eth => self.eth_l1_data_gas_price,
        }
    }
}
