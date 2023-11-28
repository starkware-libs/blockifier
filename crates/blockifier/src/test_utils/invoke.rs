use starknet_api::calldata;
use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, Fee, InvokeTransactionV0, InvokeTransactionV1,
    InvokeTransactionV3, PaymasterData, ResourceBoundsMapping, Tip, TransactionHash,
    TransactionSignature, TransactionVersion,
};

use crate::abi::abi_utils::selector_from_name;
use crate::test_utils::default_testing_resource_bounds;
use crate::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use crate::transaction::transactions::InvokeTransaction;

#[derive(Clone)]
pub struct InvokeTxArgs {
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub sender_address: ContractAddress,
    pub calldata: Calldata,
    pub version: TransactionVersion,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,
    pub nonce: Nonce,
    pub only_query: bool,
}

impl Default for InvokeTxArgs {
    fn default() -> Self {
        InvokeTxArgs {
            max_fee: Fee::default(),
            signature: TransactionSignature::default(),
            sender_address: ContractAddress::default(),
            calldata: calldata![],
            // TODO(Dori, 10/10/2023): Change to THREE when supported.
            version: TransactionVersion::ONE,
            resource_bounds: default_testing_resource_bounds(),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
            nonce: Nonce::default(),
            only_query: false,
        }
    }
}

/// Utility macro for creating `InvokeTxArgs` with "smart" default values, kwarg-style notation.
#[macro_export]
macro_rules! invoke_tx_args {
    ($($field:ident $(: $value:expr)?),* $(,)?) => {
        {
            // Fill in all fields + defaults for missing fields.
            let mut _macro_invoke_tx_args = InvokeTxArgs {
                $($field $(: $value)?,)*
                ..Default::default()
            };
            // If resource bounds aren't explicitly passed, derive them from max_fee.
            if _macro_invoke_tx_args.version >= TransactionVersion::THREE
                && [$(stringify!($field) != "resource_bounds"),*].iter().all(|&x| x) {
                let _macro_new_resource_bounds_vec: Vec<(
                    starknet_api::transaction::Resource,
                    starknet_api::transaction::ResourceBounds
                )> = [
                    starknet_api::transaction::Resource::L1Gas,
                    starknet_api::transaction::Resource::L2Gas
                ].into_iter().map(|resource| (
                    resource,
                    starknet_api::transaction::ResourceBounds {
                        max_amount: _macro_invoke_tx_args.max_fee.0 as u64,
                        max_price_per_unit: 1
                    },
                )).collect();
                _macro_invoke_tx_args.resource_bounds
                    = starknet_api::transaction::ResourceBoundsMapping::try_from(
                        _macro_new_resource_bounds_vec
                    ).unwrap();
            }
            _macro_invoke_tx_args
        }
    };
    ($($field:ident $(: $value:expr)?),* , ..$defaults:expr) => {
        {
            // Fill in all fields + use the provided defaults for missing fields.
            // In this case, do not derive "smart" defaults for fields not passed explicitly - we
            // assume these fields are already "correct" on the provided defaults.
            InvokeTxArgs {
                $($field $(: $value)?,)*
                ..$defaults
            }
        }
    };
}

pub fn invoke_tx(invoke_args: InvokeTxArgs) -> InvokeTransaction {
    let invoke_tx = match invoke_args.version {
        TransactionVersion::ZERO => {
            starknet_api::transaction::InvokeTransaction::V0(InvokeTransactionV0 {
                max_fee: invoke_args.max_fee,
                calldata: invoke_args.calldata,
                contract_address: invoke_args.sender_address,
                signature: invoke_args.signature,
                // V0 transactions should always select the `__execute__` entry point.
                entry_point_selector: selector_from_name(EXECUTE_ENTRY_POINT_NAME),
            })
        }
        TransactionVersion::ONE => {
            starknet_api::transaction::InvokeTransaction::V1(InvokeTransactionV1 {
                max_fee: invoke_args.max_fee,
                sender_address: invoke_args.sender_address,
                nonce: invoke_args.nonce,
                calldata: invoke_args.calldata,
                signature: invoke_args.signature,
            })
        }
        TransactionVersion::THREE => {
            starknet_api::transaction::InvokeTransaction::V3(InvokeTransactionV3 {
                resource_bounds: invoke_args.resource_bounds,
                calldata: invoke_args.calldata,
                sender_address: invoke_args.sender_address,
                nonce: invoke_args.nonce,
                signature: invoke_args.signature,
                tip: invoke_args.tip,
                nonce_data_availability_mode: invoke_args.nonce_data_availability_mode,
                fee_data_availability_mode: invoke_args.fee_data_availability_mode,
                paymaster_data: invoke_args.paymaster_data,
                account_deployment_data: invoke_args.account_deployment_data,
            })
        }
        _ => panic!("Unsupported transaction version: {:?}.", invoke_args.version),
    };

    let default_tx_hash = TransactionHash::default();
    match invoke_args.only_query {
        true => InvokeTransaction::new_for_query(invoke_tx, default_tx_hash),
        false => InvokeTransaction::new(invoke_tx, default_tx_hash),
    }
}
