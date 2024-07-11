use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3, Fee,
    PaymasterData, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::execution::contract_class::ClassInfo;
use crate::test_utils::default_testing_resource_bounds;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::DeclareTransaction;

#[derive(Clone)]
pub struct DeclareTxArgs {
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub sender_address: ContractAddress,
    pub version: TransactionVersion,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,
    pub nonce: Nonce,
    pub class_hash: ClassHash,
    pub compiled_class_hash: CompiledClassHash,
    pub tx_hash: TransactionHash,
}

impl Default for DeclareTxArgs {
    fn default() -> Self {
        Self {
            max_fee: Fee::default(),
            signature: TransactionSignature::default(),
            sender_address: ContractAddress::default(),
            version: TransactionVersion::THREE,
            resource_bounds: default_testing_resource_bounds(),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
            nonce: Nonce::default(),
            class_hash: ClassHash::default(),
            compiled_class_hash: CompiledClassHash::default(),
            tx_hash: TransactionHash::default(),
        }
    }
}

/// Utility macro for creating `DeclareTxArgs` to reduce boilerplate.
#[macro_export]
macro_rules! declare_tx_args {
    ($($field:ident $(: $value:expr)?),* $(,)?) => {
        $crate::test_utils::declare::DeclareTxArgs {
            $($field $(: $value)?,)*
            ..Default::default()
        }
    };
    ($($field:ident $(: $value:expr)?),* , ..$defaults:expr) => {
        $crate::test_utils::declare::DeclareTxArgs {
            $($field $(: $value)?,)*
            ..$defaults
        }
    };
}

pub fn declare_tx(declare_tx_args: DeclareTxArgs, class_info: ClassInfo) -> AccountTransaction {
    AccountTransaction::Declare(
        DeclareTransaction::new(
            // TODO: Make TransactionVersion an enum and use match here.
            if declare_tx_args.version == TransactionVersion::ZERO {
                starknet_api::transaction::DeclareTransaction::V0(DeclareTransactionV0V1 {
                    max_fee: declare_tx_args.max_fee,
                    signature: declare_tx_args.signature,
                    sender_address: declare_tx_args.sender_address,
                    nonce: declare_tx_args.nonce,
                    class_hash: declare_tx_args.class_hash,
                })
            } else if declare_tx_args.version == TransactionVersion::ONE {
                starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
                    max_fee: declare_tx_args.max_fee,
                    signature: declare_tx_args.signature,
                    sender_address: declare_tx_args.sender_address,
                    nonce: declare_tx_args.nonce,
                    class_hash: declare_tx_args.class_hash,
                })
            } else if declare_tx_args.version == TransactionVersion::TWO {
                starknet_api::transaction::DeclareTransaction::V2(DeclareTransactionV2 {
                    max_fee: declare_tx_args.max_fee,
                    signature: declare_tx_args.signature,
                    sender_address: declare_tx_args.sender_address,
                    nonce: declare_tx_args.nonce,
                    class_hash: declare_tx_args.class_hash,
                    compiled_class_hash: declare_tx_args.compiled_class_hash,
                })
            } else if declare_tx_args.version == TransactionVersion::THREE {
                starknet_api::transaction::DeclareTransaction::V3(DeclareTransactionV3 {
                    signature: declare_tx_args.signature,
                    sender_address: declare_tx_args.sender_address,
                    resource_bounds: declare_tx_args.resource_bounds,
                    tip: declare_tx_args.tip,
                    nonce_data_availability_mode: declare_tx_args.nonce_data_availability_mode,
                    fee_data_availability_mode: declare_tx_args.fee_data_availability_mode,
                    paymaster_data: declare_tx_args.paymaster_data,
                    account_deployment_data: declare_tx_args.account_deployment_data,
                    nonce: declare_tx_args.nonce,
                    class_hash: declare_tx_args.class_hash,
                    compiled_class_hash: declare_tx_args.compiled_class_hash,
                })
            } else {
                panic!("Unsupported transaction version: {:?}.", declare_tx_args.version)
            },
            declare_tx_args.tx_hash,
            class_info,
        )
        .unwrap(),
    )
}
