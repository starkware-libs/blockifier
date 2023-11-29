use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, DeclareTransactionV0V1, Fee, PaymasterData, ResourceBoundsMapping, Tip,
    TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::execution::contract_class::ContractClass;
use crate::test_utils::default_testing_resource_bounds;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::DeclareTransaction;

#[derive(Clone)]
pub struct DeclareTxArgs {
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub class_hash: ClassHash,
    pub sender_address: ContractAddress,
    pub compiled_class_hash: CompiledClassHash,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,

    // Meta fields.
    pub version: TransactionVersion,
    pub tx_hash: TransactionHash,
}

impl Default for DeclareTxArgs {
    fn default() -> Self {
        Self {
            max_fee: Fee::default(),
            signature: TransactionSignature::default(),
            sender_address: ContractAddress::default(),
            class_hash: ClassHash::default(),
            compiled_class_hash: CompiledClassHash::default(),
            version: TransactionVersion::ONE,
            resource_bounds: default_testing_resource_bounds(),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
            nonce: Nonce::default(),
            tx_hash: TransactionHash::default(),
        }
    }
}

pub fn declare_tx(
    declare_tx_args: DeclareTxArgs,
    contract_class: ContractClass,
) -> AccountTransaction {
    AccountTransaction::Declare(
        DeclareTransaction::new(
            starknet_api::transaction::DeclareTransaction::V1(DeclareTransactionV0V1 {
                max_fee: declare_tx_args.max_fee,
                class_hash: declare_tx_args.class_hash,
                sender_address: declare_tx_args.sender_address,
                signature: declare_tx_args.signature,
                nonce: declare_tx_args.nonce,
            }),
            declare_tx_args.tx_hash,
            contract_class,
        )
        .unwrap(),
    )
}
