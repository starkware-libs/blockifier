use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransactionV1, Fee, PaymasterData, Resource,
    ResourceBounds, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use super::NonceManager;
use crate::transaction::transactions::DeployAccountTransaction;

#[derive(Clone)]
pub struct DeployTxArgs {
    pub version: TransactionVersion,
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub class_hash: ClassHash,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Calldata,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub deployer_address: ContractAddress,
}

impl Default for DeployTxArgs {
    fn default() -> Self {
        DeployTxArgs {
            version: TransactionVersion::ONE,
            resource_bounds: ResourceBoundsMapping::try_from(vec![
                (Resource::L1Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 1 }),
                // TODO(Dori, 1/2/2024): When fee market is developed, change the default price of
                //   L2 gas.
                (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
            ])
            .unwrap(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            nonce: Nonce::default(),
            class_hash: ClassHash::default(),
            contract_address_salt: ContractAddressSalt::default(),
            constructor_calldata: Calldata::default(),
            tip: Tip::default(),
            paymaster_data: PaymasterData::default(),
            signature: TransactionSignature::default(),
            max_fee: Fee::default(),
            deployer_address: ContractAddress::default(),
        }
    }
}

pub fn deploy_account_tx(
    deploy_tx_args: DeployTxArgs,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    let contract_address = calculate_contract_address(
        deploy_tx_args.contract_address_salt,
        deploy_tx_args.class_hash,
        &deploy_tx_args.constructor_calldata,
        deploy_tx_args.deployer_address,
    )
    .unwrap();

    let tx = starknet_api::transaction::DeployAccountTransaction::V1(DeployAccountTransactionV1 {
        max_fee: deploy_tx_args.max_fee,
        signature: deploy_tx_args.signature,
        class_hash: deploy_tx_args.class_hash,
        contract_address_salt: deploy_tx_args.contract_address_salt,
        constructor_calldata: deploy_tx_args.constructor_calldata,
        nonce: nonce_manager.next(contract_address),
    });

    DeployAccountTransaction::new(tx, TransactionHash::default(), contract_address)
}
