use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransactionV1, DeployAccountTransactionV3, Fee,
    PaymasterData, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use super::default_testing_resource_bounds;
use crate::test_utils::NonceManager;
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
            resource_bounds: default_testing_resource_bounds(),
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

    let tx = match deploy_tx_args.version {
        TransactionVersion::ONE => {
            starknet_api::transaction::DeployAccountTransaction::V1(DeployAccountTransactionV1 {
                max_fee: deploy_tx_args.max_fee,
                signature: deploy_tx_args.signature,
                class_hash: deploy_tx_args.class_hash,
                contract_address_salt: deploy_tx_args.contract_address_salt,
                constructor_calldata: deploy_tx_args.constructor_calldata,
                nonce: nonce_manager.next(contract_address),
            })
        }
        TransactionVersion::THREE => {
            starknet_api::transaction::DeployAccountTransaction::V3(DeployAccountTransactionV3 {
                resource_bounds: deploy_tx_args.resource_bounds,
                signature: deploy_tx_args.signature,
                class_hash: deploy_tx_args.class_hash,
                contract_address_salt: deploy_tx_args.contract_address_salt,
                constructor_calldata: deploy_tx_args.constructor_calldata,
                nonce: nonce_manager.next(contract_address),
                tip: deploy_tx_args.tip,
                nonce_data_availability_mode: deploy_tx_args.nonce_data_availability_mode,
                fee_data_availability_mode: deploy_tx_args.fee_data_availability_mode,
                paymaster_data: deploy_tx_args.paymaster_data,
            })
        }
        version => panic!("Unsupported transaction version: {:?}.", version),
    };

    DeployAccountTransaction::new(tx, TransactionHash::default(), contract_address)
}
