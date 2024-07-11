use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransactionV1, DeployAccountTransactionV3, Fee,
    PaymasterData, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::test_utils::{default_testing_resource_bounds, NonceManager};
use crate::transaction::transactions::DeployAccountTransaction;

#[derive(Clone)]
pub struct DeployAccountTxArgs {
    pub max_fee: Fee,
    pub signature: TransactionSignature,
    pub deployer_address: ContractAddress,
    pub version: TransactionVersion,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub nonce: Nonce,
    pub class_hash: ClassHash,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Calldata,
}

impl Default for DeployAccountTxArgs {
    fn default() -> Self {
        DeployAccountTxArgs {
            max_fee: Fee::default(),
            signature: TransactionSignature::default(),
            deployer_address: ContractAddress::default(),
            version: TransactionVersion::THREE,
            resource_bounds: default_testing_resource_bounds(),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            nonce: Nonce::default(),
            class_hash: ClassHash::default(),
            contract_address_salt: ContractAddressSalt::default(),
            constructor_calldata: Calldata::default(),
        }
    }
}

/// Utility macro for creating `DeployAccountTxArgs` to reduce boilerplate.
#[macro_export]
macro_rules! deploy_account_tx_args {
    ($($field:ident $(: $value:expr)?),* $(,)?) => {
        $crate::test_utils::deploy_account::DeployAccountTxArgs {
            $($field $(: $value)?,)*
            ..Default::default()
        }
    };
    ($($field:ident $(: $value:expr)?),* , ..$defaults:expr) => {
        $crate::test_utils::deploy_account::DeployAccountTxArgs {
            $($field $(: $value)?,)*
            ..$defaults
        }
    };
}

pub fn deploy_account_tx(
    deploy_tx_args: DeployAccountTxArgs,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    let contract_address = calculate_contract_address(
        deploy_tx_args.contract_address_salt,
        deploy_tx_args.class_hash,
        &deploy_tx_args.constructor_calldata,
        deploy_tx_args.deployer_address,
    )
    .unwrap();

    // TODO: Make TransactionVersion an enum and use match here.
    let tx = if deploy_tx_args.version == TransactionVersion::ONE {
        starknet_api::transaction::DeployAccountTransaction::V1(DeployAccountTransactionV1 {
            max_fee: deploy_tx_args.max_fee,
            signature: deploy_tx_args.signature,
            nonce: nonce_manager.next(contract_address),
            class_hash: deploy_tx_args.class_hash,
            contract_address_salt: deploy_tx_args.contract_address_salt,
            constructor_calldata: deploy_tx_args.constructor_calldata,
        })
    } else if deploy_tx_args.version == TransactionVersion::THREE {
        starknet_api::transaction::DeployAccountTransaction::V3(DeployAccountTransactionV3 {
            signature: deploy_tx_args.signature,
            resource_bounds: deploy_tx_args.resource_bounds,
            tip: deploy_tx_args.tip,
            nonce_data_availability_mode: deploy_tx_args.nonce_data_availability_mode,
            fee_data_availability_mode: deploy_tx_args.fee_data_availability_mode,
            paymaster_data: deploy_tx_args.paymaster_data,
            nonce: nonce_manager.next(contract_address),
            class_hash: deploy_tx_args.class_hash,
            contract_address_salt: deploy_tx_args.contract_address_salt,
            constructor_calldata: deploy_tx_args.constructor_calldata,
        })
    } else {
        panic!("Unsupported transaction version: {:?}.", deploy_tx_args.version)
    };

    DeployAccountTransaction::new(tx, TransactionHash::default(), contract_address)
}
