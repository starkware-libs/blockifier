use starknet_api::class_hash;
use starknet_api::core::{calculate_contract_address, ClassHash, ContractAddress};
use starknet_api::hash::StarkHash;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransactionV1, Fee, TransactionHash,
    TransactionSignature,
};

use crate::test_utils::NonceManager;
use crate::transaction::transactions::DeployAccountTransaction;

pub fn deploy_account_tx(
    class_hash: &str,
    max_fee: Fee,
    constructor_calldata: Option<Calldata>,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    deploy_account_tx_with_salt(
        class_hash,
        max_fee,
        constructor_calldata,
        ContractAddressSalt::default(),
        signature,
        nonce_manager,
    )
}

pub fn deploy_account_tx_with_salt(
    class_hash: &str,
    max_fee: Fee,
    constructor_calldata: Option<Calldata>,
    contract_address_salt: ContractAddressSalt,
    signature: Option<TransactionSignature>,
    nonce_manager: &mut NonceManager,
) -> DeployAccountTransaction {
    let class_hash = class_hash!(class_hash);
    let deployer_address = ContractAddress::default();
    let constructor_calldata = constructor_calldata.unwrap_or_default();
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &constructor_calldata,
        deployer_address,
    )
    .unwrap();

    let tx = starknet_api::transaction::DeployAccountTransaction::V1(DeployAccountTransactionV1 {
        max_fee,
        signature: signature.unwrap_or_default(),
        class_hash,
        contract_address_salt,
        constructor_calldata,
        nonce: nonce_manager.next(contract_address),
    });

    DeployAccountTransaction::new(tx, TransactionHash::default(), contract_address)
}
