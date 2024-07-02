use std::sync::Arc;

use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::DeployAccountTransaction;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeployAccountTransactionV1, DeployAccountTransactionV3, Fee,
    PaymasterData, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
};
use starknet_types_core::felt::Felt;

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_transaction::{PyDataAvailabilityMode, PyResourceBoundsMapping};
use crate::py_utils::{from_py_felts, py_attr, PyFelt};

#[derive(FromPyObject)]
struct PyDeployAccountTransactionV1 {
    pub max_fee: u128,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub class_hash: PyFelt,
    pub contract_address_salt: PyFelt,
    pub constructor_calldata: Vec<PyFelt>,
}

impl From<PyDeployAccountTransactionV1> for DeployAccountTransactionV1 {
    fn from(tx: PyDeployAccountTransactionV1) -> Self {
        Self {
            max_fee: Fee(tx.max_fee),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            class_hash: ClassHash(tx.class_hash.0),
            contract_address_salt: ContractAddressSalt(tx.contract_address_salt.0),
            constructor_calldata: Calldata(Arc::from(from_py_felts(tx.constructor_calldata))),
        }
    }
}

#[derive(FromPyObject)]
struct PyDeployAccountTransactionV3 {
    pub resource_bounds: PyResourceBoundsMapping,
    pub tip: u64,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub class_hash: PyFelt,
    pub contract_address_salt: PyFelt,
    pub constructor_calldata: Vec<PyFelt>,
    pub nonce_data_availability_mode: PyDataAvailabilityMode,
    pub fee_data_availability_mode: PyDataAvailabilityMode,
    pub paymaster_data: Vec<PyFelt>,
}

impl TryFrom<PyDeployAccountTransactionV3> for DeployAccountTransactionV3 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyDeployAccountTransactionV3) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_bounds: ResourceBoundsMapping::try_from(tx.resource_bounds)?,
            tip: Tip(tx.tip),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            class_hash: ClassHash(tx.class_hash.0),
            contract_address_salt: ContractAddressSalt(tx.contract_address_salt.0),
            constructor_calldata: Calldata(Arc::from(from_py_felts(tx.constructor_calldata))),
            nonce_data_availability_mode: DataAvailabilityMode::from(
                tx.nonce_data_availability_mode,
            ),
            fee_data_availability_mode: DataAvailabilityMode::from(tx.fee_data_availability_mode),
            paymaster_data: PaymasterData(from_py_felts(tx.paymaster_data)),
        })
    }
}

pub fn py_deploy_account(py_tx: &PyAny) -> NativeBlockifierResult<DeployAccountTransaction> {
    let version = py_attr::<PyFelt>(py_tx, "version")?.0;
    // TODO: Make TransactionVersion an enum and use match here.
    let tx = if version == Felt::ONE {
        let py_deploy_account_tx: PyDeployAccountTransactionV1 = py_tx.extract()?;
        let deploy_account_tx = DeployAccountTransactionV1::from(py_deploy_account_tx);
        Ok(starknet_api::transaction::DeployAccountTransaction::V1(deploy_account_tx))
    } else if version == Felt::THREE {
        let py_deploy_account_tx: PyDeployAccountTransactionV3 = py_tx.extract()?;
        let deploy_account_tx = DeployAccountTransactionV3::try_from(py_deploy_account_tx)?;
        Ok(starknet_api::transaction::DeployAccountTransaction::V3(deploy_account_tx))
    } else {
        Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::DeployAccount,
            version: version.to_biguint(),
        })
    }?;

    let tx_hash = TransactionHash(py_attr::<PyFelt>(py_tx, "hash_value")?.0);
    let contract_address =
        ContractAddress::try_from(py_attr::<PyFelt>(py_tx, "sender_address")?.0)?;
    Ok(DeployAccountTransaction::new(tx, tx_hash, contract_address))
}
