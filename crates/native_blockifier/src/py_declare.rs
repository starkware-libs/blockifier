use std::convert::TryFrom;

use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::DeclareTransaction;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3, Fee,
    PaymasterData, ResourceBoundsMapping, Tip, TransactionHash, TransactionSignature,
};
use starknet_types_core::felt::Felt;

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_transaction::{PyClassInfo, PyDataAvailabilityMode, PyResourceBoundsMapping};
use crate::py_utils::{from_py_felts, py_attr, PyFelt};

#[derive(FromPyObject)]
struct PyDeclareTransactionV0V1 {
    pub max_fee: u128,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub class_hash: PyFelt,
    pub sender_address: PyFelt,
}

impl TryFrom<PyDeclareTransactionV0V1> for DeclareTransactionV0V1 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyDeclareTransactionV0V1) -> Result<Self, Self::Error> {
        Ok(Self {
            max_fee: Fee(tx.max_fee),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            class_hash: ClassHash(tx.class_hash.0),
            sender_address: ContractAddress::try_from(tx.sender_address.0)?,
        })
    }
}

#[derive(FromPyObject)]
struct PyDeclareTransactionV2 {
    pub max_fee: u128,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub class_hash: PyFelt,
    pub compiled_class_hash: PyFelt,
    pub sender_address: PyFelt,
}

impl TryFrom<PyDeclareTransactionV2> for DeclareTransactionV2 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyDeclareTransactionV2) -> Result<Self, Self::Error> {
        Ok(Self {
            max_fee: Fee(tx.max_fee),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            class_hash: ClassHash(tx.class_hash.0),
            compiled_class_hash: CompiledClassHash(tx.compiled_class_hash.0),
            sender_address: ContractAddress::try_from(tx.sender_address.0)?,
        })
    }
}

#[derive(FromPyObject)]
struct PyDeclareTransactionV3 {
    pub resource_bounds: PyResourceBoundsMapping,
    pub tip: u64,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub class_hash: PyFelt,
    pub compiled_class_hash: PyFelt,
    pub sender_address: PyFelt,
    pub nonce_data_availability_mode: PyDataAvailabilityMode,
    pub fee_data_availability_mode: PyDataAvailabilityMode,
    pub paymaster_data: Vec<PyFelt>,
    pub account_deployment_data: Vec<PyFelt>,
}

impl TryFrom<PyDeclareTransactionV3> for DeclareTransactionV3 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyDeclareTransactionV3) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_bounds: ResourceBoundsMapping::try_from(tx.resource_bounds)?,
            tip: Tip(tx.tip),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            class_hash: ClassHash(tx.class_hash.0),
            compiled_class_hash: CompiledClassHash(tx.compiled_class_hash.0),
            sender_address: ContractAddress::try_from(tx.sender_address.0)?,
            nonce_data_availability_mode: DataAvailabilityMode::from(
                tx.nonce_data_availability_mode,
            ),
            fee_data_availability_mode: DataAvailabilityMode::from(tx.fee_data_availability_mode),
            paymaster_data: PaymasterData(from_py_felts(tx.paymaster_data)),
            account_deployment_data: AccountDeploymentData(from_py_felts(
                tx.account_deployment_data,
            )),
        })
    }
}

pub fn py_declare(
    py_tx: &PyAny,
    py_class_info: PyClassInfo,
) -> NativeBlockifierResult<DeclareTransaction> {
    let version = py_attr::<PyFelt>(py_tx, "version")?.0;
    // TODO: Make TransactionVersion an enum and use match here.
    let tx = if version == Felt::ZERO {
        let py_declare_tx: PyDeclareTransactionV0V1 = py_tx.extract()?;
        let declare_tx = DeclareTransactionV0V1::try_from(py_declare_tx)?;
        Ok(starknet_api::transaction::DeclareTransaction::V0(declare_tx))
    } else if version == Felt::ONE {
        let py_declare_tx: PyDeclareTransactionV0V1 = py_tx.extract()?;
        let declare_tx = DeclareTransactionV0V1::try_from(py_declare_tx)?;
        Ok(starknet_api::transaction::DeclareTransaction::V1(declare_tx))
    } else if version == Felt::TWO {
        let py_declare_tx: PyDeclareTransactionV2 = py_tx.extract()?;
        let declare_tx = DeclareTransactionV2::try_from(py_declare_tx)?;
        Ok(starknet_api::transaction::DeclareTransaction::V2(declare_tx))
    } else if version == Felt::THREE {
        let py_declare_tx: PyDeclareTransactionV3 = py_tx.extract()?;
        let declare_tx = DeclareTransactionV3::try_from(py_declare_tx)?;
        Ok(starknet_api::transaction::DeclareTransaction::V3(declare_tx))
    } else {
        Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::Declare,
            version: version.to_biguint(),
        })
    }?;
    let tx_hash = TransactionHash(py_attr::<PyFelt>(py_tx, "hash_value")?.0);
    let class_info = PyClassInfo::try_from(py_class_info, &tx)?;
    Ok(DeclareTransaction::new(tx, tx_hash, class_info)?)
}
