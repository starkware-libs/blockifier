use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::InvokeTransaction;
use pyo3::prelude::*;
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, Fee, InvokeTransactionV0, InvokeTransactionV1,
    InvokeTransactionV3, PaymasterData, ResourceBoundsMapping, Tip, TransactionHash,
    TransactionSignature,
};
use starknet_types_core::felt::Felt;

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_transaction::{PyDataAvailabilityMode, PyResourceBoundsMapping};
use crate::py_utils::{from_py_felts, py_attr, PyFelt};

#[derive(FromPyObject)]
struct PyInvokeTransactionV0 {
    pub max_fee: u128,
    pub signature: Vec<PyFelt>,
    pub sender_address: PyFelt,
    pub entry_point_selector: PyFelt,
    pub calldata: Vec<PyFelt>,
}

impl TryFrom<PyInvokeTransactionV0> for InvokeTransactionV0 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyInvokeTransactionV0) -> Result<Self, Self::Error> {
        Ok(Self {
            max_fee: Fee(tx.max_fee),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            contract_address: ContractAddress::try_from(tx.sender_address.0)?,
            entry_point_selector: EntryPointSelector(tx.entry_point_selector.0),
            calldata: Calldata(Arc::from(from_py_felts(tx.calldata))),
        })
    }
}

#[derive(FromPyObject)]
struct PyInvokeTransactionV1 {
    pub max_fee: u128,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub sender_address: PyFelt,
    pub calldata: Vec<PyFelt>,
}

impl TryFrom<PyInvokeTransactionV1> for InvokeTransactionV1 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyInvokeTransactionV1) -> Result<Self, Self::Error> {
        Ok(Self {
            max_fee: Fee(tx.max_fee),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            sender_address: ContractAddress::try_from(tx.sender_address.0)?,
            calldata: Calldata(Arc::from(from_py_felts(tx.calldata))),
        })
    }
}

#[derive(FromPyObject)]
struct PyInvokeTransactionV3 {
    pub resource_bounds: PyResourceBoundsMapping,
    pub tip: u64,
    pub signature: Vec<PyFelt>,
    pub nonce: PyFelt,
    pub sender_address: PyFelt,
    pub calldata: Vec<PyFelt>,
    pub nonce_data_availability_mode: PyDataAvailabilityMode,
    pub fee_data_availability_mode: PyDataAvailabilityMode,
    pub paymaster_data: Vec<PyFelt>,
    pub account_deployment_data: Vec<PyFelt>,
}

impl TryFrom<PyInvokeTransactionV3> for InvokeTransactionV3 {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyInvokeTransactionV3) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_bounds: ResourceBoundsMapping::try_from(tx.resource_bounds)?,
            tip: Tip(tx.tip),
            signature: TransactionSignature(from_py_felts(tx.signature)),
            nonce: Nonce(tx.nonce.0),
            sender_address: ContractAddress::try_from(tx.sender_address.0)?,
            calldata: Calldata(Arc::from(from_py_felts(tx.calldata))),
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

pub fn py_invoke_function(py_tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let version = py_attr::<PyFelt>(py_tx, "version")?.0;
    // TODO: Make TransactionVersion an enum and use match here.
    let tx = if version == Felt::ZERO {
        let py_invoke_tx: PyInvokeTransactionV0 = py_tx.extract()?;
        let invoke_tx = InvokeTransactionV0::try_from(py_invoke_tx)?;
        Ok(starknet_api::transaction::InvokeTransaction::V0(invoke_tx))
    } else if version == Felt::ONE {
        let py_invoke_tx: PyInvokeTransactionV1 = py_tx.extract()?;
        let invoke_tx = InvokeTransactionV1::try_from(py_invoke_tx)?;
        Ok(starknet_api::transaction::InvokeTransaction::V1(invoke_tx))
    } else if version == Felt::THREE {
        let py_invoke_tx: PyInvokeTransactionV3 = py_tx.extract()?;
        let invoke_tx = InvokeTransactionV3::try_from(py_invoke_tx)?;
        Ok(starknet_api::transaction::InvokeTransaction::V3(invoke_tx))
    } else {
        Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::InvokeFunction,
            version: version.to_biguint(),
        })
    }?;

    let tx_hash = TransactionHash(py_attr::<PyFelt>(py_tx, "hash_value")?.0);
    Ok(InvokeTransaction::new(tx, tx_hash))
}
