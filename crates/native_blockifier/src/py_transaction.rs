use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::abi::constants::L1_HANDLER_VERSION;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::L1HandlerTransaction;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, Fee, Resource, ResourceBounds, TransactionHash, TransactionVersion,
};

use crate::errors::NativeBlockifierResult;
use crate::py_declare::py_declare;
use crate::py_deploy_account::py_deploy_account;
use crate::py_invoke_function::py_invoke_function;
use crate::py_utils::{from_py_felts, py_attr, PyFelt};

// Structs.

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum PyResource {
    L1Gas,
    L2Gas,
}

impl From<PyResource> for starknet_api::transaction::Resource {
    fn from(py_resource: PyResource) -> Self {
        match py_resource {
            PyResource::L1Gas => starknet_api::transaction::Resource::L1Gas,
            PyResource::L2Gas => starknet_api::transaction::Resource::L2Gas,
        }
    }
}

impl FromPyObject<'_> for PyResource {
    fn extract(resource: &PyAny) -> PyResult<Self> {
        let resource_name: &str = resource.getattr("name")?.extract()?;
        match resource_name {
            "L1_GAS" => Ok(PyResource::L1Gas),
            "L2_GAS" => Ok(PyResource::L2Gas),
            _ => Err(PyValueError::new_err(format!("Invalid resource: {resource_name}"))),
        }
    }
}

#[derive(Clone, Copy, Default, FromPyObject)]
pub struct PyResourceBounds {
    pub max_amount: u64,
    pub max_price_per_unit: u128,
}

impl From<PyResourceBounds> for starknet_api::transaction::ResourceBounds {
    fn from(py_resource_bounds: PyResourceBounds) -> Self {
        Self {
            max_amount: py_resource_bounds.max_amount,
            max_price_per_unit: py_resource_bounds.max_price_per_unit,
        }
    }
}

#[derive(Clone, FromPyObject)]
pub struct PyResourceBoundsMapping(pub BTreeMap<PyResource, PyResourceBounds>);

impl From<PyResourceBoundsMapping> for starknet_api::transaction::ResourceBoundsMapping {
    fn from(py_resource_bounds_mapping: PyResourceBoundsMapping) -> Self {
        let mut resource_bounds_mapping = BTreeMap::new();

        for (py_resource_type, py_resource_bounds) in py_resource_bounds_mapping.0.into_iter() {
            resource_bounds_mapping
                .insert(Resource::from(py_resource_type), ResourceBounds::from(py_resource_bounds));
        }
        Self(resource_bounds_mapping)
    }
}

#[derive(Clone)]
pub enum PyDataAvailabilityMode {
    L1 = 0,
    L2 = 1,
}

impl FromPyObject<'_> for PyDataAvailabilityMode {
    fn extract(data_availability_mode: &PyAny) -> PyResult<Self> {
        let data_availability_mode: u8 = data_availability_mode.extract()?;
        match data_availability_mode {
            0 => Ok(PyDataAvailabilityMode::L1),
            1 => Ok(PyDataAvailabilityMode::L2),
            _ => Err(PyValueError::new_err(format!(
                "Invalid data availability mode: {data_availability_mode}"
            ))),
        }
    }
}

impl From<PyDataAvailabilityMode> for starknet_api::data_availability::DataAvailabilityMode {
    fn from(py_data_availability_mode: PyDataAvailabilityMode) -> Self {
        match py_data_availability_mode {
            PyDataAvailabilityMode::L1 => starknet_api::data_availability::DataAvailabilityMode::L1,
            PyDataAvailabilityMode::L2 => starknet_api::data_availability::DataAvailabilityMode::L2,
        }
    }
}

// Utils.

fn py_calldata(tx: &PyAny, attr: &str) -> NativeBlockifierResult<Calldata> {
    let py_calldata: Vec<PyFelt> = py_attr(tx, attr)?;
    let calldata: Vec<StarkFelt> = from_py_felts(py_calldata);
    Ok(Calldata(Arc::from(calldata)))
}

// Transactions creation.

pub fn py_l1_handler(
    tx: &PyAny,
) -> NativeBlockifierResult<starknet_api::transaction::L1HandlerTransaction> {
    Ok(starknet_api::transaction::L1HandlerTransaction {
        version: TransactionVersion(StarkFelt::from(L1_HANDLER_VERSION)),
        nonce: Nonce(py_attr::<PyFelt>(tx, "nonce")?.0),
        contract_address: ContractAddress::try_from(py_attr::<PyFelt>(tx, "contract_address")?.0)?,
        entry_point_selector: EntryPointSelector(py_attr::<PyFelt>(tx, "entry_point_selector")?.0),
        calldata: py_calldata(tx, "calldata")?,
    })
}

pub fn py_tx(
    tx_type: &str,
    py_tx: &PyAny,
    raw_contract_class: Option<&str>,
) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let raw_contract_class: &str = raw_contract_class
                .expect("A contract class must be passed in a Declare transaction.");
            let declare_tx = AccountTransaction::Declare(py_declare(py_tx, raw_contract_class)?);
            Ok(Transaction::AccountTransaction(declare_tx))
        }
        "DEPLOY_ACCOUNT" => {
            let deploy_account_tx = AccountTransaction::DeployAccount(py_deploy_account(py_tx)?);
            Ok(Transaction::AccountTransaction(deploy_account_tx))
        }
        "INVOKE_FUNCTION" => {
            let invoke_tx = AccountTransaction::Invoke(py_invoke_function(py_tx)?);
            Ok(Transaction::AccountTransaction(invoke_tx))
        }
        "L1_HANDLER" => {
            let paid_fee_on_l1: Option<u128> = py_attr(py_tx, "paid_fee_on_l1")?;
            let paid_fee_on_l1 = Fee(paid_fee_on_l1.unwrap_or_default());
            let l1_handler_tx = py_l1_handler(py_tx)?;
            let tx_hash = TransactionHash(py_attr::<PyFelt>(py_tx, "hash_value")?.0);
            Ok(Transaction::L1HandlerTransaction(L1HandlerTransaction {
                tx: l1_handler_tx,
                tx_hash,
                paid_fee_on_l1,
            }))
        }
        _ => unimplemented!(),
    }
}
