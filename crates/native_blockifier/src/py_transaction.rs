use std::collections::{BTreeMap, HashMap};

use blockifier::fee::actual_cost::ActualCost;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::ResourcesMapping;
use blockifier::transaction::transaction_execution::Transaction;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use starknet_api::transaction::{Fee, Resource, ResourceBounds};
use starknet_api::StarknetApiError;

use crate::errors::NativeBlockifierResult;
use crate::py_declare::py_declare;
use crate::py_deploy_account::py_deploy_account;
use crate::py_invoke_function::py_invoke_function;
use crate::py_l1_handler::py_l1_handler;

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

impl TryFrom<PyResourceBoundsMapping> for starknet_api::transaction::ResourceBoundsMapping {
    type Error = StarknetApiError;
    fn try_from(py_resource_bounds_mapping: PyResourceBoundsMapping) -> Result<Self, Self::Error> {
        Self::try_from(
            py_resource_bounds_mapping
                .0
                .into_iter()
                .map(|(py_resource_type, py_resource_bounds)| {
                    (Resource::from(py_resource_type), ResourceBounds::from(py_resource_bounds))
                })
                .collect::<Vec<_>>(),
        )
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

// TODO(Noa, 20/11/23): Remove when the validate method of `Pyvalidator` is no longer externalized
// to Python.
#[pyclass]
#[derive(Clone, Default)]
pub struct PyActualCost {
    #[pyo3(get)]
    pub actual_fee: u128,
    #[pyo3(get)]
    pub actual_resources: HashMap<String, usize>,
}

impl From<ActualCost> for PyActualCost {
    fn from(actual_cost: ActualCost) -> Self {
        Self {
            actual_fee: actual_cost.actual_fee.0,
            actual_resources: actual_cost.actual_resources.0,
        }
    }
}

impl From<PyActualCost> for ActualCost {
    fn from(py_actual_cost: PyActualCost) -> Self {
        Self {
            actual_fee: Fee(py_actual_cost.actual_fee),
            actual_resources: ResourcesMapping(py_actual_cost.actual_resources),
        }
    }
}

// Transactions creation.

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
        "L1_HANDLER" => Ok(Transaction::L1HandlerTransaction(py_l1_handler(py_tx)?)),
        _ => unimplemented!(),
    }
}
