use std::collections::BTreeMap;

use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
<<<<<<< HEAD
use pyo3::exceptions::PyValueError;
||||||| 830a236
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::{DeclareTransaction, L1HandlerTransaction};
use num_bigint::BigUint;
=======
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, InvokeTransaction, L1HandlerTransaction,
};
use num_bigint::BigUint;
>>>>>>> origin/main-v0.12.3
use pyo3::prelude::*;
<<<<<<< HEAD
use starknet_api::transaction::{Resource, ResourceBounds};

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
||||||| 830a236
use starknet_api::core::{
    ClassHash, CompiledClassHash, ContractAddress, EntryPointSelector, Nonce,
};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeclareTransactionV2,
    DeployAccountTransaction, Fee, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1,
    TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_utils::{biguint_to_felt, py_attr};

fn py_felt_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<StarkFelt> {
    biguint_to_felt(py_attr(obj, attr)?)
=======
use starknet_api::core::{
    ClassHash, CompiledClassHash, ContractAddress, EntryPointSelector, Nonce,
};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeclareTransactionV2, Fee,
    InvokeTransactionV0, InvokeTransactionV1, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_utils::{biguint_to_felt, py_attr};

fn py_felt_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<StarkFelt> {
    biguint_to_felt(py_attr(obj, attr)?)
>>>>>>> origin/main-v0.12.3
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

<<<<<<< HEAD
#[derive(Clone)]
pub enum PyDataAvailabilityMode {
    L1 = 0,
    L2 = 1,
||||||| 830a236
pub fn py_deploy_account(tx: &PyAny) -> NativeBlockifierResult<DeployAccountTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    Ok(DeployAccountTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash: ClassHash(py_felt_attr(tx, "class_hash")?),
        contract_address: account_data_context.sender_address,
        contract_address_salt: ContractAddressSalt(py_felt_attr(tx, "contract_address_salt")?),
        constructor_calldata: py_calldata(tx, "constructor_calldata")?,
    })
=======
pub fn py_deploy_account(
    tx: &PyAny,
) -> NativeBlockifierResult<starknet_api::transaction::DeployAccountTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    Ok(starknet_api::transaction::DeployAccountTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash: ClassHash(py_felt_attr(tx, "class_hash")?),
        contract_address: account_data_context.sender_address,
        contract_address_salt: ContractAddressSalt(py_felt_attr(tx, "contract_address_salt")?),
        constructor_calldata: py_calldata(tx, "constructor_calldata")?,
    })
>>>>>>> origin/main-v0.12.3
}

<<<<<<< HEAD
impl FromPyObject<'_> for PyDataAvailabilityMode {
    fn extract(data_availability_mode: &PyAny) -> PyResult<Self> {
        let data_availability_mode: u8 = data_availability_mode.extract()?;
        match data_availability_mode {
            0 => Ok(PyDataAvailabilityMode::L1),
            1 => Ok(PyDataAvailabilityMode::L2),
            _ => Err(PyValueError::new_err(format!(
                "Invalid data availability mode: {data_availability_mode}"
            ))),
||||||| 830a236
pub fn py_invoke_function(tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    let version = usize::try_from(account_data_context.version.0)?;
    match version {
        0 => Ok(InvokeTransaction::V0(InvokeTransactionV0 {
            transaction_hash: account_data_context.transaction_hash,
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            nonce: account_data_context.nonce,
            sender_address: account_data_context.sender_address,
            entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
            calldata: py_calldata(tx, "calldata")?,
        })),
        1 => Ok(InvokeTransaction::V1(InvokeTransactionV1 {
            transaction_hash: account_data_context.transaction_hash,
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            nonce: account_data_context.nonce,
            sender_address: account_data_context.sender_address,
            calldata: py_calldata(tx, "calldata")?,
        })),
        _ => Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::InvokeFunction,
            version,
=======
pub fn py_invoke_function(
    tx: &PyAny,
) -> NativeBlockifierResult<starknet_api::transaction::InvokeTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    let version = usize::try_from(account_data_context.version.0)?;
    match version {
        0 => Ok(starknet_api::transaction::InvokeTransaction::V0(InvokeTransactionV0 {
            transaction_hash: account_data_context.transaction_hash,
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            nonce: account_data_context.nonce,
            sender_address: account_data_context.sender_address,
            entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
            calldata: py_calldata(tx, "calldata")?,
        })),
        1 => Ok(starknet_api::transaction::InvokeTransaction::V1(InvokeTransactionV1 {
            transaction_hash: account_data_context.transaction_hash,
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            nonce: account_data_context.nonce,
            sender_address: account_data_context.sender_address,
            calldata: py_calldata(tx, "calldata")?,
        })),
        _ => Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::InvokeFunction,
            version,
>>>>>>> origin/main-v0.12.3
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
<<<<<<< HEAD
            let deploy_account_tx = AccountTransaction::DeployAccount(py_deploy_account(py_tx)?);
||||||| 830a236
            let deploy_account_tx = AccountTransaction::DeployAccount(py_deploy_account(tx)?);
=======
            let deploy_account_tx = AccountTransaction::DeployAccount(DeployAccountTransaction {
                tx: py_deploy_account(tx)?,
            });
>>>>>>> origin/main-v0.12.3
            Ok(Transaction::AccountTransaction(deploy_account_tx))
        }
        "INVOKE_FUNCTION" => {
<<<<<<< HEAD
            let invoke_tx = AccountTransaction::Invoke(py_invoke_function(py_tx)?);
||||||| 830a236
            let invoke_tx = AccountTransaction::Invoke(py_invoke_function(tx)?);
=======
            let invoke_tx =
                AccountTransaction::Invoke(InvokeTransaction { tx: py_invoke_function(tx)? });
>>>>>>> origin/main-v0.12.3
            Ok(Transaction::AccountTransaction(invoke_tx))
        }
        "L1_HANDLER" => Ok(Transaction::L1HandlerTransaction(py_l1_handler(py_tx)?)),
        _ => unimplemented!(),
    }
}
