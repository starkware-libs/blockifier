use std::sync::Arc;

use blockifier::abi::constants;
use blockifier::transaction::transactions::L1HandlerTransaction;
use pyo3::prelude::*;
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce};
use starknet_api::transaction::{Calldata, Fee, TransactionHash};

use crate::errors::{NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_utils::{from_py_felts, py_attr, PyFelt};

#[derive(FromPyObject)]
struct PyL1HandlerTransaction {
    pub nonce: PyFelt,
    pub contract_address: PyFelt,
    pub entry_point_selector: PyFelt,
    pub calldata: Vec<PyFelt>,
}

impl TryFrom<PyL1HandlerTransaction> for starknet_api::transaction::L1HandlerTransaction {
    type Error = NativeBlockifierInputError;
    fn try_from(tx: PyL1HandlerTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            version: constants::L1_HANDLER_VERSION,
            nonce: Nonce(tx.nonce.0),
            contract_address: ContractAddress::try_from(tx.contract_address.0)?,
            entry_point_selector: EntryPointSelector(tx.entry_point_selector.0),
            calldata: Calldata(Arc::from(from_py_felts(tx.calldata))),
        })
    }
}

pub fn py_l1_handler(py_tx: &PyAny) -> NativeBlockifierResult<L1HandlerTransaction> {
    let py_l1_handler_tx: PyL1HandlerTransaction = py_tx.extract()?;
    let tx = starknet_api::transaction::L1HandlerTransaction::try_from(py_l1_handler_tx)?;
    let tx_hash = TransactionHash(py_attr::<PyFelt>(py_tx, "hash_value")?.0);
    let paid_fee_on_l1 = Fee(py_attr::<u128>(py_tx, "paid_fee_on_l1")?);

    Ok(L1HandlerTransaction { tx, tx_hash, paid_fee_on_l1 })
}
