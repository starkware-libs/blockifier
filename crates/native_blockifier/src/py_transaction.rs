use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_api::core::{ContractAddress, EntryPointSelector, Nonce, PatriciaKey};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransaction, TransactionHash, TransactionSignature, TransactionVersion,
};

pub fn biguint_to_felt(biguint: BigUint) -> StarkFelt {
    let biguint_hex = format!("{biguint:#x}");
    StarkFelt::try_from(biguint_hex.as_str()).unwrap()
}

pub fn get_py_felt_attr(obj: &PyAny, attr: &str) -> PyResult<StarkFelt> {
    Ok(biguint_to_felt(obj.getattr(attr)?.extract()?))
}

pub fn get_py_felt_sequence_attr(obj: &PyAny, attr: &str) -> PyResult<Vec<StarkFelt>> {
    Ok(obj.getattr(attr)?.extract::<Vec<BigUint>>()?.into_iter().map(biguint_to_felt).collect())
}

pub fn create_invoke_function_from_python(tx: &PyAny) -> PyResult<InvokeTransaction> {
    let entry_point_selector: Option<&PyAny> = tx.getattr("entry_point_selector")?.extract()?;
    let entry_point_selector = if let Some(selector) = entry_point_selector {
        Some(EntryPointSelector(biguint_to_felt(selector.extract()?)))
    } else {
        None
    };
    Ok(InvokeTransaction {
        transaction_hash: TransactionHash(get_py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion(get_py_felt_attr(tx, "version")?),
        signature: TransactionSignature(get_py_felt_sequence_attr(tx, "signature")?),
        nonce: Nonce(get_py_felt_attr(tx, "nonce")?),
        sender_address: ContractAddress(
            PatriciaKey::try_from(get_py_felt_attr(tx, "sender_address")?).unwrap(),
        ),
        entry_point_selector,
        calldata: Calldata(Arc::from(get_py_felt_sequence_attr(tx, "calldata")?)),
    })
}

pub fn create_transaction_from_python(tx: &PyAny, tx_type: &str) -> PyResult<Transaction> {
    match tx_type {
        "INVOKE_FUNCTION" => Ok(Transaction::AccountTransaction(AccountTransaction::Invoke(
            create_invoke_function_from_python(tx)?,
        ))),
        _ => unimplemented!(),
    }
}
