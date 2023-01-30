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

use crate::NativeBlockifierResult;

fn biguint_to_felt(biguint: BigUint) -> NativeBlockifierResult<StarkFelt> {
    let biguint_hex = format!("{biguint:#x}");
    let biguint_hex = biguint_hex.as_str();
    Ok(StarkFelt::try_from(biguint_hex)?)
}

fn py_felt_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<StarkFelt> {
    biguint_to_felt(obj.getattr(attr)?.extract()?)
}

fn py_felt_sequence_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<Vec<StarkFelt>> {
    let raw_felts = obj.getattr(attr)?.extract::<Vec<BigUint>>()?;
    raw_felts.into_iter().map(biguint_to_felt).collect()
}

pub fn invoke_function_from_python(tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let entry_point_selector: Option<&PyAny> = tx.getattr("entry_point_selector")?.extract()?;
    let entry_point_selector = if let Some(selector) = entry_point_selector {
        Some(EntryPointSelector(biguint_to_felt(selector.extract()?)?))
    } else {
        None
    };

    Ok(InvokeTransaction {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        signature: TransactionSignature(py_felt_sequence_attr(tx, "signature")?),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        sender_address: ContractAddress(
            PatriciaKey::try_from(py_felt_attr(tx, "sender_address")?).unwrap(),
        ),
        entry_point_selector,
        calldata: Calldata(Arc::from(py_felt_sequence_attr(tx, "calldata")?)),
    })
}

pub fn tx_from_python(tx: &PyAny, tx_type: &str) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "INVOKE_FUNCTION" => {
            let invoke_tx = AccountTransaction::Invoke(invoke_function_from_python(tx)?);
            Ok(Transaction::AccountTransaction(invoke_tx))
        }
        _ => unimplemented!(),
    }
}
