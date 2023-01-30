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

fn biguint_to_felt(biguint: BigUint) -> StarkFelt {
    let biguint_hex = format!("{biguint:#x}");
    StarkFelt::try_from(biguint_hex.as_str()).unwrap()
}

fn create_invoke_function_from_python(tx: &PyAny) -> PyResult<InvokeTransaction> {
    let signature = TransactionSignature(
        tx.getattr("signature")?
            .extract::<Vec<BigUint>>()?
            .into_iter()
            .map(biguint_to_felt)
            .collect(),
    );
    let calldata = Calldata(Arc::from(
        tx.getattr("calldata")?
            .extract::<Vec<BigUint>>()?
            .into_iter()
            .map(biguint_to_felt)
            .collect::<Vec<StarkFelt>>(),
    ));
    let entry_point_selector: Option<&PyAny> = tx.getattr("entry_point_selector")?.extract()?;
    let entry_point_selector = if let Some(selector) = entry_point_selector {
        Some(EntryPointSelector(biguint_to_felt(selector.extract()?)))
    } else {
        None
    };
    Ok(InvokeTransaction {
        transaction_hash: TransactionHash(biguint_to_felt(tx.getattr("hash_value")?.extract()?)),
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion(biguint_to_felt(tx.getattr("version")?.extract()?)),
        signature,
        nonce: Nonce(biguint_to_felt(tx.getattr("nonce")?.extract()?)),
        sender_address: ContractAddress(
            PatriciaKey::try_from(biguint_to_felt(tx.getattr("sender_address")?.extract()?))
                .unwrap(),
        ),
        entry_point_selector,
        calldata,
    })
}

fn create_transaction_from_python(tx: &PyAny, tx_type: &str) -> PyResult<Transaction> {
    match tx_type {
        "INVOKE_FUNCTION" => Ok(Transaction::AccountTransaction(AccountTransaction::Invoke(
            create_invoke_function_from_python(tx)?,
        ))),
        _ => unimplemented!(),
    }
}

#[pyfunction]
fn execute_tx(tx: &PyAny) -> PyResult<()> {
    let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
    let _tx = create_transaction_from_python(tx, tx_type)?;
    Ok(())
}

#[pyfunction]
fn hello_world() {
    println!("Hello from rust.");
}

#[pyfunction]
fn test_ret_value(x: i32, y: i32) -> i32 {
    x + y
}

#[pymodule]
fn native_blockifier(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    m.add_function(wrap_pyfunction!(test_ret_value, m)?)?;
    m.add_function(wrap_pyfunction!(execute_tx, m)?)?;

    Ok(())
}
