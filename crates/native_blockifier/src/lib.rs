use pyo3::prelude::*;
use starknet_api::calldata;
use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::hash::StarkHash;
use starknet_api::transaction::{
    Calldata, Fee, InvokeTransaction, Transaction, TransactionHash, TransactionSignature,
    TransactionVersion,
};

fn create_invoke_function_from_python(tx: &PyAny) -> PyResult<InvokeTransaction> {
    let transaction_hash =
        TransactionHash(StarkHash::new(tx.getattr("hash_value")?.extract()?).unwrap());
    Ok(InvokeTransaction {
        transaction_hash,
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion::default(),
        signature: TransactionSignature::default(),
        nonce: Nonce::default(),
        sender_address: ContractAddress::default(),
        entry_point_selector: None,
        calldata: calldata![],
    })
}

fn create_transaction_from_python(tx: &PyAny, tx_type: &str) -> PyResult<Transaction> {
    match tx_type {
        "INVOKE_FUNCTION" => Ok(Transaction::Invoke(create_invoke_function_from_python(tx)?)),
        _ => unimplemented!(),
    }
}

#[pyfunction]
fn execute_tx(tx: &PyAny) -> PyResult<()> {
    let tx_type: &str = tx.getattr("tx_type")?.extract()?;
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
