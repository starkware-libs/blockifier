use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeployAccountTransaction, Fee,
    InvokeTransaction, L1HandlerTransaction, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::NativeBlockifierResult;

fn biguint_to_felt(biguint: BigUint) -> NativeBlockifierResult<StarkFelt> {
    let biguint_hex = format!("{biguint:#x}");
    Ok(StarkFelt::try_from(&*biguint_hex)?)
}

fn py_felt_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<StarkFelt> {
    biguint_to_felt(obj.getattr(attr)?.extract()?)
}

fn py_felt_sequence_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<Vec<StarkFelt>> {
    let raw_felts = obj.getattr(attr)?.extract::<Vec<BigUint>>()?;
    raw_felts.into_iter().map(biguint_to_felt).collect()
}

fn py_calldata(tx: &PyAny, attr: &str) -> NativeBlockifierResult<Calldata> {
    Ok(Calldata(Arc::from(py_felt_sequence_attr(tx, attr)?)))
}

pub fn py_account_data_context(tx: &PyAny) -> NativeBlockifierResult<AccountTransactionContext> {
    Ok(AccountTransactionContext {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        signature: TransactionSignature(py_felt_sequence_attr(tx, "signature")?),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        sender_address: ContractAddress::try_from(py_felt_attr(tx, "sender_address")?)?,
    })
}

pub fn py_declare(tx: &PyAny) -> NativeBlockifierResult<DeclareTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    Ok(DeclareTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash: ClassHash(py_felt_attr(tx, "class_hash")?),
        sender_address: account_data_context.sender_address,
    })
}

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
}

pub fn py_invoke_function(tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let entry_point_selector: Option<BigUint> = tx.getattr("entry_point_selector")?.extract()?;
    let entry_point_selector = if let Some(selector) = entry_point_selector {
        Some(EntryPointSelector(biguint_to_felt(selector)?))
    } else {
        None
    };
    let account_data_context = py_account_data_context(tx)?;

    Ok(InvokeTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        sender_address: account_data_context.sender_address,
        entry_point_selector,
        calldata: py_calldata(tx, "calldata")?,
    })
}

pub fn py_l1_handler(tx: &PyAny) -> NativeBlockifierResult<L1HandlerTransaction> {
    Ok(L1HandlerTransaction {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        contract_address: ContractAddress::try_from(py_felt_attr(tx, "contract_address")?)?,
        entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
        calldata: py_calldata(tx, "calldata")?,
    })
}

pub fn py_tx(tx: &PyAny, tx_type: &str) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let declare_tx = AccountTransaction::Declare(py_declare(tx)?);
            Ok(Transaction::AccountTransaction(declare_tx))
        }
        "DEPLOY_ACCOUNT" => {
            let deploy_account_tx = AccountTransaction::DeployAccount(py_deploy_account(tx)?);
            Ok(Transaction::AccountTransaction(deploy_account_tx))
        }
        "INVOKE_FUNCTION" => {
            let invoke_tx = AccountTransaction::Invoke(py_invoke_function(tx)?);
            Ok(Transaction::AccountTransaction(invoke_tx))
        }
        "L1_HANDLER" => {
            let l1_handler_tx = py_l1_handler(tx)?;
            Ok(Transaction::L1HandlerTransaction(l1_handler_tx))
        }
        _ => unimplemented!(),
    }
}
