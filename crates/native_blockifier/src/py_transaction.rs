use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::abi::constants::L1_HANDLER_VERSION;
use blockifier::execution::contract_class::{ContractClassV0, ContractClassV1};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::{
    DeclareTransaction, DeployAccountTransaction, InvokeTransaction, L1HandlerTransaction,
};
use num_bigint::BigUint;
use pyo3::prelude::*;
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
use crate::py_utils::{biguint_to_felt, py_attr, PyFelt};

fn py_calldata(tx: &PyAny, attr: &str) -> NativeBlockifierResult<Calldata> {
    let py_call: Vec<PyFelt> = py_attr(tx, attr)?;
    let call: Vec<StarkFelt> = py_call.into_iter().map(|felt| felt.0).collect();
    Ok(Calldata(Arc::from(call)))
}

pub fn py_account_data_context(tx: &PyAny) -> NativeBlockifierResult<AccountTransactionContext> {
    let nonce: Option<BigUint> = py_attr(tx, "nonce")?;
    let nonce = Nonce(biguint_to_felt(nonce.unwrap_or_default())?);
    let py_signature: Vec<PyFelt> = py_attr(tx, "signature")?;
    let signature: Vec<StarkFelt> = py_signature.into_iter().map(|felt| felt.0).collect();
    Ok(AccountTransactionContext {
        transaction_hash: TransactionHash(py_attr::<PyFelt>(tx, "hash_value")?.0),
        max_fee: Fee(py_attr(tx, "max_fee")?),
        signature: TransactionSignature(signature),
        version: TransactionVersion(py_attr::<PyFelt>(tx, "version")?.0),
        nonce,
        sender_address: ContractAddress::try_from(py_attr::<PyFelt>(tx, "sender_address")?.0)?,
    })
}

pub fn py_declare(
    tx: &PyAny,
    raw_contract_class: &str,
) -> NativeBlockifierResult<DeclareTransaction> {
    let account_data_context = py_account_data_context(tx)?;
    let class_hash = ClassHash(py_attr::<PyFelt>(tx, "class_hash")?.0);
    let version = usize::try_from(account_data_context.version.0)?;
    let sn_api_tx = match version {
        0 => {
            let declare_tx = DeclareTransactionV0V1 {
                max_fee: account_data_context.max_fee,
                signature: account_data_context.signature,
                nonce: account_data_context.nonce,
                class_hash,
                sender_address: account_data_context.sender_address,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V0(declare_tx))
        }
        1 => {
            let declare_tx = DeclareTransactionV0V1 {
                max_fee: account_data_context.max_fee,
                signature: account_data_context.signature,
                nonce: account_data_context.nonce,
                class_hash,
                sender_address: account_data_context.sender_address,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V1(declare_tx))
        }
        2 => {
            let compiled_class_hash =
                CompiledClassHash(py_attr::<PyFelt>(tx, "compiled_class_hash")?.0);
            let declare_tx = DeclareTransactionV2 {
                max_fee: account_data_context.max_fee,
                signature: account_data_context.signature,
                nonce: account_data_context.nonce,
                class_hash,
                sender_address: account_data_context.sender_address,
                compiled_class_hash,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V2(declare_tx))
        }
        _ => Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::Declare,
            version,
        }),
    }?;

    let contract_class = match sn_api_tx {
        starknet_api::transaction::DeclareTransaction::V0(_)
        | starknet_api::transaction::DeclareTransaction::V1(_) => {
            ContractClassV0::try_from_json_string(raw_contract_class)?.into()
        }
        starknet_api::transaction::DeclareTransaction::V2(_) => {
            ContractClassV1::try_from_json_string(raw_contract_class)?.into()
        }
    };

    Ok(DeclareTransaction::new(sn_api_tx, account_data_context.transaction_hash, contract_class)?)
}

pub fn py_deploy_account(tx: &PyAny) -> NativeBlockifierResult<DeployAccountTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    let tx = starknet_api::transaction::DeployAccountTransaction {
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash: ClassHash(py_attr::<PyFelt>(tx, "class_hash")?.0),
        contract_address_salt: ContractAddressSalt(
            py_attr::<PyFelt>(tx, "contract_address_salt")?.0,
        ),
        constructor_calldata: py_calldata(tx, "constructor_calldata")?,
    };
    Ok(DeployAccountTransaction {
        tx,
        tx_hash: account_data_context.transaction_hash,
        contract_address: account_data_context.sender_address,
    })
}

pub fn py_invoke_function(tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let account_data_context = py_account_data_context(tx)?;

    let version = usize::try_from(account_data_context.version.0)?;
    let sn_api_tx = match version {
        0 => Ok(starknet_api::transaction::InvokeTransaction::V0(InvokeTransactionV0 {
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            contract_address: account_data_context.sender_address,
            entry_point_selector: EntryPointSelector(
                py_attr::<PyFelt>(tx, "entry_point_selector")?.0,
            ),
            calldata: py_calldata(tx, "calldata")?,
        })),
        1 => Ok(starknet_api::transaction::InvokeTransaction::V1(InvokeTransactionV1 {
            max_fee: account_data_context.max_fee,
            signature: account_data_context.signature,
            nonce: account_data_context.nonce,
            sender_address: account_data_context.sender_address,
            calldata: py_calldata(tx, "calldata")?,
        })),
        _ => Err(NativeBlockifierInputError::UnsupportedTransactionVersion {
            tx_type: TransactionType::InvokeFunction,
            version,
        }),
    }?;

    Ok(InvokeTransaction { tx: sn_api_tx, tx_hash: account_data_context.transaction_hash })
}

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
    tx: &PyAny,
    raw_contract_class: Option<&str>,
) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let raw_contract_class: &str = raw_contract_class
                .expect("A contract class must be passed in a Declare transaction.");
            let declare_tx = AccountTransaction::Declare(py_declare(tx, raw_contract_class)?);
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
            let paid_fee_on_l1: Option<u128> = py_attr(tx, "paid_fee_on_l1")?;
            let paid_fee_on_l1 = Fee(paid_fee_on_l1.unwrap_or_default());
            let l1_handler_tx = py_l1_handler(tx)?;
            let tx_hash = TransactionHash(py_attr::<PyFelt>(tx, "hash_value")?.0);
            Ok(Transaction::L1HandlerTransaction(L1HandlerTransaction {
                tx: l1_handler_tx,
                tx_hash,
                paid_fee_on_l1,
            }))
        }
        _ => unimplemented!(),
    }
}
