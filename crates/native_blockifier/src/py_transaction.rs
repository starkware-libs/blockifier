use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::abi::constants::L1_HANDLER_VERSION;
use blockifier::execution::contract_class::{ContractClassV0, ContractClassV1};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::{DeclareTransaction, L1HandlerTransaction};
use num_bigint::BigUint;
use pyo3::prelude::*;
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
}

fn py_felt_sequence_attr(obj: &PyAny, attr: &str) -> NativeBlockifierResult<Vec<StarkFelt>> {
    let raw_felts: Vec<BigUint> = py_attr(obj, attr)?;
    raw_felts.into_iter().map(biguint_to_felt).collect()
}

fn py_calldata(tx: &PyAny, attr: &str) -> NativeBlockifierResult<Calldata> {
    Ok(Calldata(Arc::from(py_felt_sequence_attr(tx, attr)?)))
}

pub fn py_account_data_context(tx: &PyAny) -> NativeBlockifierResult<AccountTransactionContext> {
    let nonce: Option<BigUint> = py_attr(tx, "nonce")?;
    let nonce = Nonce(biguint_to_felt(nonce.unwrap_or_default())?);
    Ok(AccountTransactionContext {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(py_attr(tx, "max_fee")?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        signature: TransactionSignature(py_felt_sequence_attr(tx, "signature")?),
        nonce,
        sender_address: ContractAddress::try_from(py_felt_attr(tx, "sender_address")?)?,
    })
}

pub fn py_declare(
    tx: &PyAny,
) -> NativeBlockifierResult<starknet_api::transaction::DeclareTransaction> {
    let account_data_context = py_account_data_context(tx)?;
    let class_hash = ClassHash(py_felt_attr(tx, "class_hash")?);

    let version = usize::try_from(account_data_context.version.0)?;

    match version {
        0 => {
            let declare_tx = DeclareTransactionV0V1 {
                transaction_hash: account_data_context.transaction_hash,
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
                transaction_hash: account_data_context.transaction_hash,
                max_fee: account_data_context.max_fee,
                signature: account_data_context.signature,
                nonce: account_data_context.nonce,
                class_hash,
                sender_address: account_data_context.sender_address,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V1(declare_tx))
        }
        2 => {
            let compiled_class_hash = CompiledClassHash(py_felt_attr(tx, "compiled_class_hash")?);
            let declare_tx = DeclareTransactionV2 {
                transaction_hash: account_data_context.transaction_hash,
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
        }
        .into()),
    }
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
        }
        .into()),
    }
}

pub fn py_l1_handler(
    tx: &PyAny,
) -> NativeBlockifierResult<starknet_api::transaction::L1HandlerTransaction> {
    Ok(starknet_api::transaction::L1HandlerTransaction {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        version: TransactionVersion(StarkFelt::from(L1_HANDLER_VERSION)),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        contract_address: ContractAddress::try_from(py_felt_attr(tx, "contract_address")?)?,
        entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
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
            let tx = py_declare(tx)?;
            let raw_contract_class: &str = raw_contract_class
                .expect("A contract class must be passed in a Declare transaction.");
            let contract_class = match tx {
                starknet_api::transaction::DeclareTransaction::V0(_)
                | starknet_api::transaction::DeclareTransaction::V1(_) => {
                    ContractClassV0::try_from_json_string(raw_contract_class)?.into()
                }
                starknet_api::transaction::DeclareTransaction::V2(_) => {
                    ContractClassV1::try_from_json_string(raw_contract_class)?.into()
                }
            };

            let declare_tx =
                AccountTransaction::Declare(DeclareTransaction::new(tx, contract_class)?);
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
            Ok(Transaction::L1HandlerTransaction(L1HandlerTransaction {
                tx: l1_handler_tx,
                paid_fee_on_l1,
            }))
        }
        _ => unimplemented!(),
    }
}
