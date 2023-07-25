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
    AccountParams, Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeclareTransactionV2,
    Fee, InvokeTransactionV0, InvokeTransactionV1, TransactionHash, TransactionSignature,
    TransactionVersion,
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
        account_params: AccountParams {
            max_fee: Fee(py_attr(tx, "max_fee")?),
            signature: TransactionSignature(py_felt_sequence_attr(tx, "signature")?),
            nonce,
        },
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        sender_address: ContractAddress::try_from(py_felt_attr(tx, "sender_address")?)?,
    })
}

pub fn py_declare(
    tx: &PyAny,
    raw_contract_class: &str,
) -> NativeBlockifierResult<DeclareTransaction> {
    let account_data_context = py_account_data_context(tx)?;
    let class_hash = ClassHash(py_felt_attr(tx, "class_hash")?);

    let version = usize::try_from(account_data_context.version.0)?;

    let sn_api_tx = match version {
        0 => {
            let declare_tx = DeclareTransactionV0V1 {
                account_params: account_data_context.account_params,
                class_hash,
                sender_address: account_data_context.sender_address,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V0(declare_tx))
        }
        1 => {
            let declare_tx = DeclareTransactionV0V1 {
                account_params: account_data_context.account_params,
                class_hash,
                sender_address: account_data_context.sender_address,
            };
            Ok(starknet_api::transaction::DeclareTransaction::V1(declare_tx))
        }
        2 => {
            let compiled_class_hash = CompiledClassHash(py_felt_attr(tx, "compiled_class_hash")?);
            let declare_tx = DeclareTransactionV2 {
                account_params: account_data_context.account_params,
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
        account_params: account_data_context.account_params,
        version: account_data_context.version,
        class_hash: ClassHash(py_felt_attr(tx, "class_hash")?),
        contract_address_salt: ContractAddressSalt(py_felt_attr(tx, "contract_address_salt")?),
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
            max_fee: account_data_context.account_params.max_fee,
            signature: account_data_context.account_params.signature,
            contract_address: account_data_context.sender_address,
            entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
            calldata: py_calldata(tx, "calldata")?,
        })),
        1 => Ok(starknet_api::transaction::InvokeTransaction::V1(InvokeTransactionV1 {
            account_params: account_data_context.account_params,
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
            let tx_hash = TransactionHash(py_felt_attr(tx, "hash_value")?);
            Ok(Transaction::L1HandlerTransaction(L1HandlerTransaction {
                tx: l1_handler_tx,
                tx_hash,
                paid_fee_on_l1,
            }))
        }
        _ => unimplemented!(),
    }
}
