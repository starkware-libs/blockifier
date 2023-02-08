use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::DictStateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transaction_execution::Transaction;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeployAccountTransaction, Fee,
    InvokeTransaction, L1HandlerTransaction, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::{NativeBlockifierError, NativeBlockifierResult};

/// Common fields used in all account transactions.
#[derive(Debug)]
pub struct AccountDataContext {
    pub transaction_hash: TransactionHash,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub sender_address: ContractAddress,
}

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

pub fn account_data_context_from_python(tx: &PyAny) -> NativeBlockifierResult<AccountDataContext> {
    Ok(AccountDataContext {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(tx.getattr("max_fee")?.extract()?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        signature: TransactionSignature(py_felt_sequence_attr(tx, "signature")?),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        sender_address: ContractAddress::try_from(py_felt_attr(tx, "sender_address")?)?,
    })
}

pub fn declare_from_python(tx: &PyAny) -> NativeBlockifierResult<DeclareTransaction> {
    let account_data_context = account_data_context_from_python(tx)?;

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

pub fn deploy_account_from_python(tx: &PyAny) -> NativeBlockifierResult<DeployAccountTransaction> {
    let account_data_context = account_data_context_from_python(tx)?;

    Ok(DeployAccountTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash: ClassHash(py_felt_attr(tx, "class_hash")?),
        contract_address: account_data_context.sender_address,
        contract_address_salt: ContractAddressSalt(py_felt_attr(tx, "contract_address_salt")?),
        constructor_calldata: Calldata(Arc::from(py_felt_sequence_attr(
            tx,
            "constructor_calldata",
        )?)),
    })
}

pub fn invoke_function_from_python(tx: &PyAny) -> NativeBlockifierResult<InvokeTransaction> {
    let entry_point_selector: Option<BigUint> = tx.getattr("entry_point_selector")?.extract()?;
    let entry_point_selector = if let Some(selector) = entry_point_selector {
        Some(EntryPointSelector(biguint_to_felt(selector)?))
    } else {
        None
    };
    let account_data_context = account_data_context_from_python(tx)?;

    Ok(InvokeTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        sender_address: account_data_context.sender_address,
        entry_point_selector,
        calldata: Calldata(Arc::from(py_felt_sequence_attr(tx, "calldata")?)),
    })
}

pub fn l1_handler_from_python(tx: &PyAny) -> NativeBlockifierResult<L1HandlerTransaction> {
    Ok(L1HandlerTransaction {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        version: TransactionVersion(py_felt_attr(tx, "version")?),
        nonce: Nonce(py_felt_attr(tx, "nonce")?),
        contract_address: ContractAddress::try_from(py_felt_attr(tx, "contract_address")?)?,
        entry_point_selector: EntryPointSelector(py_felt_attr(tx, "entry_point_selector")?),
        calldata: Calldata(Arc::from(py_felt_sequence_attr(tx, "calldata")?)),
    })
}

pub fn tx_from_python(tx: &PyAny, tx_type: &str) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let declare_tx = AccountTransaction::Declare(declare_from_python(tx)?);
            Ok(Transaction::AccountTransaction(declare_tx))
        }
        "DEPLOY_ACCOUNT" => {
            let deploy_account_tx =
                AccountTransaction::DeployAccount(deploy_account_from_python(tx)?);
            Ok(Transaction::AccountTransaction(deploy_account_tx))
        }
        "INVOKE_FUNCTION" => {
            let invoke_tx = AccountTransaction::Invoke(invoke_function_from_python(tx)?);
            Ok(Transaction::AccountTransaction(invoke_tx))
        }
        "L1_HANDLER" => {
            let l1_handler_tx = l1_handler_from_python(tx)?;
            Ok(Transaction::L1HandlerTransaction(l1_handler_tx))
        }
        _ => unimplemented!(),
    }
}

#[pyclass]
pub struct PyTransactionExecutor {
    pub state: CachedState<DictStateReader>,
    pub block_context: BlockContext,
}

#[allow(clippy::new_without_default)]
#[pymethods]
impl PyTransactionExecutor {
    #[new]
    pub fn new(general_config: &PyAny, block_info: &PyAny) -> NativeBlockifierResult<Self> {
        // TODO: Use Papyrus storage as state reader.
        let state = CachedState::new(DictStateReader::default());

        let starknet_os_config = general_config.getattr("starknet_os_config")?;
        let chain_id =
            starknet_os_config.getattr("starknet_os_config")?.getattr("name")?.extract()?;
        let block_context = BlockContext {
            chain_id: ChainId(chain_id),
            block_number: BlockNumber(block_info.getattr("block_number")?.extract()?),
            block_timestamp: BlockTimestamp(block_info.getattr("block_timestamp")?.extract()?),
            sequencer_address: ContractAddress::try_from(py_felt_attr(
                general_config,
                "sequencer_address",
            )?)?,
            fee_token_address: ContractAddress::try_from(py_felt_attr(
                starknet_os_config,
                "fee_token_address",
            )?)?,
            cairo_resource_fee_weights: general_config
                .getattr("cairo_resource_fee_weights")?
                .extract()?,
            invoke_tx_max_n_steps: general_config.getattr("invoke_tx_max_n_steps")?.extract()?,
            validate_max_n_steps: general_config.getattr("validate_max_n_steps")?.extract()?,
        };
        Ok(Self { state, block_context })
    }

    pub fn execute(&mut self, tx: &PyAny) -> PyResult<()> {
        let tx_type: &str = tx.getattr("tx_type")?.getattr("name")?.extract()?;
        let tx = tx_from_python(tx, tx_type)?;
        tx.execute(&mut self.state, &self.block_context).map_err(NativeBlockifierError::from)?;
        Ok(())
    }
}
