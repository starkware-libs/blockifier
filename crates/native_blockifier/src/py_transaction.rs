use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::DictStateReader;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
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

use crate::py_state_diff::PyStateDiff;
use crate::py_transaction_execution_info::PyTransactionExecutionInfo;
use crate::py_utils::biguint_to_felt;
use crate::{NativeBlockifierError, NativeBlockifierResult};

fn py_attr<T>(obj: &PyAny, attr: &str) -> NativeBlockifierResult<T>
where
    T: for<'a> FromPyObject<'a>,
    T: Clone,
{
    Ok(obj.getattr(attr)?.extract()?)
}

fn py_enum_name<T>(obj: &PyAny, attr: &str) -> NativeBlockifierResult<T>
where
    T: for<'a> FromPyObject<'a>,
    T: Clone,
    T: ToString,
{
    py_attr(obj.getattr(attr)?, "name")
}

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
    Ok(AccountTransactionContext {
        transaction_hash: TransactionHash(py_felt_attr(tx, "hash_value")?),
        max_fee: Fee(py_attr(tx, "max_fee")?),
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
    let entry_point_selector: Option<BigUint> = py_attr(tx, "entry_point_selector")?;
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

pub fn py_tx(
    tx_type: &str,
    tx: &PyAny,
    contract_class: Option<&str>,
) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let contract_class: &str =
                contract_class.expect("A contract class must be passed in a Declare transaction.");
            let contract_class: ContractClass =
                serde_json::from_str(contract_class).expect("Illegal class schema from Python.");
            let declare_tx = AccountTransaction::Declare(py_declare(tx)?, contract_class);
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

#[pyclass]
pub struct PyTransactionExecutor {
    pub state: CachedState<DictStateReader>,
    pub block_context: BlockContext,
}

#[pymethods]
impl PyTransactionExecutor {
    #[new]
    #[args(general_config, block_info)]
    pub fn new(general_config: &PyAny, block_info: &PyAny) -> NativeBlockifierResult<Self> {
        // TODO: Use Papyrus storage as state reader.
        let state = CachedState::new(DictStateReader::default());

        let starknet_os_config = general_config.getattr("starknet_os_config")?;
        let block_context = BlockContext {
            chain_id: ChainId(py_enum_name(starknet_os_config, "chain_id")?),
            block_number: BlockNumber(py_attr(block_info, "block_number")?),
            block_timestamp: BlockTimestamp(py_attr(block_info, "block_timestamp")?),
            sequencer_address: ContractAddress::try_from(py_felt_attr(
                general_config,
                "sequencer_address",
            )?)?,
            fee_token_address: ContractAddress::try_from(py_felt_attr(
                starknet_os_config,
                "fee_token_address",
            )?)?,
            cairo_resource_fee_weights: py_attr(general_config, "cairo_resource_fee_weights")?,
            invoke_tx_max_n_steps: py_attr(general_config, "invoke_tx_max_n_steps")?,
            validate_max_n_steps: py_attr(general_config, "validate_max_n_steps")?,
        };

        Ok(Self { state, block_context })
    }

    #[args(tx)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        contract_class: Option<&str>,
    ) -> PyResult<(PyStateDiff, PyTransactionExecutionInfo)> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, contract_class)?;
        let (state_diff, tx_execution_info) = tx
            .execute(&mut self.state, &self.block_context)
            .map_err(NativeBlockifierError::from)?;
        Ok((PyStateDiff::from(state_diff), PyTransactionExecutionInfo::from(tx_execution_info)))
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self) -> PyStateDiff {
        PyStateDiff::from(self.state.to_state_diff())
    }
}
