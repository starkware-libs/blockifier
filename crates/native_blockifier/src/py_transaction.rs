use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::CachedState;
use blockifier::state::papyrus_state::PapyrusStateReader;
use blockifier::state::state_api::State;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use num_bigint::BigUint;
use ouroboros;
use papyrus_storage::db::RO;
use papyrus_storage::state::StateStorageReader;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeployAccountTransaction, Fee,
    InvokeTransaction, L1HandlerTransaction, TransactionHash, TransactionSignature,
    TransactionVersion,
};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_state_diff::PyStateDiff;
use crate::py_transaction_execution_info::PyTransactionExecutionInfo;
use crate::py_utils::{biguint_to_felt, to_chain_id_enum};
use crate::storage::Storage;

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
    let account_data_context = py_account_data_context(tx)?;

    Ok(InvokeTransaction {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        version: account_data_context.version,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        sender_address: account_data_context.sender_address,
        entry_point_selector: None, // Hardcoded `__execute__` selector; set inside execution.
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
    raw_contract_class: Option<&str>,
) -> NativeBlockifierResult<Transaction> {
    match tx_type {
        "DECLARE" => {
            let raw_contract_class: &str = raw_contract_class
                .expect("A contract class must be passed in a Declare transaction.");
            let contract_class: ContractClass = serde_json::from_str(raw_contract_class)
                .expect("Illegal class schema from Python.");
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
// To access a field you must use `self.borrow_{field_name}()`.
// Alternately, you can borrow the whole object using `self.with[_mut]()`.
#[ouroboros::self_referencing]
pub struct PyTransactionExecutor {
    pub block_context: BlockContext,

    // State-related fields.
    // Storage reader and transaction are kept merely for lifetime parameter referencing.
    pub storage_reader: papyrus_storage::StorageReader,
    #[borrows(storage_reader)]
    #[covariant]
    pub storage_tx: papyrus_storage::StorageTxn<'this, RO>,
    #[borrows(storage_tx)]
    #[covariant]
    pub state: CachedState<PapyrusStateReader<'this, RO>>,
}

#[pymethods]
impl PyTransactionExecutor {
    #[new]
    #[args(general_config, block_info, storage_path, max_size)]
    pub fn create(
        general_config: &PyAny,
        block_info: &PyAny,
        storage_path: String,
        max_size: usize,
    ) -> NativeBlockifierResult<Self> {
        // Build block context.
        let starknet_os_config = general_config.getattr("starknet_os_config")?;
        let block_number = BlockNumber(py_attr(block_info, "block_number")?);
        let block_context = BlockContext {
            chain_id: to_chain_id_enum(py_attr(starknet_os_config, "chain_id")?)?,
            block_number,
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

        // Build Papyrus reader-based state.
        let Storage { reader, writer: _ } = Storage::new(storage_path, max_size)?;

        // The following callbacks are required to capture the local lifetime parameter.
        fn storage_tx_builder(
            storage_reader: &papyrus_storage::StorageReader,
        ) -> NativeBlockifierResult<papyrus_storage::StorageTxn<'_, RO>> {
            Ok(storage_reader.begin_ro_txn()?)
        }

        fn state_builder<'a>(
            storage_tx: &'a papyrus_storage::StorageTxn<'a, RO>,
            block_number: BlockNumber,
        ) -> NativeBlockifierResult<CachedState<PapyrusStateReader<'a, RO>>> {
            let state_reader = storage_tx.get_state_reader()?;
            let papyrus_reader = PapyrusStateReader::new(state_reader, block_number);
            Ok(CachedState::new(papyrus_reader))
        }

        // The builder struct below is implicitly created by `ouroboros`.
        let py_tx_executor_builder = PyTransactionExecutorTryBuilder {
            block_context,
            storage_reader: reader,
            storage_tx_builder,
            state_builder: |storage_tx| state_builder(storage_tx, block_number),
        };
        py_tx_executor_builder.try_build()
    }

    #[args(tx, raw_contract_class)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
    ) -> PyResult<PyTransactionExecutionInfo> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, raw_contract_class)?;
        let tx_execution_info = self.with_mut(|executor| {
            tx.execute(executor.state, executor.block_context).map_err(NativeBlockifierError::from)
        })?;

        Ok(PyTransactionExecutionInfo::from(tx_execution_info))
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self) -> PyStateDiff {
        PyStateDiff::from(self.borrow_state().to_state_diff())
    }
}
