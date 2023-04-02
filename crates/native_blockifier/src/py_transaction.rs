use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::abi::constants::L1_HANDLER_VERSION;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::state::cached_state::{CachedState, MutRefState};
use blockifier::state::papyrus_state::PapyrusStateReader;
use blockifier::state::state_api::State;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::ExecutableTransaction;
use num_bigint::BigUint;
use ouroboros;
use papyrus_storage::db::RO;
use papyrus_storage::state::StateStorageReader;
use pyo3::prelude::*;
use pyo3::types::IntoPyDict;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransaction, DeclareTransactionV0V1,
    DeployAccountTransaction, Fee, InvokeTransactionV1, L1HandlerTransaction, TransactionHash,
    TransactionSignature, TransactionVersion,
};

use crate::errors::{NativeBlockifierError, NativeBlockifierInputError, NativeBlockifierResult};
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

pub fn py_block_context(
    general_config: &PyAny,
    block_info: &PyAny,
) -> NativeBlockifierResult<BlockContext> {
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
        gas_price: py_attr(block_info, "gas_price")?,
        invoke_tx_max_n_steps: py_attr(general_config, "invoke_tx_max_n_steps")?,
        validate_max_n_steps: py_attr(general_config, "validate_max_n_steps")?,
    };

    Ok(block_context)
}

pub fn py_declare(tx: &PyAny) -> NativeBlockifierResult<DeclareTransaction> {
    let account_data_context = py_account_data_context(tx)?;
    let class_hash = ClassHash(py_felt_attr(tx, "class_hash")?);

    let version = usize::try_from(account_data_context.version.0)?;
    let declare_tx = DeclareTransactionV0V1 {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        class_hash,
        sender_address: account_data_context.sender_address,
    };

    match version {
        0 => Ok(DeclareTransaction::V0(declare_tx)),
        1 => Ok(DeclareTransaction::V1(declare_tx)),
        _ => Err(NativeBlockifierError::from(
            NativeBlockifierInputError::UnsupportedTransactionVersion {
                tx_type: TransactionType::Declare,
                version,
            },
        )),
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

pub fn py_invoke_function(tx: &PyAny) -> NativeBlockifierResult<InvokeTransactionV1> {
    let account_data_context = py_account_data_context(tx)?;

    Ok(InvokeTransactionV1 {
        transaction_hash: account_data_context.transaction_hash,
        max_fee: account_data_context.max_fee,
        signature: account_data_context.signature,
        nonce: account_data_context.nonce,
        sender_address: account_data_context.sender_address,
        calldata: py_calldata(tx, "calldata")?,
    })
}

pub fn py_l1_handler(tx: &PyAny) -> NativeBlockifierResult<L1HandlerTransaction> {
    Ok(L1HandlerTransaction {
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

pub fn build_tx_executor(
    block_context: BlockContext,
    storage_reader: papyrus_storage::StorageReader,
) -> NativeBlockifierResult<PyTransactionExecutor> {
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

    let block_number = block_context.block_number;
    // The builder struct below is implicitly created by `ouroboros`.
    let py_tx_executor_builder = PyTransactionExecutorTryBuilder {
        block_context,
        storage_reader,
        storage_tx_builder,
        state_builder: |storage_tx| state_builder(storage_tx, block_number),
    };
    py_tx_executor_builder.try_build()
}

#[pymethods]
impl PyTransactionExecutor {
    #[new]
    #[args(general_config, block_info, papyrus_storage)]
    pub fn create(
        general_config: &PyAny,
        block_info: &PyAny,
        papyrus_storage: &Storage,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");

        // Assumption: storage is aligned.
        let reader = papyrus_storage.reader().clone();

        let block_context = py_block_context(general_config, block_info)?;
        let build_result = build_tx_executor(block_context, reader);
        log::debug!("Initialized Transaction Executor.");

        build_result
    }

    #[args(tx, raw_contract_class, enough_room_for_tx)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add_weights, tx_time_created=tx_written.time_created).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<PyTransactionExecutionInfo> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, raw_contract_class)?;

        let tx_execution_info = self.with_mut(|executor| {
            let mut transactional_state = CachedState::new(MutRefState::new(executor.state));
            let tx_execution_result = tx
                .execute_raw(&mut transactional_state, executor.block_context)
                .map_err(NativeBlockifierError::from);

            // Commit the transaction if and only if it can be added into the batch.
            match &tx_execution_result {
                Ok(tx_execution_info) => {
                    let tx_weights = &tx_execution_info.actual_resources.0;

                    Python::with_gil(|py| {
                        let kwargs = [("tx_weights".to_string(), tx_weights)].into_py_dict(py);
                        match enough_room_for_tx.call((), Some(kwargs)) {
                            Ok(_) => transactional_state.commit(),
                            Err(_tx_too_big) => transactional_state.abort(),
                        }
                    });
                }
                Err(_tx_execution_failed) => transactional_state.abort(),
            }

            tx_execution_result
        })?;

        Ok(PyTransactionExecutionInfo::from(tx_execution_info))
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let state_diff = PyStateDiff::from(self.borrow_state().to_state_diff());
        log::debug!("Finalized execution.");

        state_diff
    }
}
