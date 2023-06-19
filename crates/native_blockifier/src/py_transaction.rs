use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;

use blockifier::abi::constants::L1_HANDLER_VERSION;
use blockifier::block_context::BlockContext;
use blockifier::block_execution::pre_process_block;
use blockifier::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use blockifier::state::cached_state::{CachedState, MutRefState};
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::transaction::transactions::{
    DeclareTransaction, ExecutableTransaction, L1HandlerTransaction,
};
use num_bigint::BigUint;
use ouroboros;
use papyrus_storage::db::RO;
use papyrus_storage::state::StateStorageReader;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::{
    ClassHash, CompiledClassHash, ContractAddress, EntryPointSelector, Nonce,
};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, DeclareTransactionV0V1, DeclareTransactionV2,
    DeployAccountTransaction, Fee, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1,
    TransactionHash, TransactionSignature, TransactionVersion,
};

use crate::errors::{NativeBlockifierError, NativeBlockifierInputError, NativeBlockifierResult};
use crate::papyrus_state::{PapyrusReader, PapyrusStateReader};
use crate::py_state_diff::PyStateDiff;
use crate::py_transaction_execution_info::PyTransactionExecutionInfo;
use crate::py_utils::{biguint_to_felt, to_chain_id_enum, PyFelt};
use crate::storage::Storage;

fn py_attr<T>(obj: &PyAny, attr: &str) -> NativeBlockifierResult<T>
where
    T: for<'a> FromPyObject<'a>,
    T: Clone,
{
    Ok(obj.getattr(attr)?.extract()?)
}

fn py_item<T>(obj: &PyAny, index: u8) -> NativeBlockifierResult<T>
where
    T: for<'a> FromPyObject<'a>,
    T: Clone,
{
    Ok(obj.get_item(index)?.extract()?)
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

pub fn py_block_context(
    general_config: PyGeneralConfig,
    block_info: &PyAny,
) -> NativeBlockifierResult<BlockContext> {
    let starknet_os_config = general_config.starknet_os_config;
    let block_number = BlockNumber(py_attr(block_info, "block_number")?);
    let block_context = BlockContext {
        chain_id: to_chain_id_enum(starknet_os_config.chain_id)?,
        block_number,
        block_timestamp: BlockTimestamp(py_attr(block_info, "block_timestamp")?),
        sequencer_address: ContractAddress::try_from(general_config.sequencer_address.0)?,
        fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
        vm_resource_fee_cost: general_config.cairo_resource_fee_weights,
        gas_price: py_attr(block_info, "gas_price")?,
        invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
        validate_max_n_steps: general_config.validate_max_n_steps,
    };

    Ok(block_context)
}

#[derive(FromPyObject)]
pub struct PyGeneralConfig {
    pub starknet_os_config: PyOsConfig,
    pub sequencer_address: PyFelt,
    pub cairo_resource_fee_weights: HashMap<String, f64>,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}
#[derive(FromPyObject)]
pub struct PyOsConfig {
    pub chain_id: BigUint,
    pub fee_token_address: PyFelt,
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

/// Wraps the transaction executor in an optional, to allow an explicit deallocation of it.
/// The explicit deallocation is needed since PyO3 can't track lifetimes within Python.
#[pyclass]
pub struct PyTransactionExecutor {
    pub executor: Option<PyTransactionExecutorInner>,
}

#[pymethods]
impl PyTransactionExecutor {
    #[new]
    #[args(general_config, block_info, papyrus_storage)]
    pub fn create(
        general_config: PyGeneralConfig,
        block_info: &PyAny,
        papyrus_storage: &Storage,
    ) -> NativeBlockifierResult<Self> {
        log::debug!("Initializing Transaction Executor...");
        let executor =
            PyTransactionExecutorInner::create(general_config, block_info, papyrus_storage)?;
        log::debug!("Initialized Transaction Executor.");

        Ok(Self { executor: Some(executor) })
    }

    #[args(tx, raw_contract_class, enough_room_for_tx)]
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add, tw_written=tx_written).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<(
        Py<PyTransactionExecutionInfo>,
        HashMap<PyFelt, PyContractClassSizes>,
    )> {
        self.executor().execute(tx, raw_contract_class, enough_room_for_tx)
    }

    pub fn finalize(&mut self) -> PyStateDiff {
        log::debug!("Finalizing execution...");
        let state_diff = self.executor().finalize();
        self.close();
        log::debug!("Finalized execution.");

        state_diff
    }

    pub fn close(&mut self) {
        self.executor = None;
    }

    pub fn pre_process_block(
        &mut self,
        n_from_current_block_number_and_hash: &PyAny,
    ) -> NativeBlockifierResult<()> {
        self.executor().pre_process_block(n_from_current_block_number_and_hash)
    }
}

impl PyTransactionExecutor {
    fn executor(&mut self) -> &mut PyTransactionExecutorInner {
        self.executor.as_mut().expect("Transaction executor should be initialized.")
    }
}

// To access a field you must use `self.borrow_{field_name}()`.
// Alternately, you can borrow the whole object using `self.with[_mut]()`.
#[ouroboros::self_referencing]
pub struct PyTransactionExecutorInner {
    pub block_context: BlockContext,

    // State-related fields.
    // Storage reader and transaction are kept merely for lifetime parameter referencing.
    pub storage_reader: papyrus_storage::StorageReader,
    #[borrows(storage_reader)]
    #[covariant]
    pub storage_tx: papyrus_storage::StorageTxn<'this, RO>,
    #[borrows(storage_tx)]
    #[covariant]
    pub state: CachedState<PapyrusReader<'this>>,
}

impl PyTransactionExecutorInner {
    pub fn create(
        general_config: PyGeneralConfig,
        block_info: &PyAny,
        papyrus_storage: &Storage,
    ) -> NativeBlockifierResult<Self> {
        // Assumption: storage is aligned.
        let reader = papyrus_storage.reader().clone();

        let block_context = py_block_context(general_config, block_info)?;
        build_tx_executor(block_context, reader)
    }

    /// Executes the given transaction on the state maintained by the executor.
    /// Returns the execution trace, together with the compiled class hashes of executed classes
    /// (used for counting purposes).
    pub fn execute(
        &mut self,
        tx: &PyAny,
        raw_contract_class: Option<&str>,
        // This is functools.partial(bouncer.add, tw_written=tx_written).
        enough_room_for_tx: &PyAny,
    ) -> NativeBlockifierResult<(
        Py<PyTransactionExecutionInfo>,
        HashMap<PyFelt, PyContractClassSizes>,
    )> {
        let tx_type: String = py_enum_name(tx, "tx_type")?;
        let tx: Transaction = py_tx(&tx_type, tx, raw_contract_class)?;

        let mut executed_class_hashes = HashSet::<ClassHash>::new();
        self.with_mut(|executor| {
            let mut transactional_state = CachedState::new(MutRefState::new(executor.state));
            let tx_execution_result = tx
                .execute_raw(&mut transactional_state, executor.block_context)
                .map_err(NativeBlockifierError::from);
            let py_tx_execution_info = match tx_execution_result {
                Ok(tx_execution_info) => {
                    executed_class_hashes.extend(tx_execution_info.get_executed_class_hashes());
                    Python::with_gil(|py| {
                        // Allocate this instance on the Python heap.
                        // This is necessary in order to pass a reference to it to the callback
                        // (otherwise, if it were allocated on Rust's heap/stack, giving Python a
                        // reference to the objects will not work).
                        Py::new(py, PyTransactionExecutionInfo::from(tx_execution_info))
                            .expect("Should be able to allocate on Python heap")
                    })
                }
                Err(error) => {
                    transactional_state.abort();
                    return Err(error);
                }
            };

            let has_enough_room_for_tx = Python::with_gil(|py| {
                // Can be done because `py_tx_execution_info` is a `Py<PyTransactionExecutionInfo>`,
                // hence is allocated on the Python heap.
                let args = (py_tx_execution_info.borrow(py),);
                enough_room_for_tx.call1(args) // Callback to Python code.
            });

            match has_enough_room_for_tx {
                Ok(_) => {
                    transactional_state.commit();
                    let py_executed_compiled_class_hashes = into_py_contract_class_sizes_mapping(
                        executor.state,
                        executed_class_hashes,
                    )?;
                    Ok((py_tx_execution_info, py_executed_compiled_class_hashes))
                }
                // Unexpected error, abort and let caller know.
                Err(error) if unexpected_callback_error(&error) => {
                    transactional_state.abort();
                    Err(error.into())
                }
                // Not enough room in batch, abort and let caller verify on its own.
                Err(_not_enough_weight_error) => {
                    transactional_state.abort();
                    let py_executed_compiled_class_hashes = into_py_contract_class_sizes_mapping(
                        executor.state,
                        executed_class_hashes,
                    )?;
                    Ok((py_tx_execution_info, py_executed_compiled_class_hashes))
                }
            }
        })
    }

    /// Returns the state diff resulting in executing transactions.
    pub fn finalize(&mut self) -> PyStateDiff {
        PyStateDiff::from(self.borrow_state().to_state_diff())
    }

    // Block pre-processing; see `block_execution::pre_process_block` documentation.
    pub fn pre_process_block(
        &mut self,
        n_from_current_block_number_and_hash: &PyAny,
    ) -> NativeBlockifierResult<()> {
        if n_from_current_block_number_and_hash.is_none() {
            return Ok(());
        }

        let block_number = py_item(n_from_current_block_number_and_hash, 0)?;
        let block_hash = biguint_to_felt(py_item(n_from_current_block_number_and_hash, 1)?)?;

        self.with_mut(|executor| {
            pre_process_block(
                executor.state,
                Some((BlockNumber(block_number), BlockHash(block_hash))),
            );
        });
        Ok(())
    }
}

pub fn build_tx_executor(
    block_context: BlockContext,
    storage_reader: papyrus_storage::StorageReader,
) -> NativeBlockifierResult<PyTransactionExecutorInner> {
    // The following callbacks are required to capture the local lifetime parameter.
    fn storage_tx_builder(
        storage_reader: &papyrus_storage::StorageReader,
    ) -> NativeBlockifierResult<papyrus_storage::StorageTxn<'_, RO>> {
        Ok(storage_reader.begin_ro_txn()?)
    }

    fn state_builder<'a>(
        storage_tx: &'a papyrus_storage::StorageTxn<'a, RO>,
        block_number: BlockNumber,
    ) -> NativeBlockifierResult<CachedState<PapyrusReader<'a>>> {
        let state_reader = storage_tx.get_state_reader()?;
        let state_reader = PapyrusStateReader::new(state_reader, block_number);
        let papyrus_reader = PapyrusReader::new(storage_tx, state_reader);
        Ok(CachedState::new(papyrus_reader))
    }

    let block_number = block_context.block_number;
    // The builder struct below is implicitly created by `ouroboros`.
    let py_tx_executor_builder = PyTransactionExecutorInnerTryBuilder {
        block_context,
        storage_reader,
        storage_tx_builder,
        state_builder: |storage_tx| state_builder(storage_tx, block_number),
    };
    py_tx_executor_builder.try_build()
}

#[pyclass]
#[derive(Clone)]
pub struct PyContractClassSizes {
    #[pyo3(get)]
    pub bytecode_length: usize,
    #[pyo3(get)]
    // For a Cairo 1.0 contract class, builtins are an attribute of an entry point,
    // and not of the entire class.
    pub n_builtins: Option<usize>,
}

fn unexpected_callback_error(error: &PyErr) -> bool {
    let error_string = error.to_string();
    !(error_string.contains("BatchFull") || error_string.contains("TransactionBiggerThanBatch"))
}

/// Maps Sierra class hashes to their corresponding compiled class hash.
pub fn into_py_contract_class_sizes_mapping(
    state: &mut CachedState<PapyrusReader<'_>>,
    executed_class_hashes: HashSet<ClassHash>,
) -> NativeBlockifierResult<HashMap<PyFelt, PyContractClassSizes>> {
    let mut executed_compiled_class_sizes = HashMap::<PyFelt, PyContractClassSizes>::new();

    for class_hash in executed_class_hashes {
        let class = state.get_compiled_contract_class(&class_hash)?;

        let sizes = match class {
            ContractClass::V0(class) => PyContractClassSizes {
                bytecode_length: class.bytecode_length(),
                n_builtins: Some(class.n_builtins()),
            },
            ContractClass::V1(class) => {
                PyContractClassSizes { bytecode_length: class.bytecode_length(), n_builtins: None }
            }
        };

        executed_compiled_class_sizes.insert(PyFelt::from(class_hash), sizes);
    }

    Ok(executed_compiled_class_sizes)
}
