use blockifier::blockifier::stateful_validator::StatefulValidator;
use pyo3::{pyclass, pymethods, PyAny};
use starknet_api::core::Nonce;
use starknet_api::transaction::TransactionHash;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::{into_block_context_args, PyGeneralConfig};
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_account_tx, PyClassInfo};
use crate::py_utils::PyFelt;
use crate::state_readers::py_state_reader::PyStateReader;

#[pyclass]
pub struct PyValidator {
    pub stateful_validator: StatefulValidator<PyStateReader>,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, state_reader_proxy, next_block_info, validate_max_n_steps, max_recursion_depth, global_contract_cache_size, max_nonce_for_validation_skip))]
    pub fn create(
        general_config: PyGeneralConfig,
        state_reader_proxy: &PyAny,
        next_block_info: PyBlockInfo,
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        global_contract_cache_size: usize,
        max_nonce_for_validation_skip: PyFelt,
    ) -> NativeBlockifierResult<Self> {
        let state_reader = PyStateReader::new(state_reader_proxy);
        let (block_info, chain_info) = into_block_context_args(&general_config, &next_block_info)?;

        let stateful_validator = StatefulValidator::create(
            state_reader,
            block_info,
            chain_info,
            validate_max_n_steps,
            max_recursion_depth,
            global_contract_cache_size,
            Nonce(max_nonce_for_validation_skip.0),
        );

        Ok(Self { stateful_validator })
    }

    // Transaction Execution API.

    #[pyo3(signature = (tx, optional_py_class_info, deploy_account_tx_hash))]
    pub fn perform_validations(
        &mut self,
        tx: &PyAny,
        optional_py_class_info: Option<PyClassInfo>,
        deploy_account_tx_hash: Option<PyFelt>,
    ) -> NativeBlockifierResult<()> {
        let account_tx = py_account_tx(tx, optional_py_class_info)?;
        let deploy_account_tx_hash = deploy_account_tx_hash.map(|hash| TransactionHash(hash.0));
        self.stateful_validator.perform_validations(account_tx, deploy_account_tx_hash)?;

        Ok(())
    }
}
