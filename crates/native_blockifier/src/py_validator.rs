use blockifier::blockifier::stateful_validator::StatefulValidator;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::{pyclass, pymethods, PyAny};
use starknet_api::core::Nonce;
use starknet_api::transaction::TransactionHash;

use crate::errors::NativeBlockifierResult;
use crate::py_block_executor::PyGeneralConfig;
use crate::py_objects::PyVersionedConstantsOverrides;
use crate::py_state_diff::PyBlockInfo;
use crate::py_transaction::{py_account_tx, PyClassInfo, PY_TX_PARSING_ERR};
use crate::py_utils::PyFelt;
use crate::state_readers::py_state_reader::PyStateReader;

#[pyclass]
pub struct PyValidator {
    pub stateful_validator: StatefulValidator<PyStateReader>,
}

#[pymethods]
impl PyValidator {
    #[new]
    #[pyo3(signature = (general_config, state_reader_proxy, next_block_info, max_nonce_for_validation_skip, py_versioned_constants_overrides))]
    pub fn create(
        general_config: PyGeneralConfig,
        state_reader_proxy: &PyAny,
        next_block_info: PyBlockInfo,
        max_nonce_for_validation_skip: PyFelt,
        py_versioned_constants_overrides: PyVersionedConstantsOverrides,
    ) -> NativeBlockifierResult<Self> {
        // Create the state.
        let state_reader = PyStateReader::new(state_reader_proxy);
        let state = CachedState::new(state_reader);

        // Create the block context.
        let versioned_constants =
            VersionedConstants::get_versioned_constants(py_versioned_constants_overrides.into());
        let block_context = BlockContext::new(
            next_block_info.try_into().expect("Failed to convert block info."),
            general_config.starknet_os_config.into_chain_info(),
            versioned_constants,
            BouncerConfig::max(),
            false,
        );

        // Create the stateful validator.
        let max_nonce_for_validation_skip = Nonce(max_nonce_for_validation_skip.0);
        let stateful_validator =
            StatefulValidator::create(state, block_context, max_nonce_for_validation_skip);

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
        let account_tx = py_account_tx(tx, optional_py_class_info).expect(PY_TX_PARSING_ERR);
        let deploy_account_tx_hash = deploy_account_tx_hash.map(|hash| TransactionHash(hash.0));
        self.stateful_validator.perform_validations(account_tx, deploy_account_tx_hash)?;

        Ok(())
    }
}
