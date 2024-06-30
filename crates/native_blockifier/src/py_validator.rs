use blockifier::blockifier::stateful_validator::{StatefulValidator, StatefulValidatorResult};
use blockifier::bouncer::BouncerConfig;
use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::objects::TransactionInfoCreator;
use blockifier::transaction::transaction_types::TransactionType;
use blockifier::versioned_constants::VersionedConstants;
use pyo3::{pyclass, pymethods, PyAny};
use starknet_api::core::Nonce;
use starknet_api::transaction::TransactionHash;
use starknet_types_core::felt::Felt;

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
    pub max_nonce_for_validation_skip: Nonce,
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
        );

        // Create the stateful validator.
        let max_nonce_for_validation_skip = Nonce(max_nonce_for_validation_skip.0);
        let stateful_validator = StatefulValidator::create(state, block_context);

        Ok(Self { stateful_validator, max_nonce_for_validation_skip })
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

        // We check if the transaction should be skipped due to the deploy account not being
        // processed.
        let skip_validate = self
            .skip_validate_due_to_unprocessed_deploy_account(&account_tx, deploy_account_tx_hash)?;
        self.stateful_validator.perform_validations(account_tx, skip_validate)?;

        Ok(())
    }
}

impl PyValidator {
    // Check if deploy account was submitted but not processed yet. If so, then skip
    // `__validate__` method for subsequent transactions for a better user experience.
    // (they will otherwise fail solely because the deploy account hasn't been processed yet).
    pub fn skip_validate_due_to_unprocessed_deploy_account(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(false);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(skip_validate)
    }
}
