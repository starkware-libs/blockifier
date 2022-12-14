use starknet_api::core::ClassHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateReaderError {
    #[error("Class with hash {0:#?} is not declared.")]
    UndeclaredClassHash(ClassHash),
}
