use anyhow;
use starknet_api::StarknetApiError;

#[derive(Debug)]
pub enum TransactionExecutionError {
    Any(anyhow::Error),
    String(String),
    StarknetApiError(StarknetApiError),
}

impl From<anyhow::Error> for TransactionExecutionError {
    fn from(anyhow_error: anyhow::Error) -> Self {
        Self::Any(anyhow_error)
    }
}

impl From<StarknetApiError> for TransactionExecutionError {
    fn from(starknet_api_error: StarknetApiError) -> Self {
        Self::StarknetApiError(starknet_api_error)
    }
}

impl From<String> for TransactionExecutionError {
    fn from(string_error: String) -> Self {
        Self::String(string_error)
    }
}

impl From<&str> for TransactionExecutionError {
    fn from(string_error: &str) -> Self {
        Self::String(string_error.to_string())
    }
}
