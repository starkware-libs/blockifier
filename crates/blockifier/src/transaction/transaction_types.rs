use serde::Deserialize;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq)]
pub enum TransactionType {
    #[serde(alias = "DECLARE")]
    Declare,
    #[serde(alias = "DEPLOY_ACCOUNT")]
    DeployAccount,
    #[serde(alias = "INVOKE_FUNCTION")]
    InvokeFunction,
    #[serde(alias = "L1_HANDLER")]
    L1Handler,
}
