use strum_macros::EnumIter;

#[derive(EnumIter, Eq, Hash, PartialEq)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InvokeFunction,
    L1Handler,
}
