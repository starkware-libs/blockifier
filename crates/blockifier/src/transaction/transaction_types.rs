use strum_macros::EnumIter;

#[derive(EnumIter, Eq, Hash, PartialEq)]
pub enum TransactionType {
    Declare,
    DeployAccount,
    InvokeFunction,
    L1Handler,
}
