// TODO(10/12/2022): Implement 'get_selector_from_name' and only define the entrypoint names here.
// The entrypoint selector corresponding to the '__execute__' entrypoint.
pub const EXECUTE_ENTRY_POINT_SELECTOR: &str =
    "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad";
// The entrypoint selector corresponding to the '__validate__' entrypoint.
pub const VALIDATE_ENTRY_POINT_SELECTOR: &str =
    "0x162da33a4585851fe8d3af3c2a9c60b557814e221e0d4f30ff0b2189d9c7775";

pub const ACCOUNT_CONTRACT_ADDRESS: &str = "0x0";
// TODO(Adi, 25/12/2022): Remove once a class hash can be computed given a class.
pub const ACCOUNT_CONTRACT_CLASS_HASH: &str = "0x0";
// TODO(Adi, 10/02/2022): Replace with 'account_contract_without_validations' once the syscalls are
// implemented.
pub const ACCOUNT_CONTRACT_PATH: &str =
    "./feature_contracts/compiled/account_without_some_syscalls_compiled.json";

// The index of the beginning of the called contract calldata in the invoke transaction
// `__execute__` calldata.
pub const CALL_CONTRACT_CALLDATA_INDEX: usize = 3;
