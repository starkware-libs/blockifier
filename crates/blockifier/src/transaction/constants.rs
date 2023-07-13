pub const EXECUTE_ENTRY_POINT_NAME: &str = "__execute__";
pub const TRANSFER_ENTRY_POINT_NAME: &str = "transfer";
pub const VALIDATE_ENTRY_POINT_NAME: &str = "__validate__";
pub const VALIDATE_DECLARE_ENTRY_POINT_NAME: &str = "__validate_declare__";
pub const VALIDATE_DEPLOY_ENTRY_POINT_NAME: &str = "__validate_deploy__";

pub const TRANSFER_EVENT_NAME: &str = "Transfer";

// Cairo constants.
pub const FELT_FALSE: u64 = 0;
pub const FELT_TRUE: u64 = 1;

// Expected return value of a `validate` entry point: `VALID`.
pub const VALIDATE_RETDATA: &str = "0x56414c4944";
