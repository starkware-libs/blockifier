use crate::fee::os_usage::OsResources;

// TODO(Arni, 14/6/2023): Update `GetBlockHash` values.
// TODO(ilya): Consider moving the resources of a keccak round to a seperate dict.
pub const OS_RESOURCES_JSON: &str = include_str!("../../resources/os_resources.json");

#[ctor::ctor]
pub static OS_RESOURCES: OsResources = {
    serde_json::from_str(OS_RESOURCES_JSON)
        .expect("os_resources json does not exist or cannot be deserialized.")
};
