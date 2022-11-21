use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use starknet_api::{EntryPoint, EntryPointType, Program};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    pub abi: serde_json::Value,
    pub program: Program,
    /// The selector of each entry point is a unique identifier in the program.
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl ContractClass {
    pub fn from_file(path: &Path) -> Result<ContractClass, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let contract_class_json = serde_json::from_reader(reader)?;

        Ok(contract_class_json)
    }
}

impl From<ContractClass> for starknet_api::ContractClass {
    fn from(class: ContractClass) -> Self {
        // Starknet does not verify the abi. If we can't parse it, we set it to None.
        let abi = serde_json::from_value::<Vec<ContractClassAbiEntry>>(class.abi)
            .ok()
            .map(|entries| entries.into_iter().map(ContractClassAbiEntry::try_into).collect())
            .and_then(Result::ok);
        Self { abi, program: class.program, entry_points_by_type: class.entry_points_by_type }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ContractClassAbiEntry {
    Event(EventAbiEntry),
    Function(FunctionAbiEntry),
    Struct(StructAbiEntry),
}

impl ContractClassAbiEntry {
    fn try_into(self) -> Result<starknet_api::ContractClassAbiEntry, ()> {
        match self {
            ContractClassAbiEntry::Event(entry) => {
                Ok(starknet_api::ContractClassAbiEntry::Event(entry.entry))
            }
            ContractClassAbiEntry::Function(entry) => {
                Ok(starknet_api::ContractClassAbiEntry::Function(entry.try_into()?))
            }
            ContractClassAbiEntry::Struct(entry) => {
                Ok(starknet_api::ContractClassAbiEntry::Struct(entry.entry))
            }
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct EventAbiEntry {
    pub r#type: String,
    #[serde(flatten)]
    pub entry: starknet_api::EventAbiEntry,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct FunctionAbiEntry {
    pub r#type: String,
    #[serde(flatten)]
    pub entry: starknet_api::FunctionAbiEntry,
}

impl FunctionAbiEntry {
    fn try_into(self) -> Result<starknet_api::FunctionAbiEntryWithType, ()> {
        match self.r#type.as_str() {
            "constructor" => Ok(starknet_api::FunctionAbiEntryType::Constructor),
            "function" => Ok(starknet_api::FunctionAbiEntryType::Regular),
            "l1_handler" => Ok(starknet_api::FunctionAbiEntryType::L1Handler),
            _ => Err(()),
        }
        .map(|t| starknet_api::FunctionAbiEntryWithType { r#type: t, entry: self.entry })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct StructAbiEntry {
    pub r#type: String,
    #[serde(flatten)]
    pub entry: starknet_api::StructAbiEntry,
}
