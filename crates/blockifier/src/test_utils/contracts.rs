use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_api::{class_hash, contract_address, patricia_key};

use crate::execution::contract_class::{
    ContractClass, ContractClassV0, ContractClassV1, SierraContractClassV1,
};
use crate::test_utils::{get_raw_contract_class, CairoVersion};

// This file contains featured contracts, used for tests. Use the function 'test_state' in
// initial_test_state.rs to initialize a state with these contracts.
//
// Use the mock class hashes and addresses to interact with the contracts in tests.
// The structure of such mock address / class hash is as follows:
// +-+-+-----------+---------------+---------------+---------------+
// |v|a| reserved  | 8 bits: class | 16 bits : address             |
// +-+-+-----------+---------------+---------------+---------------+
// v: 1 bit. 0 for Cairo0, 1 for Cairo1. bit 31.
// a: 1 bit. 0 for class hash, 1 for address. bit 30.
// reserved: Must be 0. bit 29-24.
// class: 8 bits. The class hash of the contract. bit 23-16. allows up to 256 unique contracts.
// address: 16 bits. The instance ID of the contract. bit 15-0. allows up to 65536 instances of each
// contract.

// Bit to set on class hashes and addresses of feature contracts to indicate the Cairo1 variant.
const CAIRO1_BIT: u32 = 1 << 31;

// Bit to set on a class hash to convert it to the respective address.
const ADDRESS_BIT: u32 = 1 << 30;

// Mock class hashes of the feature contract. Keep the bottom 16 bits of each class hash unset, to
// allow up to 65536 deployed instances of each contract.
const CLASS_HASH_BASE: u32 = 1 << 16;
const ACCOUNT_LONG_VALIDATE_BASE: u32 = CLASS_HASH_BASE;
const ACCOUNT_WITHOUT_VALIDATIONS_BASE: u32 = 2 * CLASS_HASH_BASE;
const EMPTY_CONTRACT_BASE: u32 = 3 * CLASS_HASH_BASE;
const FAULTY_ACCOUNT_BASE: u32 = 4 * CLASS_HASH_BASE;
const LEGACY_CONTRACT_BASE: u32 = 5 * CLASS_HASH_BASE;
const SECURITY_TEST_CONTRACT_BASE: u32 = 6 * CLASS_HASH_BASE;
const TEST_CONTRACT_BASE: u32 = 7 * CLASS_HASH_BASE;
const ERC20_CONTRACT_BASE: u32 = 8 * CLASS_HASH_BASE;
const SIERRA_TEST_CONTRACT_BASE: u32 = 9 * CLASS_HASH_BASE;
const SIERRA_EXECUTION_INFO_V1_CONTRACT_BASE: u32 = 10 * CLASS_HASH_BASE;

// Contract names.
const ACCOUNT_LONG_VALIDATE_NAME: &str = "account_with_long_validate";
const ACCOUNT_WITHOUT_VALIDATIONS_NAME: &str = "account_with_dummy_validate";
const EMPTY_CONTRACT_NAME: &str = "empty_contract";
const FAULTY_ACCOUNT_NAME: &str = "account_faulty";
const LEGACY_CONTRACT_NAME: &str = "legacy_test_contract";
const SECURITY_TEST_CONTRACT_NAME: &str = "security_tests_contract";
const TEST_CONTRACT_NAME: &str = "test_contract";
const SIERRA_TEST_CONTRACT_NAME: &str = "sierra_test_contract";
const SIERRA_EXECUTION_INFO_V1_CONTRACT_NAME: &str = "sierra_execution_info_v1";

// ERC20 contract is in a unique location.
const ERC20_CONTRACT_PATH: &str =
    "./ERC20_without_some_syscalls/ERC20/erc20_contract_without_some_syscalls_compiled.json";

/// Enum representing all feature contracts.
/// The contracts that are implemented in both Cairo versions include a version field.
#[derive(Clone, Copy, Debug)]
pub enum FeatureContract {
    AccountWithLongValidate(CairoVersion),
    AccountWithoutValidations(CairoVersion),
    ERC20,
    Empty(CairoVersion),
    FaultyAccount(CairoVersion),
    LegacyTestContract,
    SecurityTests,
    TestContract(CairoVersion),
    SierraTestContract,
    SierraExecutionInfoV1Contract,
}

impl FeatureContract {
    fn cairo_version(&self) -> CairoVersion {
        match self {
            Self::AccountWithLongValidate(version)
            | Self::AccountWithoutValidations(version)
            | Self::Empty(version)
            | Self::FaultyAccount(version)
            | Self::TestContract(version) => *version,
            Self::SecurityTests | Self::ERC20 => CairoVersion::Cairo0,
            Self::LegacyTestContract
            | Self::SierraTestContract
            | Self::SierraExecutionInfoV1Contract => CairoVersion::Cairo1,
        }
    }

    fn get_cairo_version_bit(&self) -> u32 {
        match self.cairo_version() {
            CairoVersion::Cairo0 => 0,
            CairoVersion::Cairo1 => CAIRO1_BIT,
        }
    }

    /// Unique integer representing each unique contract. Used to derive "class hash" and "address".
    fn get_integer_base(self) -> u32 {
        self.get_cairo_version_bit()
            + match self {
                Self::AccountWithLongValidate(_) => ACCOUNT_LONG_VALIDATE_BASE,
                Self::AccountWithoutValidations(_) => ACCOUNT_WITHOUT_VALIDATIONS_BASE,
                Self::Empty(_) => EMPTY_CONTRACT_BASE,
                Self::ERC20 => ERC20_CONTRACT_BASE,
                Self::FaultyAccount(_) => FAULTY_ACCOUNT_BASE,
                Self::LegacyTestContract => LEGACY_CONTRACT_BASE,
                Self::SecurityTests => SECURITY_TEST_CONTRACT_BASE,
                Self::TestContract(_) => TEST_CONTRACT_BASE,
                Self::SierraTestContract => SIERRA_TEST_CONTRACT_BASE,
                Self::SierraExecutionInfoV1Contract => SIERRA_EXECUTION_INFO_V1_CONTRACT_BASE,
            }
    }

    fn get_compiled_path(&self) -> String {
        let cairo_version = self.cairo_version();
        let contract_name = match self {
            Self::AccountWithLongValidate(_) => ACCOUNT_LONG_VALIDATE_NAME,
            Self::AccountWithoutValidations(_) => ACCOUNT_WITHOUT_VALIDATIONS_NAME,
            Self::Empty(_) => EMPTY_CONTRACT_NAME,
            Self::FaultyAccount(_) => FAULTY_ACCOUNT_NAME,
            Self::LegacyTestContract => LEGACY_CONTRACT_NAME,
            Self::SecurityTests => SECURITY_TEST_CONTRACT_NAME,
            Self::TestContract(_) => TEST_CONTRACT_NAME,
            Self::SierraTestContract => SIERRA_TEST_CONTRACT_NAME,
            // ERC20 is a special case - not in the feature_contracts directory.
            Self::ERC20 => return ERC20_CONTRACT_PATH.into(),
            Self::SierraExecutionInfoV1Contract => SIERRA_EXECUTION_INFO_V1_CONTRACT_NAME,
        };
        format!(
            "./feature_contracts/cairo{}/compiled/{}{}.json",
            match cairo_version {
                CairoVersion::Cairo0 => "0",
                CairoVersion::Cairo1 => "1",
            },
            contract_name,
            match self {
                // TODO replace with a vm vs native flag when expanding native tests to use all the
                // cairo 1 contracts
                Self::SierraTestContract | Self::SierraExecutionInfoV1Contract => ".sierra",
                _ => match cairo_version {
                    CairoVersion::Cairo0 => "_compiled",
                    CairoVersion::Cairo1 => ".casm",
                },
            }
        )
    }

    pub fn set_cairo_version(&mut self, version: CairoVersion) {
        match self {
            Self::AccountWithLongValidate(v)
            | Self::AccountWithoutValidations(v)
            | Self::Empty(v)
            | Self::FaultyAccount(v)
            | Self::TestContract(v) => *v = version,
            Self::ERC20
            | Self::LegacyTestContract
            | Self::SecurityTests
            | Self::SierraTestContract
            | Self::SierraExecutionInfoV1Contract => {
                panic!("{self:?} contract has no configurable version.")
            }
        }
    }

    pub fn get_class_hash(&self) -> ClassHash {
        class_hash!(self.get_integer_base())
    }

    /// Returns the address of the instance with the given instance ID.
    pub fn get_instance_address(&self, instance_id: u16) -> ContractAddress {
        let instance_id_as_u32: u32 = instance_id.into();
        contract_address!(self.get_integer_base() + instance_id_as_u32 + ADDRESS_BIT)
    }

    pub fn get_class(&self) -> ContractClass {
        match self {
            // TODO replace once vm/native is a flag
            Self::SierraTestContract | Self::SierraExecutionInfoV1Contract => {
                SierraContractClassV1::from_file(&self.get_compiled_path()).into()
            }
            _ => match self.cairo_version() {
                CairoVersion::Cairo0 => {
                    ContractClassV0::from_file(&self.get_compiled_path()).into()
                }
                CairoVersion::Cairo1 => {
                    ContractClassV1::from_file(&self.get_compiled_path()).into()
                }
            },
        }
    }

    // TODO(Arni, 1/1/2025): Remove this function, and use the get_class function instead.
    pub fn get_deprecated_contract_class(&self) -> DeprecatedContractClass {
        let mut raw_contract_class: serde_json::Value =
            serde_json::from_str(&self.get_raw_class()).unwrap();

        // ABI is not required for execution.
        raw_contract_class
            .as_object_mut()
            .expect("A compiled contract must be a JSON object.")
            .remove("abi");

        serde_json::from_value(raw_contract_class)
            .expect("DeprecatedContractClass is not supported for this contract.")
    }

    pub fn get_raw_class(&self) -> String {
        get_raw_contract_class(&self.get_compiled_path())
    }
}
