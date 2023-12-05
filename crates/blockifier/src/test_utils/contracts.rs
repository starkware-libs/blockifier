use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_api::{class_hash, contract_address, patricia_key};
use strum_macros::EnumIter;

use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::test_utils::{get_deprecated_contract_class, CairoVersion};

// Bit to set on class hashes and addresses of feature contracts to indicate the Cairo1 variant.
const CAIRO1_BIT: u32 = 1 << 31;

// Bit to set on a class hash to convert it to the respective address.
const ADDRESS_BIT: u32 = 1 << 30;

// Class hashes of the feature contract. Keep the bottom 8 bits of each class hash unset, to allow
// up to 256 deployed instances of each contract.
const CLASS_HASH_BASE: u32 = 1 << 8;
const ACCOUNT_LONG_VALIDATE_BASE: u32 = CLASS_HASH_BASE;
const ACCOUNT_WITHOUT_VALIDATIONS_BASE: u32 = 2 * CLASS_HASH_BASE;
const EMPTY_CONTRACT_BASE: u32 = 3 * CLASS_HASH_BASE;
const FAULTY_ACCOUNT_BASE: u32 = 4 * CLASS_HASH_BASE;
const LEGACY_CONTRACT_BASE: u32 = 5 * CLASS_HASH_BASE;
const SECURITY_TEST_CONTRACT_BASE: u32 = 6 * CLASS_HASH_BASE;
const TEST_CONTRACT_BASE: u32 = 7 * CLASS_HASH_BASE;

// Contract names.
const ACCOUNT_LONG_VALIDATE_NAME: &str = "account_with_long_validate";
const ACCOUNT_WITHOUT_VALIDATIONS_NAME: &str = "account_without_validations";
const EMPTY_CONTRACT_NAME: &str = "empty_contract";
const FAULTY_ACCOUNT_NAME: &str = "account_faulty";
const LEGACY_CONTRACT_NAME: &str = "legacy_test_contract";
const SECURITY_TEST_CONTRACT_NAME: &str = "security_tests_contract";
const TEST_CONTRACT_NAME: &str = "test_contract";

/// Enum representing all feature contracts. Each one may be implemented in multiple Cairo versions.
#[derive(Clone, Copy, EnumIter, PartialEq)]
pub enum FeatureContractId {
    AccountWithLongValidate,
    AccountWithoutValidations,
    Empty,
    FaultyAccount,
    LegacyTestContract,
    SecurityTests,
    TestContract,
}

impl FeatureContractId {
    pub fn get_class_hash(&self, cairo_version: CairoVersion) -> ClassHash {
        class_hash!(self.get_integer_base(cairo_version))
    }

    /// To allow multiple deployments of the same contract class, the address also depends on
    /// instance ID.
    pub fn get_address(self, cairo_version: CairoVersion, instance_id: u8) -> ContractAddress {
        contract_address!(self.get_integer_base(cairo_version) + instance_id as u32 + ADDRESS_BIT)
    }

    fn get_relative_path(contract_name: &str, cairo_version: CairoVersion) -> String {
        format!(
            "./feature_contracts/cairo{}/compiled/{}{}.json",
            match cairo_version {
                CairoVersion::Cairo0 => "0",
                CairoVersion::Cairo1 => "1",
            },
            contract_name,
            match cairo_version {
                CairoVersion::Cairo0 => "_compiled",
                CairoVersion::Cairo1 => ".casm",
            }
        )
    }

    fn get_cairo_version_bit(cairo_version: CairoVersion) -> u32 {
        match cairo_version {
            CairoVersion::Cairo0 => 0,
            CairoVersion::Cairo1 => CAIRO1_BIT,
        }
    }

    /// Unique integer representing each unique contract. Used to derive "class hash" and "address".
    fn get_integer_base(&self, cairo_version: CairoVersion) -> u32 {
        Self::get_cairo_version_bit(cairo_version)
            + match self {
                FeatureContractId::AccountWithLongValidate => ACCOUNT_LONG_VALIDATE_BASE,
                FeatureContractId::AccountWithoutValidations => ACCOUNT_WITHOUT_VALIDATIONS_BASE,
                FeatureContractId::Empty => EMPTY_CONTRACT_BASE,
                FeatureContractId::FaultyAccount => FAULTY_ACCOUNT_BASE,
                FeatureContractId::LegacyTestContract => LEGACY_CONTRACT_BASE,
                FeatureContractId::SecurityTests => SECURITY_TEST_CONTRACT_BASE,
                FeatureContractId::TestContract => TEST_CONTRACT_BASE,
            }
    }

    pub fn get_compiled_path(self, cairo_version: CairoVersion) -> String {
        Self::get_relative_path(
            match self {
                FeatureContractId::AccountWithLongValidate => ACCOUNT_LONG_VALIDATE_NAME,
                FeatureContractId::AccountWithoutValidations => ACCOUNT_WITHOUT_VALIDATIONS_NAME,
                FeatureContractId::Empty => EMPTY_CONTRACT_NAME,
                FeatureContractId::FaultyAccount => FAULTY_ACCOUNT_NAME,
                FeatureContractId::LegacyTestContract => LEGACY_CONTRACT_NAME,
                FeatureContractId::SecurityTests => SECURITY_TEST_CONTRACT_NAME,
                FeatureContractId::TestContract => TEST_CONTRACT_NAME,
            },
            cairo_version,
        )
    }
}

/// Represents an instance of a feature contract. Create with `::new()`.
pub struct FeatureContract {
    pub id: FeatureContractId,
    pub cairo_version: CairoVersion,
    pub class_hash: ClassHash,
    pub address: ContractAddress,
}

impl FeatureContract {
    /// To create a new instance of a feature contract, use this function. Use unique instance IDs
    /// to allow multiple deployments of the same contract class (different addresses).
    pub fn new(id: FeatureContractId, cairo_version: CairoVersion, instance_id: u8) -> Self {
        Self {
            id,
            cairo_version,
            class_hash: id.get_class_hash(cairo_version),
            address: id.get_address(cairo_version, instance_id),
        }
    }

    pub fn get_class(&self) -> ContractClass {
        match self.cairo_version {
            CairoVersion::Cairo0 => {
                ContractClassV0::from_file(&self.id.get_compiled_path(self.cairo_version)).into()
            }
            CairoVersion::Cairo1 => {
                ContractClassV1::from_file(&self.id.get_compiled_path(self.cairo_version)).into()
            }
        }
    }

    pub fn get_deprecated_contract_class(&self) -> DeprecatedContractClass {
        let path = self.id.get_compiled_path(self.cairo_version);
        get_deprecated_contract_class(&path)
    }

    pub fn get_compiled_path(&self) -> String {
        self.id.get_compiled_path(self.cairo_version)
    }
}
