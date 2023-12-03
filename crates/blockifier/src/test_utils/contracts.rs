use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{class_hash, contract_address, patricia_key};

use crate::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use crate::test_utils::CairoVersion;

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
#[derive(Clone, Copy)]
pub enum FeatureContractId {
    AccountWithLongValidate,
    AccountWithoutValidations,
    Empty,
    FaultyAccount,
    LegacyTestContract,
    SecurityTests,
    TestContract,
}

/// Represents an instance of a feature contract. Create with `::new()`.
pub struct FeatureContract {
    pub class_hash: ClassHash,
    pub address: ContractAddress,
    pub class: ContractClass,
}

impl FeatureContract {
    /// To create a new instance of a feature contract, use this function. Use unique instance IDs
    /// to allow multiple deployments of the same contract class (different addresses).
    pub fn new(id: FeatureContractId, cairo_version: CairoVersion, instance_id: u8) -> Self {
        Self {
            class_hash: Self::get_class_hash(id, cairo_version),
            address: Self::get_address(id, cairo_version, instance_id),
            class: Self::get_class(id, cairo_version),
        }
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
    fn get_integer_base(id: FeatureContractId, cairo_version: CairoVersion) -> u32 {
        Self::get_cairo_version_bit(cairo_version)
            + match id {
                FeatureContractId::AccountWithLongValidate => ACCOUNT_LONG_VALIDATE_BASE,
                FeatureContractId::AccountWithoutValidations => ACCOUNT_WITHOUT_VALIDATIONS_BASE,
                FeatureContractId::Empty => EMPTY_CONTRACT_BASE,
                FeatureContractId::FaultyAccount => FAULTY_ACCOUNT_BASE,
                FeatureContractId::LegacyTestContract => LEGACY_CONTRACT_BASE,
                FeatureContractId::SecurityTests => SECURITY_TEST_CONTRACT_BASE,
                FeatureContractId::TestContract => TEST_CONTRACT_BASE,
            }
    }

    fn get_compiled_path(id: FeatureContractId, cairo_version: CairoVersion) -> String {
        Self::get_relative_path(
            match id {
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

    fn get_class_hash(id: FeatureContractId, cairo_version: CairoVersion) -> ClassHash {
        class_hash!(Self::get_integer_base(id, cairo_version))
    }

    /// To allow multiple deployments of the same contract class, the address also depends on
    /// instance ID.
    fn get_address(
        id: FeatureContractId,
        cairo_version: CairoVersion,
        instance_id: u8,
    ) -> ContractAddress {
        contract_address!(
            Self::get_integer_base(id, cairo_version) + instance_id as u32 + ADDRESS_BIT
        )
    }

    fn get_class(id: FeatureContractId, cairo_version: CairoVersion) -> ContractClass {
        match cairo_version {
            CairoVersion::Cairo0 => {
                ContractClassV0::from_file(&Self::get_compiled_path(id, cairo_version)).into()
            }
            CairoVersion::Cairo1 => {
                ContractClassV1::from_file(&Self::get_compiled_path(id, cairo_version)).into()
            }
        }
    }
}
