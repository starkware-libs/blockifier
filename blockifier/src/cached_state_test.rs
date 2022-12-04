use std::collections::HashMap;

use anyhow::bail;
use pretty_assertions::assert_eq;
use starknet_api::{shash, StarkHash};

use super::*;
use crate::BlockifierError;

#[test]
fn storage_get_uninitialized() -> Result<()> {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let key = StorageKey::try_from(shash!("0x10"))?;

    assert_eq!(*state.get_storage_at(contract_address, key).unwrap(), uninitialized_storage());
    Ok(())
}

#[test]
fn storage_read() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let key1 = StorageKey::try_from(shash!("0x10"))?;
    let key2 = StorageKey::try_from(shash!("0x20"))?;
    let storage_val1: StarkFelt = shash!("0x123");
    let storage_val2: StarkFelt = shash!("0x123");
    let mut state = CachedState::new(DictStateReader {
        contract_storage_key_to_value: HashMap::from([
            ((contract_address, key1), storage_val1),
            ((contract_address, key2), storage_val2),
        ]),
        ..Default::default()
    });
    assert_eq!(*state.get_storage_at(contract_address, key1).unwrap(), storage_val1);
    assert_eq!(*state.get_storage_at(contract_address, key1).unwrap(), storage_val2);
    Ok(())
}

#[test]
fn storage_set() -> Result<()> {
    let contract_address1 = ContractAddress::try_from(shash!("0x100"))?;
    let contract_address2 = ContractAddress::try_from(shash!("0x200"))?;
    let key1 = StorageKey::try_from(shash!("0x10"))?;
    let key2 = StorageKey::try_from(shash!("0x20"))?;
    let storage_val1: StarkFelt = shash!("0x1");
    let storage_val2: StarkFelt = shash!("0x5");
    let mut state = CachedState::new(DictStateReader {
        contract_storage_key_to_value: HashMap::from([
            ((contract_address1, key1), storage_val1),
            ((contract_address2, key2), storage_val2),
        ]),
        ..Default::default()
    });

    state.set_storage_at(contract_address1, key1, shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address2, key2).unwrap(), shash!("0x5"));

    state.set_storage_at(contract_address2, key2, shash!("0x7"));
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address2, key2).unwrap(), shash!("0x7"));
    Ok(())
}

#[test]
fn nonce_get_uninitialized() -> Result<()> {
    let mut state = CachedState::new(DictStateReader::default());
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;

    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), uninitialized_nonce());
    Ok(())
}

#[test]
fn gets_nonce() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x0"))?;
    let initial_nonce = Nonce::new(shash!("0x1"));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([(contract_address, initial_nonce)]),
        ..Default::default()
    });
    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), initial_nonce);
    Ok(())
}

#[test]
fn increments_nonce() -> Result<()> {
    let contract_address1 = ContractAddress::try_from(shash!("0x100"))?;
    let contract_address2 = ContractAddress::try_from(shash!("0x200"))?;
    let initial_nonce1 = Nonce::new(shash!("0x1"));
    let initial_nonce2 = Nonce::new(shash!("0x1"));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce1),
            (contract_address2, initial_nonce2),
        ]),
        ..Default::default()
    });

    state.increment_nonce(contract_address1)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce::new(shash!("0x2")));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce::new(shash!("0x1")));

    state.increment_nonce(contract_address1)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce::new(shash!("0x3")));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce::new(shash!("0x1")));

    state.increment_nonce(contract_address2)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce::new(shash!("0x3")));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce::new(shash!("0x2")));

    Ok(())
}

#[test]
fn class_hash_get_uninitialized() -> Result<()> {
    let mut state = CachedState::new(DictStateReader::default());
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;

    assert_eq!(*state.get_class_hash_at(contract_address).unwrap(), uninitialized_class_hash());
    Ok(())
}

#[test]
fn class_hash_read() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let class_hash = ClassHash::new(shash!("0x10"));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_class_hash: HashMap::from([(contract_address, class_hash)]),
        ..Default::default()
    });
    assert_eq!(*state.get_class_hash_at(contract_address).unwrap(), class_hash);
    Ok(())
}

#[test]
fn set_contract_hash_success() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let uninitialized_class_hash = ClassHash::default();
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_class_hash: HashMap::from([(
            contract_address,
            uninitialized_class_hash,
        )]),
        ..Default::default()
    });

    let class_hash = ClassHash::new(shash!("0x10"));
    assert_eq!(state.set_contract_hash(contract_address, class_hash), Ok(()));
    Ok(())
}

#[test]
fn cannot_set_class_hash_to_deployed_contract() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let deployed_class_hash = ClassHash::new(shash!("0x10"));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_class_hash: HashMap::from([(contract_address, deployed_class_hash)]),
        ..Default::default()
    });

    let class_hash = ClassHash::new(shash!("0x100"));
    match state.set_contract_hash(contract_address, class_hash) {
        Err(err) => {
            assert_eq!(matches!(err, BlockifierError::ContractAddressUnavailable { .. }), true)
        }
        Ok(_) => bail!("Should not be able to set_contract_hash"),
    }
    Ok(())
}

#[test]
fn cannot_set_class_hash_to_uninitialized_contract() -> Result<()> {
    let uninitialized_contract_address = uninitialized_contract_address();
    let uninitialized_class_hash = uninitialized_class_hash();
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_class_hash: HashMap::from([(
            uninitialized_contract_address,
            uninitialized_class_hash,
        )]),
        ..Default::default()
    });

    let class_hash = ClassHash::new(shash!("0x100"));
    match state.set_contract_hash(uninitialized_contract_address, class_hash) {
        Err(err) => assert_eq!(matches!(err, BlockifierError::OutOfRangeAddress), true),
        Ok(_) => bail!("Should not be able to set_contract_hash"),
    }
    Ok(())
}

#[test]
fn state_reader_errors() -> Result<()> {
    // Simulates data-retrieval errors, e.g. timeouts when trying to fetch from a DB.
    pub struct NoGoodStateReader;

    // TODO(Gilad, 10/12/2022) add and test the other two methods once they support errors.
    impl StateReader for NoGoodStateReader {
        fn get_storage_at(
            &self,
            _contract_address: ContractAddress,
            _key: StorageKey,
        ) -> Result<StarkFelt> {
            unimplemented!();
        }

        fn get_nonce_at(&self, _contract_address: ContractAddress) -> Result<Nonce> {
            unimplemented!();
        }

        fn get_class_hash_at(
            &self,
            contract_address: ContractAddress,
        ) -> Result<ClassHash, StateReaderError> {
            Err(StateReaderError::from(contract_address))
        }
    }

    let no_good_state_reader = NoGoodStateReader {};
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;

    let state_get_error = no_good_state_reader.get_class_hash_at(contract_address).unwrap_err();
    assert_eq!(matches!(state_get_error, StateReaderError { .. }), true);

    let mut cached_state = CachedState::new(no_good_state_reader);
    let class_hash = ClassHash::new(shash!("0x10"));
    let cached_state_get_error =
        cached_state.set_contract_hash(contract_address, class_hash).unwrap_err();
    assert_eq!(matches!(cached_state_get_error, BlockifierError::StateError { .. }), true);

    Ok(())
}
