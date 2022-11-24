use std::collections::HashMap;

use pretty_assertions::assert_eq;
use starknet_api::{shash, StarkHash};

use super::*;

#[test]
fn storage_get_uninitialized() -> Result<()> {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let key = StorageKey::try_from(shash!("0x10"))?;

    assert_eq!(*state.get_storage_at(contract_address, key).unwrap(), default_storage_value());
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
    });

    state.set_storage_at(contract_address1, key1, shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address2, key2).unwrap(), shash!("0x5"));

    state.set_storage_at(contract_address2, key2, shash!("0x7"));
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), shash!("0xA"));
    assert_eq!(*state.get_storage_at(contract_address2, key2).unwrap(), shash!("0x7"));
    Ok(())
}
