use std::collections::HashMap;

use pretty_assertions::assert_eq;
use starknet_api::{shash, StarkHash};

use super::*;

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
