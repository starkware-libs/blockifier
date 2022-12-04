use std::collections::HashMap;

use pretty_assertions::assert_eq;
use starknet_api::hash::StarkHash;
use starknet_api::shash;

use super::*;

#[test]
fn get_uninitialized_storage_value() -> Result<()> {
    let mut state: CachedState<DictStateReader> = CachedState::default();
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;
    let key = StorageKey::try_from(shash!("0x10"))?;

    assert_eq!(*state.get_storage_at(contract_address, key).unwrap(), StarkFelt::default());
    Ok(())
}

#[test]
fn get_and_set_storage_value() -> Result<()> {
    let contract_address0 = ContractAddress::try_from(shash!("0x100"))?;
    let contract_address1 = ContractAddress::try_from(shash!("0x200"))?;
    let key0 = StorageKey::try_from(shash!("0x10"))?;
    let key1 = StorageKey::try_from(shash!("0x20"))?;
    let storage_val0: StarkFelt = shash!("0x1");
    let storage_val1: StarkFelt = shash!("0x5");

    let mut state = CachedState::new(DictStateReader {
        contract_storage_key_to_value: HashMap::from([
            ((contract_address0, key0), storage_val0),
            ((contract_address1, key1), storage_val1),
        ]),
        ..Default::default()
    });
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), storage_val0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value0 = shash!("0xA");
    state.set_storage_at(contract_address0, key0, modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), storage_val1);

    let modified_storage_value1 = shash!("0x7");
    state.set_storage_at(contract_address1, key1, modified_storage_value1);
    assert_eq!(*state.get_storage_at(contract_address0, key0).unwrap(), modified_storage_value0);
    assert_eq!(*state.get_storage_at(contract_address1, key1).unwrap(), modified_storage_value1);
    Ok(())
}

#[test]
fn get_uninitialized_value() -> Result<()> {
    let mut state = CachedState::new(DictStateReader::default());
    let contract_address = ContractAddress::try_from(shash!("0x1"))?;

    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), Nonce::default());
    Ok(())
}

#[test]
fn gets_nonce() -> Result<()> {
    let contract_address = ContractAddress::try_from(shash!("0x0"))?;
    let initial_nonce = Nonce(shash!("0x1"));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([(contract_address, initial_nonce)]),
        ..Default::default()
    });
    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), initial_nonce);
    Ok(())
}

#[test]
fn get_and_increment_nonce() -> Result<()> {
    let contract_address1 = ContractAddress::try_from(shash!("0x100"))?;
    let contract_address2 = ContractAddress::try_from(shash!("0x200"))?;
    let initial_nonce = Nonce(shash!("0x1"));

    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce),
            (contract_address2, initial_nonce),
        ]),
        ..Default::default()
    });
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), initial_nonce);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    state.increment_nonce(contract_address1)?;
    let nonce1_plus_one = Nonce(shash!("0x2"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_one);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    state.increment_nonce(contract_address1)?;
    let nonce1_plus_two = Nonce(shash!("0x3"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), initial_nonce);

    state.increment_nonce(contract_address2)?;
    let nonce2_plus_one = Nonce(shash!("0x2"));
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), nonce1_plus_two);
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), nonce2_plus_one);

    Ok(())
}
