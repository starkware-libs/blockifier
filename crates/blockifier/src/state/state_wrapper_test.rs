use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;

use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader};
use crate::state::state_wrapper::DynStateWrapper;

#[test]
fn set_class_hash_at() {
    let contract_address = ContractAddress::from(1u128);
    let mut cached_state = CachedState::default();

    cached_state.set_class_hash_at(contract_address, ClassHash(StarkHash::from(1u128))).unwrap();

    let mut wrapped_state = DynStateWrapper::new(&mut cached_state);

    assert_eq!(
        wrapped_state.get_raw_class_hash_at(contract_address).unwrap(),
        ClassHash(StarkHash::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_class_hash_at(contract_address).unwrap(),
        ClassHash(StarkHash::from(1u128))
    );

    wrapped_state.set_class_hash_at(contract_address, ClassHash(StarkHash::from(2u128))).unwrap();

    assert_eq!(
        wrapped_state.get_raw_class_hash_at(ContractAddress::from(1u128)).unwrap(),
        ClassHash(StarkHash::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_class_hash_at(ContractAddress::from(1u128)).unwrap(),
        ClassHash(StarkHash::from(2u128))
    );

    wrapped_state.commit().unwrap();

    assert_eq!(
        wrapped_state.get_class_hash_at(ContractAddress::from(1u128)).unwrap(),
        ClassHash(StarkHash::from(2u128))
    );

    drop(wrapped_state);

    assert_eq!(
        cached_state.get_class_hash_at(ContractAddress::from(1u128)).unwrap(),
        ClassHash(StarkHash::from(2u128))
    );
}

#[test]
fn test_nonce() {
    let contract_address = ContractAddress::from(1u128);

    let mut cached_state = CachedState::default();

    cached_state.increment_nonce(contract_address).unwrap();

    let mut wrapped_state = DynStateWrapper::new(&mut cached_state);

    assert_eq!(
        wrapped_state.get_raw_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    wrapped_state.increment_nonce(contract_address).unwrap();

    assert_eq!(
        wrapped_state.get_raw_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(2u128))
    );

    wrapped_state.commit().unwrap();

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(2u128))
    );

    drop(wrapped_state);

    assert_eq!(cached_state.get_nonce_at(contract_address).unwrap(), Nonce(StarkFelt::from(2u128)));
}

#[test]
fn test_storage() {
    let contract_address = ContractAddress::from(1u128);
    let storage_key = StorageKey::from(1u128);

    let mut cached_state = CachedState::default();

    cached_state.set_storage_at(contract_address, storage_key, StarkFelt::from(1u128)).unwrap();

    let mut wrapped_state = DynStateWrapper::new(&mut cached_state);

    assert_eq!(
        wrapped_state.get_raw_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(1u128)
    );

    assert_eq!(
        wrapped_state.get_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(1u128)
    );

    wrapped_state.set_storage_at(contract_address, storage_key, StarkFelt::from(2u128)).unwrap();

    assert_eq!(
        wrapped_state.get_raw_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(1u128)
    );

    assert_eq!(
        wrapped_state.get_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(2u128)
    );

    wrapped_state.commit().unwrap();

    assert_eq!(
        wrapped_state.get_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(2u128)
    );

    drop(wrapped_state);

    assert_eq!(
        cached_state.get_storage_at(contract_address, storage_key).unwrap(),
        StarkFelt::from(2u128)
    );
}

#[test]
fn test_compiled_class_hash() {
    let class_hash = ClassHash(StarkHash::from(1u128));
    let compiled_class_hash = CompiledClassHash(StarkHash::from(2u128));

    let mut cached_state = CachedState::default();

    cached_state.set_compiled_class_hash(class_hash, compiled_class_hash).unwrap();

    let mut wrapped_state = DynStateWrapper::new(&mut cached_state);

    assert_eq!(wrapped_state.get_raw_compiled_class_hash(class_hash).unwrap(), compiled_class_hash);

    assert_eq!(wrapped_state.get_compiled_class_hash(class_hash).unwrap(), compiled_class_hash);

    wrapped_state
        .set_compiled_class_hash(class_hash, CompiledClassHash(StarkHash::from(3u128)))
        .unwrap();

    assert_eq!(wrapped_state.get_raw_compiled_class_hash(class_hash).unwrap(), compiled_class_hash);

    assert_eq!(
        wrapped_state.get_compiled_class_hash(class_hash).unwrap(),
        CompiledClassHash(StarkHash::from(3u128))
    );

    wrapped_state.commit().unwrap();

    assert_eq!(
        wrapped_state.get_compiled_class_hash(class_hash).unwrap(),
        CompiledClassHash(StarkHash::from(3u128))
    );

    drop(wrapped_state);

    assert_eq!(
        cached_state.get_compiled_class_hash(class_hash).unwrap(),
        CompiledClassHash(StarkHash::from(3u128))
    );
}

#[test]
fn test_multiple_nonce_updates() {
    let contract_address = ContractAddress::from(1u128);

    let mut cached_state = CachedState::default();

    cached_state.increment_nonce(contract_address).unwrap();

    let mut wrapped_state = DynStateWrapper::new(&mut cached_state);

    assert_eq!(
        wrapped_state.get_raw_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    wrapped_state.increment_nonce(contract_address).unwrap();
    wrapped_state.increment_nonce(contract_address).unwrap();

    assert_eq!(
        wrapped_state.get_raw_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(1u128))
    );

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(3u128))
    );

    wrapped_state.commit().unwrap();

    assert_eq!(
        wrapped_state.get_nonce_at(contract_address).unwrap(),
        Nonce(StarkFelt::from(3u128))
    );

    drop(wrapped_state);

    assert_eq!(cached_state.get_nonce_at(contract_address).unwrap(), Nonce(StarkFelt::from(3u128)));
}
