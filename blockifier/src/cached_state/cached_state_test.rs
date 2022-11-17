use std::collections::HashMap;

use pretty_assertions::assert_eq;
use starknet_api::{Nonce, StarkHash};

use super::*;

#[test]
fn gets_nonce() -> Result<()> {
    let contract_address = ContractAddress::try_from(StarkHash::try_from(0)?)?;
    let initial_nonce = Nonce(StarkHash::from(1));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([(contract_address, initial_nonce)]),
    });
    assert_eq!(*state.get_nonce_at(contract_address).unwrap(), initial_nonce);
    Ok(())
}

#[test]
fn increments_nonce() -> Result<()> {
    let contract_address1 = ContractAddress::try_from(StarkHash::try_from(100)?)?;
    let contract_address2 = ContractAddress::try_from(StarkHash::try_from(200)?)?;
    let initial_nonce1 = Nonce(StarkHash::from(1));
    let initial_nonce2 = Nonce(StarkHash::from(1));
    let mut state = CachedState::new(DictStateReader {
        contract_address_to_nonce: HashMap::from([
            (contract_address1, initial_nonce1),
            (contract_address2, initial_nonce2),
        ]),
    });

    state.increment_nonce(contract_address1)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce(StarkHash::from(2)));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce(StarkHash::from(1)));

    state.increment_nonce(contract_address1)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce(StarkHash::from(3)));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce(StarkHash::from(1)));

    state.increment_nonce(contract_address2)?;
    assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), Nonce(StarkHash::from(3)));
    assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), Nonce(StarkHash::from(2)));
    Ok(())
}
