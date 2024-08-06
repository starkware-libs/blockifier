use std::collections::{HashMap, HashSet};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::StarknetApiError;
use starknet_core::types::FieldElement;

use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};

#[cfg(test)]
#[path = "state_wrapper_test.rs"]
mod test;

/// DynStateWrapper is a wrapper that works as a TransactionState, but using only the dyn State
/// trait.
///
/// The reason of creating this wrapper is to allow the usage of the anything that implements the
/// State trait, as Transactional, it was created to be used in the fallback mechanism of the in the
/// following way:
/// - We have state A, that is a `&mut dyn State`
/// - We create wrapped state B, that is a `DynStateWrapper<'_>`, that wraps the state A
/// - We call the fallback mechanism with the wrapped state B
/// - The fallback mechanism will call the `commit` method of the wrapped state B if everything is
///   ok
/// - If execution fails, the wrapped state B will be dropped, and the state A will be untouched
///
/// This way, we can use the fallback mechanism with any state that implements the State trait.
pub struct DynStateWrapper<'a> {
    pub state: &'a mut dyn State,

    pub storage_updates: HashMap<(ContractAddress, StorageKey), StarkFelt>,
    pub nonce_updates: HashMap<ContractAddress, u128>,
    pub class_hashes: HashMap<ContractAddress, ClassHash>,
    pub contract_classes: HashMap<ClassHash, ContractClass>,
    pub compiled_class_hashes: HashMap<ClassHash, CompiledClassHash>,
}

impl<'a> DynStateWrapper<'a> {
    pub fn new(state: &'a mut dyn State) -> Self {
        Self {
            state,
            storage_updates: Default::default(),
            nonce_updates: Default::default(),
            class_hashes: Default::default(),
            contract_classes: Default::default(),
            compiled_class_hashes: Default::default(),
        }
    }

    /// Commits the update to the state, and clears the updates.
    pub fn commit(&mut self) -> StateResult<()> {
        for ((contract_address, key), value) in &self.storage_updates {
            self.state.set_storage_at(*contract_address, *key, *value)?
        }

        for (contract_address, num_of_updates) in &self.nonce_updates {
            for _ in 0..*num_of_updates {
                self.state.increment_nonce(*contract_address)?;
            }
        }

        for (contract_address, class_hash) in &self.class_hashes {
            self.state.set_class_hash_at(*contract_address, *class_hash)?;
        }

        for (class_hash, contract_class) in &self.contract_classes {
            self.state.set_contract_class(*class_hash, contract_class.clone())?;
        }

        for (class_hash, compiled_class_hash) in &self.compiled_class_hashes {
            self.state.set_compiled_class_hash(*class_hash, *compiled_class_hash)?;
        }

        self.abort();

        Ok(())
    }

    /// Aborts the updates (clears the updates).
    pub fn abort(&mut self) {
        self.storage_updates.clear();
        self.nonce_updates.clear();
        self.class_hashes.clear();
        self.contract_classes.clear();
        self.compiled_class_hashes.clear();
    }
}

impl StateReader for DynStateWrapper<'_> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        Ok(self
            .storage_updates
            .get(&(contract_address, key))
            .copied()
            .unwrap_or(self.state.get_storage_at(contract_address, key)?))
    }

    fn get_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let current_nonce = FieldElement::from(self.state.get_nonce_at(contract_address)?.0);

        let delta = *self.nonce_updates.get(&contract_address).unwrap_or(&0u128);
        let delta = FieldElement::from(delta);

        // Check if an overflow occurred during increment.
        match StarkFelt::from(current_nonce + FieldElement::ONE * delta) {
            StarkFelt::ZERO => Err(StateError::from(StarknetApiError::OutOfRange {
                string: format!("{:?}", current_nonce),
            })),
            incremented_felt => Ok(Nonce(incremented_felt)),
        }
    }

    fn get_class_hash_at(&self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        Ok(self
            .class_hashes
            .get(&contract_address)
            .copied()
            .unwrap_or(self.state.get_class_hash_at(contract_address)?))
    }

    fn get_compiled_contract_class(&self, class_hash: ClassHash) -> StateResult<ContractClass> {
        Ok(self
            .contract_classes
            .get(&class_hash)
            .cloned()
            .unwrap_or(self.state.get_compiled_contract_class(class_hash)?))
    }

    fn get_compiled_class_hash(&self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        Ok(self
            .compiled_class_hashes
            .get(&class_hash)
            .cloned()
            .unwrap_or(self.state.get_compiled_class_hash(class_hash)?))
    }

    fn get_fee_token_balance(
        &mut self,
        contract_address: ContractAddress,
        fee_token_address: ContractAddress,
    ) -> Result<(StarkFelt, StarkFelt), StateError> {
        self.state.get_fee_token_balance(contract_address, fee_token_address)
    }
}

impl State for DynStateWrapper<'_> {
    fn set_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
        value: StarkFelt,
    ) -> StateResult<()> {
        self.storage_updates.insert((contract_address, key), value);

        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: ContractAddress) -> StateResult<()> {
        let value = self.nonce_updates.get(&contract_address).unwrap_or(&0u128);

        self.nonce_updates.insert(contract_address, value + 1);

        Ok(())
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: ContractAddress,
        class_hash: ClassHash,
    ) -> StateResult<()> {
        self.class_hashes.insert(contract_address, class_hash);

        Ok(())
    }

    fn set_contract_class(
        &mut self,
        class_hash: ClassHash,
        contract_class: ContractClass,
    ) -> StateResult<()> {
        self.contract_classes.insert(class_hash, contract_class);

        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: ClassHash,
        compiled_class_hash: CompiledClassHash,
    ) -> StateResult<()> {
        self.compiled_class_hashes.insert(class_hash, compiled_class_hash);

        Ok(())
    }

    fn add_visited_pcs(&mut self, class_hash: ClassHash, pcs: &HashSet<usize>) {
        self.state.add_visited_pcs(class_hash, pcs)
    }
}

#[cfg(test)]
impl DynStateWrapper<'_> {
    pub fn get_raw_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        self.state.get_storage_at(contract_address, key)
    }

    pub fn get_raw_nonce_at(&self, contract_address: ContractAddress) -> StateResult<Nonce> {
        self.state.get_nonce_at(contract_address)
    }

    pub fn get_raw_class_hash_at(
        &self,
        contract_address: ContractAddress,
    ) -> StateResult<ClassHash> {
        self.state.get_class_hash_at(contract_address)
    }

    pub fn get_raw_compiled_contract_class(
        &self,
        class_hash: ClassHash,
    ) -> StateResult<ContractClass> {
        self.state.get_compiled_contract_class(class_hash)
    }

    pub fn get_raw_compiled_class_hash(
        &self,
        class_hash: ClassHash,
    ) -> StateResult<CompiledClassHash> {
        self.state.get_compiled_class_hash(class_hash)
    }
}
