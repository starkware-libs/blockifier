use cairo_native::starknet::StarkNetSyscallHandler;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;

use super::sierra_utils::{felt_to_starkfelt, starkfelt_to_felt};
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::state::state_api::State;

pub struct NativeSyscallHandler<'state> {
    pub state: &'state mut dyn State,
    pub storage_address: ContractAddress,
    pub execution_context: EntryPointExecutionContext,
}

impl<'state> StarkNetSyscallHandler for NativeSyscallHandler<'state> {
    fn get_block_hash(
        &mut self,
        block_number: u64,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Felt> {
        log::debug!("Native syscall handler - get_block_hash");

        let current_block_number = self.execution_context.block_context.block_number.0;

        if current_block_number < 10 || block_number > current_block_number - 10 {
            let out_of_range_felt =
                Felt::from_bytes_be_slice("Block number out of range".as_bytes());

            return Err(vec![out_of_range_felt]);
        }

        let key = StorageKey::from(block_number);
        let block_hash_address = ContractAddress::from(1u128);

        match self.state.get_storage_at(block_hash_address, key) {
            Ok(value) => Ok(Felt::from_bytes_be_slice(value.bytes())),
            Err(e) => Err(vec![Felt::from_bytes_be_slice(e.to_string().as_bytes())]),
        }
    }

    fn get_execution_info(
        &mut self,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<cairo_native::starknet::ExecutionInfo> {
        todo!("Native syscall handler - get_execution_info") // only implemented for v1 in cairo native, but untested
    }

    fn deploy(
        &mut self,
        _class_hash: Felt,
        _contract_address_salt: Felt,
        _calldata: &[Felt],
        _deploy_from_zero: bool,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<(Felt, Vec<Felt>)> {
        todo!("Native syscall handler - deploy")
    }

    fn replace_class(
        &mut self,
        _class_hash: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        todo!("Native syscall handler - replace_class")
    }

    fn library_call(
        &mut self,
        _class_hash: Felt,
        _function_selector: Felt,
        _calldata: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Vec<Felt>> {
        todo!("Native syscall handler - library_call")
    }

    fn call_contract(
        &mut self,
        _address: Felt,
        _entry_point_selector: Felt,
        _calldata: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Vec<Felt>> {
        todo!("Native syscall handler - call_contract")
    }

    fn storage_read(
        &mut self,
        _address_domain: u32,
        address: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Felt> {
        // TODO - in progress - Dom
        let storage_key = StorageKey(PatriciaKey::try_from(felt_to_starkfelt(address)).unwrap());
        let read_result = self.state.get_storage_at(self.storage_address, storage_key);
        let unsafe_read_result = read_result.unwrap(); // TODO handle properly
        Ok(starkfelt_to_felt(unsafe_read_result))
    }

    fn storage_write(
        &mut self,
        _address_domain: u32,
        address: Felt,
        value: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        let storage_key = StorageKey(PatriciaKey::try_from(felt_to_starkfelt(address)).unwrap());
        let write_result =
            self.state.set_storage_at(self.storage_address, storage_key, felt_to_starkfelt(value));
        write_result.unwrap(); // TODO handle properly
        Ok(())
    }

    fn emit_event(
        &mut self,
        _keys: &[Felt],
        _data: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        todo!("Native syscall handler - emit_event")
    }

    fn send_message_to_l1(
        &mut self,
        _to_address: Felt,
        _payload: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        todo!("Native syscall handler - send_message_to_l1")
    }

    fn keccak(
        &mut self,
        _input: &[u64],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<cairo_native::starknet::U256> {
        todo!("Native syscall handler - keccak")
    }

    fn secp256k1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_add") // unimplemented in cairo native
    }

    fn secp256k1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_get_point_from_x") // unimplemented in cairo native
    }

    fn secp256k1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<(
        cairo_native::starknet::U256,
        cairo_native::starknet::U256,
    )> {
        todo!("Native syscall handler - secp256k1_get_xy") // unimplemented in cairo native
    }

    fn secp256k1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_mul") // unimplemented in cairo native
    }

    fn secp256k1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_new") // unimplemented in cairo native
    }

    fn secp256r1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_add") // unimplemented in cairo native
    }

    fn secp256r1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_get_point_from_x") // unimplemented in cairo native
    }

    fn secp256r1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<(
        cairo_native::starknet::U256,
        cairo_native::starknet::U256,
    )> {
        todo!("Native syscall handler - secp256r1_get_xy") // unimplemented in cairo native
    }

    fn secp256r1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_mul") // unimplemented in cairo native
    }

    fn secp256r1_new(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_new") // unimplemented in cairo native
    }

    fn pop_log(&mut self) {
        todo!("Native syscall handler - pop_log") // unimplemented in cairo native
    }

    fn set_account_contract_address(&mut self, _contract_address: Felt) {
        todo!("Native syscall handler - set_account_contract_address") // unimplemented in cairo native
    }

    fn set_block_number(&mut self, _block_number: u64) {
        todo!("Native syscall handler - set_block_number") // unimplemented in cairo native
    }

    fn set_block_timestamp(&mut self, _block_timestamp: u64) {
        todo!("Native syscall handler - set_block_timestamp") // unimplemented in cairo native
    }

    fn set_caller_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_caller_address") // unimplemented in cairo native
    }

    fn set_chain_id(&mut self, _chain_id: Felt) {
        todo!("Native syscall handler - set_chain_id") // unimplemented in cairo native
    }

    fn set_contract_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_contract_address") // unimplemented in cairo native
    }

    fn set_max_fee(&mut self, _max_fee: u128) {
        todo!("Native syscall handler - set_max_fee") // unimplemented in cairo native
    }

    fn set_nonce(&mut self, _nonce: Felt) {
        todo!("Native syscall handler - set_nonce") // unimplemented in cairo native
    }

    fn set_sequencer_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_sequencer_address") // unimplemented in cairo native
    }

    fn set_signature(&mut self, _signature: &[Felt]) {
        todo!("Native syscall handler - set_signature") // unimplemented in cairo native
    }

    fn set_transaction_hash(&mut self, _transaction_hash: Felt) {
        todo!("Native syscall handler - set_transaction_hash") // unimplemented in cairo native
    }

    fn set_version(&mut self, _version: Felt) {
        todo!("Native syscall handler - set_version") // unimplemented in cairo native
    }
}
