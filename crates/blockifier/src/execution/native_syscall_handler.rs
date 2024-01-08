use cairo_native::starknet::StarkNetSyscallHandler;
use starknet_types_core::felt::Felt;

pub struct NativeSyscallHandler {

}

impl StarkNetSyscallHandler for NativeSyscallHandler {
    fn get_block_hash(
        &mut self,
        _block_number: u64,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Felt> {
        todo!("Native syscall handler - get_block_hash")
    }

    fn get_execution_info(&mut self, _remaining_gas: &mut u128) -> cairo_native::starknet::SyscallResult<cairo_native::starknet::ExecutionInfo> {
        todo!("Native syscall handler - get_execution_info")
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

    fn replace_class(&mut self, _class_hash: Felt, _remaining_gas: &mut u128) -> cairo_native::starknet::SyscallResult<()> {
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
        _address: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Felt> {
        // TODO - in progress - Dom
        Ok(Felt::from_dec_str("0").unwrap())
    }

    fn storage_write(
        &mut self,
        _address_domain: u32,
        _address: Felt,
        _value: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        // TODO
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

    fn keccak(&mut self, _input: &[u64], _remaining_gas: &mut u128) -> cairo_native::starknet::SyscallResult<cairo_native::starknet::U256> {
        todo!("Native syscall handler - keccak")
    }

    fn secp256k1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_add")
    }

    fn secp256k1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_get_point_from_x")
    }

    fn secp256k1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!("Native syscall handler - secp256k1_get_xy")
    }

    fn secp256k1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_mul")
    }

    fn secp256k1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256k1_new")
    }

    fn secp256r1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_add")
    }

    fn secp256r1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_get_point_from_x")
    }

    fn secp256r1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!("Native syscall handler - secp256r1_get_xy")
    }

    fn secp256r1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_mul")
    }

    fn secp256r1_new(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!("Native syscall handler - secp256r1_new")
    }

    fn pop_log(&mut self) {
        todo!("Native syscall handler - pop_log")
    }

    fn set_account_contract_address(&mut self, _contract_address: Felt) {
        todo!("Native syscall handler - set_account_contract_address")
    }

    fn set_block_number(&mut self, _block_number: u64) {
        todo!("Native syscall handler - set_block_number")
    }

    fn set_block_timestamp(&mut self, _block_timestamp: u64) {
        todo!("Native syscall handler - set_block_timestamp")
    }

    fn set_caller_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_caller_address")
    }

    fn set_chain_id(&mut self, _chain_id: Felt) {
        todo!("Native syscall handler - set_chain_id")
    }

    fn set_contract_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_contract_address")
    }

    fn set_max_fee(&mut self, _max_fee: u128) {
        todo!("Native syscall handler - set_max_fee")
    }

    fn set_nonce(&mut self, _nonce: Felt) {
        todo!("Native syscall handler - set_nonce")
    }

    fn set_sequencer_address(&mut self, _address: Felt) {
        todo!("Native syscall handler - set_sequencer_address")
    }

    fn set_signature(&mut self, _signature: &[Felt]) {
        todo!("Native syscall handler - set_signature")
    }

    fn set_transaction_hash(&mut self, _transaction_hash: Felt) {
        todo!("Native syscall handler - set_transaction_hash")
    }

    fn set_version(&mut self, _version: Felt) {
        todo!("Native syscall handler - set_version")
    }
}