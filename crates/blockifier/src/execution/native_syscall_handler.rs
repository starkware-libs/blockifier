use std::sync::Arc;

use cairo_native::starknet::StarkNetSyscallHandler;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector, EthAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, EventContent, EventData, EventKey, L2ToL1Payload};
use starknet_types_core::felt::Felt;

use super::sierra_utils::{felt_to_starkfelt, starkfelt_to_felt};
use crate::abi::constants;
use crate::execution::call_info::{MessageToL1, OrderedEvent, OrderedL2ToL1Message};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{CallEntryPoint, CallType, EntryPointExecutionContext};
use crate::execution::syscalls::hint_processor::{
    execute_inner_call_raw, BLOCK_NUMBER_OUT_OF_RANGE_ERROR, FAILED_TO_GET_CONTRACT_CLASS,
    FAILED_TO_SET_CLASS_HASH, FORBIDDEN_CLASS_REPLACEMENT, INVALID_ARGUMENT,
    INVALID_EXECUTION_MODE_ERROR, INVALID_INPUT_LENGTH_ERROR,
};
use crate::state::state_api::State;

pub struct NativeSyscallHandler<'state> {
    pub state: &'state mut dyn State,
    pub storage_address: ContractAddress,
    pub execution_context: EntryPointExecutionContext,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
}

impl<'state> StarkNetSyscallHandler for NativeSyscallHandler<'state> {
    fn get_block_hash(
        &mut self,
        block_number: u64,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Felt> {
        if self.execution_context.execution_mode == ExecutionMode::Validate {
            let execution_mode_err = Felt::from_hex(INVALID_EXECUTION_MODE_ERROR).unwrap();

            return Err(vec![execution_mode_err]);
        }

        let current_block_number = self.execution_context.block_context.block_number.0;

        if current_block_number < constants::STORED_BLOCK_HASH_BUFFER
            || block_number > current_block_number - constants::STORED_BLOCK_HASH_BUFFER
        {
            // todo: possibly remove unwraps here, but `panic` is unreachable in this case
            let out_of_range_felt = Felt::from_hex(BLOCK_NUMBER_OUT_OF_RANGE_ERROR).unwrap();

            return Err(vec![out_of_range_felt]);
        }

        let key = StorageKey::try_from(StarkFelt::from(block_number))
            .map_err(|e| vec![Felt::from_bytes_be_slice(e.to_string().as_bytes())])?;
        let block_hash_address =
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .map_err(|e| vec![Felt::from_bytes_be_slice(e.to_string().as_bytes())])?;

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
        class_hash: Felt,
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        let class_hash = ClassHash(StarkHash::from(felt_to_starkfelt(class_hash)));
        let contract_class = self
            .state
            .get_compiled_contract_class(class_hash)
            .map_err(|_| vec![Felt::from_hex(FAILED_TO_GET_CONTRACT_CLASS).unwrap()])?;

        let set_class_hash_lambda =
            |state: &mut dyn State| -> cairo_native::starknet::SyscallResult<()> {
                state
                    .set_class_hash_at(self.storage_address, class_hash)
                    .map_err(|_| vec![Felt::from_hex(FAILED_TO_SET_CLASS_HASH).unwrap()])?;

                Ok(())
            };

        match contract_class {
            ContractClass::V0(_) => Err(vec![Felt::from_hex(FORBIDDEN_CLASS_REPLACEMENT).unwrap()]),
            ContractClass::V1(_) => set_class_hash_lambda(self.state),
            ContractClass::V1Sierra(_) => {
                // todo: assure if it is correct
                set_class_hash_lambda(self.state)
            }
        }
    }

    fn library_call(
        &mut self,
        class_hash: Felt,
        function_selector: Felt,
        calldata: &[Felt],
        remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Vec<Felt>> {
        let call_to_external = true;
        let entry_point_type =
            if call_to_external { EntryPointType::External } else { EntryPointType::L1Handler };

        let class_hash = ClassHash(StarkHash::from(felt_to_starkfelt(class_hash)));

        let wrapper_calldata = Calldata(Arc::new(
            calldata
                .to_vec()
                .iter()
                .map(|felt| felt_to_starkfelt(*felt))
                .collect::<Vec<StarkFelt>>(),
        ));

        let entry_point = CallEntryPoint {
            class_hash: Some(class_hash),
            code_address: None,
            entry_point_type,
            entry_point_selector: EntryPointSelector(StarkHash::from(felt_to_starkfelt(
                function_selector,
            ))),
            calldata: wrapper_calldata,
            // The call context remains the same in a library call.
            storage_address: self.storage_address,
            // todo: check if it is correct
            caller_address: self.storage_address,
            call_type: CallType::Delegate,
            initial_gas: *remaining_gas as u64,
        };

        execute_inner_call_raw(entry_point, self.state, &mut self.execution_context)
    }

    fn call_contract(
        &mut self,
        address: Felt,
        entry_point_selector: Felt,
        calldata: &[Felt],
        remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<Vec<Felt>> {
        let storage_address = ContractAddress::try_from(felt_to_starkfelt(address))
            .map_err(|_| vec![Felt::from_hex(INVALID_ARGUMENT).unwrap()])?;

        if self.execution_context.execution_mode == ExecutionMode::Validate
            && self.storage_address != storage_address
        {
            return Err(vec![Felt::from_hex(INVALID_EXECUTION_MODE_ERROR).unwrap()]);
        }

        let wrapper_calldata = Calldata(Arc::new(
            calldata
                .to_vec()
                .iter()
                .map(|felt| felt_to_starkfelt(*felt))
                .collect::<Vec<StarkFelt>>(),
        ));

        let entry_point = CallEntryPoint {
            class_hash: None,
            code_address: Some(storage_address),
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(StarkHash::from(felt_to_starkfelt(
                entry_point_selector,
            ))),
            calldata: wrapper_calldata,
            storage_address,
            caller_address: self.storage_address,
            call_type: CallType::Call,
            initial_gas: *remaining_gas as u64,
        };

        execute_inner_call_raw(entry_point, self.state, &mut self.execution_context)
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
        keys: &[Felt],
        data: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        let order = self.execution_context.n_emitted_events;

        self.events.push(OrderedEvent {
            order,
            event: EventContent {
                keys: keys
                    .to_vec()
                    .iter()
                    .map(|felt| EventKey(felt_to_starkfelt(*felt)))
                    .collect::<Vec<EventKey>>(),
                data: EventData(
                    data.to_vec().iter().map(|felt| felt_to_starkfelt(*felt)).collect(),
                ),
            },
        });

        self.execution_context.n_emitted_events += 1;

        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        to_address: Felt,
        payload: &[Felt],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<()> {
        let order = self.execution_context.n_sent_messages_to_l1;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message {
            order,
            message: MessageToL1 {
                // todo: handle error properly
                to_address: EthAddress::try_from(felt_to_starkfelt(to_address)).unwrap(),
                payload: L2ToL1Payload(
                    payload.to_vec().iter().map(|felt| felt_to_starkfelt(*felt)).collect(),
                ),
            },
        });

        self.execution_context.n_sent_messages_to_l1 += 1;

        Ok(())
    }

    fn keccak(
        &mut self,
        input: &[u64],
        _remaining_gas: &mut u128,
    ) -> cairo_native::starknet::SyscallResult<cairo_native::starknet::U256> {
        let input_len = input.len();

        const KECCAK_FULL_RATE_IN_WORDS: usize = 17;
        let (_, remainder) = num_integer::div_rem(input_len, KECCAK_FULL_RATE_IN_WORDS);

        if remainder != 0 {
            return Err(vec![Felt::from_hex(INVALID_INPUT_LENGTH_ERROR).unwrap()]);
        }

        let input_chunks = input.chunks_exact(KECCAK_FULL_RATE_IN_WORDS);
        let mut keccak_state = [0u64; 25];

        for chunk in input_chunks {
            for (i, val) in chunk.iter().enumerate() {
                keccak_state[i] ^= val;
            }
            keccak::f1600(&mut keccak_state)
        }

        let hash: Vec<Vec<u8>> =
            [keccak_state[0], keccak_state[1], keccak_state[2], keccak_state[3]]
                .iter()
                .map(|e| e.to_le_bytes().to_vec())
                .collect();

        let hash = hash.concat();

        Ok(cairo_native::starknet::U256(hash[0..32].try_into().unwrap()))
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
