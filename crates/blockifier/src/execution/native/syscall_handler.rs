use std::collections::HashSet;
use std::hash::RandomState;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_native::starknet::{
    BlockInfo, ExecutionInfoV2, Secp256k1Point, Secp256r1Point, StarkNetSyscallHandler,
    SyscallResult, TxV2Info, U256,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::ToPrimitive;
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector, EthAddress,
    PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, L2ToL1Payload,
};
use starknet_types_core::felt::Felt;

use super::utils::{
    allocate_point, big4int_to_u256, calculate_resource_bounds, contract_address_to_native_felt,
    default_tx_v2_info, encode_str_as_felts, native_felt_to_stark_felt, stark_felt_to_native_felt,
    u256_to_biguint,
};
use crate::abi::constants;
use crate::execution::call_info::{CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, ConstructorContext, EntryPointExecutionContext,
};
use crate::execution::execution_utils::{execute_deployment, max_fee_for_execution_info};
use crate::execution::syscalls::exceeds_event_size_limit;
use crate::execution::syscalls::hint_processor::{
    SyscallExecutionError, BLOCK_NUMBER_OUT_OF_RANGE_ERROR, INVALID_INPUT_LENGTH_ERROR,
};
use crate::execution::syscalls::secp::{
    SecpAddRequest, SecpAddResponse, SecpGetPointFromXRequest, SecpGetPointFromXResponse,
    SecpHintProcessor, SecpMulRequest, SecpMulResponse, SecpNewRequest, SecpNewResponse,
};
use crate::state::state_api::State;
use crate::transaction::objects::TransactionInfo;

pub struct NativeSyscallHandler<'state> {
    // Input for execution
    pub state: &'state mut dyn State,
    pub execution_resources: &'state mut ExecutionResources,
    pub execution_context: &'state mut EntryPointExecutionContext,

    // Call information
    pub caller_address: ContractAddress,
    pub contract_address: ContractAddress,
    pub entry_point_selector: StarkFelt,

    // Execution results
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub inner_calls: Vec<CallInfo>,
    // Additional execution result info
    pub storage_read_values: Vec<StarkFelt>,
    pub accessed_storage_keys: HashSet<StorageKey, RandomState>,

    // Secp hint processors.
    pub secp256k1_hint_processor: SecpHintProcessor<ark_secp256k1::Config>,
    pub secp256r1_hint_processor: SecpHintProcessor<ark_secp256r1::Config>,
}

impl<'state> NativeSyscallHandler<'_> {
    pub fn new(
        state: &'state mut dyn State,
        caller_address: ContractAddress,
        contract_address: ContractAddress,
        entry_point_selector: EntryPointSelector,
        execution_resources: &'state mut ExecutionResources,
        execution_context: &'state mut EntryPointExecutionContext,
    ) -> NativeSyscallHandler<'state> {
        NativeSyscallHandler {
            state,
            caller_address,
            contract_address,
            entry_point_selector: entry_point_selector.0,
            execution_resources,
            execution_context,
            events: Vec::new(),
            l2_to_l1_messages: Vec::new(),
            inner_calls: Vec::new(),
            secp256k1_hint_processor: Default::default(),
            secp256r1_hint_processor: Default::default(),
            storage_read_values: Vec::new(),
            accessed_storage_keys: HashSet::new(),
        }
    }
}

impl<'state> StarkNetSyscallHandler for NativeSyscallHandler<'state> {
    fn get_block_hash(
        &mut self,
        block_number: u64,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Felt> {
        if self.execution_context.execution_mode == ExecutionMode::Validate {
            let err = SyscallExecutionError::InvalidSyscallInExecutionMode {
                syscall_name: "get_block_hash".to_string(),
                execution_mode: ExecutionMode::Validate,
            };

            return Err(encode_str_as_felts(&err.to_string()));
        }

        let current_block_number =
            self.execution_context.tx_context.block_context.block_info.block_number.0;

        if current_block_number < constants::STORED_BLOCK_HASH_BUFFER
            || block_number > current_block_number - constants::STORED_BLOCK_HASH_BUFFER
        {
            // `panic` is unreachable in this case, also this is covered by tests so we can safely
            // unwrap
            let out_of_range_felt = Felt::from_hex(BLOCK_NUMBER_OUT_OF_RANGE_ERROR).unwrap();

            return Err(vec![out_of_range_felt]);
        }

        let key = StorageKey::try_from(StarkFelt::from(block_number))
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;
        let block_hash_address =
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        match self.state.get_storage_at(block_hash_address, key) {
            Ok(value) => Ok(Felt::from_bytes_be_slice(value.bytes())),
            Err(e) => Err(encode_str_as_felts(&e.to_string())),
        }
    }

    fn get_execution_info(
        &mut self,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        panic!("Blockifier doesn't use this syscall")
    }

    fn get_execution_info_v2(
        &mut self,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<ExecutionInfoV2> {
        // Get Block Info
        let block_info = &self.execution_context.tx_context.block_context.block_info;
        let native_block_info: BlockInfo = if self.execution_context.execution_mode
            == ExecutionMode::Validate
        {
            let versioned_constants = self.execution_context.versioned_constants();
            let block_number = block_info.block_number.0;
            let block_timestamp = block_info.block_timestamp.0;
            // Round down to the nearest multiple of validate_block_number_rounding.
            let validate_block_number_rounding =
                versioned_constants.get_validate_block_number_rounding();
            let rounded_block_number =
                (block_number / validate_block_number_rounding) * validate_block_number_rounding;
            // Round down to the nearest multiple of validate_timestamp_rounding.
            let validate_timestamp_rounding = versioned_constants.get_validate_timestamp_rounding();
            let rounded_timestamp =
                (block_timestamp / validate_timestamp_rounding) * validate_timestamp_rounding;
            BlockInfo {
                block_number: rounded_block_number,
                block_timestamp: rounded_timestamp,
                sequencer_address: Felt::ZERO,
            }
        } else {
            BlockInfo {
                block_number: block_info.block_number.0,
                block_timestamp: block_info.block_timestamp.0,
                sequencer_address: contract_address_to_native_felt(block_info.sequencer_address),
            }
        };

        // Get Transaction Info
        let tx_info = &self.execution_context.tx_context.tx_info;
        let mut native_tx_info = TxV2Info {
            version: stark_felt_to_native_felt(tx_info.signed_version().0),
            account_contract_address: contract_address_to_native_felt(tx_info.sender_address()),
            max_fee: max_fee_for_execution_info(tx_info).to_u128().unwrap(),
            signature: tx_info.signature().0.into_iter().map(stark_felt_to_native_felt).collect(),
            transaction_hash: stark_felt_to_native_felt(tx_info.transaction_hash().0),
            chain_id: Felt::from_hex(
                &self.execution_context.tx_context.block_context.chain_info.chain_id.as_hex(),
            )
            .unwrap(),
            nonce: stark_felt_to_native_felt(tx_info.nonce().0),
            ..default_tx_v2_info()
        };
        // If handling V3 transaction fill the "default" fields
        if let TransactionInfo::Current(context) = tx_info {
            let to_u32 = |x| match x {
                DataAvailabilityMode::L1 => 0,
                DataAvailabilityMode::L2 => 1,
            };
            native_tx_info = TxV2Info {
                resource_bounds: calculate_resource_bounds(context)?,
                tip: context.tip.0.into(),
                paymaster_data: context
                    .paymaster_data
                    .0
                    .iter()
                    .map(|f| stark_felt_to_native_felt(*f))
                    .collect(),
                nonce_data_availability_mode: to_u32(context.nonce_data_availability_mode),
                fee_data_availability_mode: to_u32(context.fee_data_availability_mode),
                account_deployment_data: context
                    .account_deployment_data
                    .0
                    .iter()
                    .map(|f| stark_felt_to_native_felt(*f))
                    .collect(),
                ..native_tx_info
            };
        }

        let caller_address = contract_address_to_native_felt(self.caller_address);
        let contract_address = contract_address_to_native_felt(self.contract_address);
        let entry_point_selector = stark_felt_to_native_felt(self.entry_point_selector);

        Ok(ExecutionInfoV2 {
            block_info: native_block_info,
            tx_info: native_tx_info,
            caller_address,
            contract_address,
            entry_point_selector,
        })
    }

    fn deploy(
        &mut self,
        class_hash: Felt,
        contract_address_salt: Felt,
        calldata: &[Felt],
        deploy_from_zero: bool,
        remaining_gas: &mut u128,
    ) -> SyscallResult<(Felt, Vec<Felt>)> {
        let deployer_address =
            if deploy_from_zero { ContractAddress::default() } else { self.contract_address };

        let class_hash = ClassHash(native_felt_to_stark_felt(class_hash));

        let wrapper_calldata = Calldata(Arc::new(
            calldata
                .iter()
                .map(|felt| native_felt_to_stark_felt(*felt))
                .collect::<Vec<StarkFelt>>(),
        ));

        let calculated_contract_address = calculate_contract_address(
            ContractAddressSalt(native_felt_to_stark_felt(contract_address_salt)),
            class_hash,
            &wrapper_calldata,
            deployer_address,
        )
        .map_err(|err| encode_str_as_felts(&err.to_string()))?;

        let ctor_context = ConstructorContext {
            class_hash,
            code_address: Some(calculated_contract_address),
            storage_address: calculated_contract_address,
            caller_address: deployer_address,
        };

        let call_info = execute_deployment(
            self.state,
            self.execution_resources,
            self.execution_context,
            ctor_context,
            wrapper_calldata,
            u64::try_from(*remaining_gas).unwrap(),
        )
        .map_err(|error| encode_str_as_felts(&error.to_string()))?;

        let return_data = call_info.execution.retdata.0[..]
            .iter()
            .map(|felt| stark_felt_to_native_felt(*felt))
            .collect();

        let contract_address_felt =
            Felt::from_bytes_be_slice(calculated_contract_address.0.key().bytes());

        self.inner_calls.push(call_info);

        Ok((contract_address_felt, return_data))
    }

    fn replace_class(&mut self, class_hash: Felt, _remaining_gas: &mut u128) -> SyscallResult<()> {
        let class_hash = ClassHash(StarkHash::from(native_felt_to_stark_felt(class_hash)));
        let contract_class = self
            .state
            .get_compiled_contract_class(class_hash)
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        match contract_class {
            ContractClass::V0(_) => Err(encode_str_as_felts(
                &SyscallExecutionError::ForbiddenClassReplacement { class_hash }.to_string(),
            )),
            ContractClass::V1(_) | ContractClass::V1Sierra(_) => {
                self.state
                    .set_class_hash_at(self.contract_address, class_hash)
                    .map_err(|e| encode_str_as_felts(&e.to_string()))?;

                Ok(())
            }
        }
    }

    fn library_call(
        &mut self,
        class_hash: Felt,
        function_selector: Felt,
        calldata: &[Felt],
        remaining_gas: &mut u128,
    ) -> SyscallResult<Vec<Felt>> {
        let class_hash = ClassHash(StarkHash::from(native_felt_to_stark_felt(class_hash)));

        let wrapper_calldata = Calldata(Arc::new(
            calldata
                .iter()
                .map(|felt| native_felt_to_stark_felt(*felt))
                .collect::<Vec<StarkFelt>>(),
        ));

        let entry_point = CallEntryPoint {
            class_hash: Some(class_hash),
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(StarkHash::from(native_felt_to_stark_felt(
                function_selector,
            ))),
            calldata: wrapper_calldata,
            // The call context remains the same in a library call.
            storage_address: self.contract_address,
            caller_address: self.caller_address,
            call_type: CallType::Delegate,
            initial_gas: u64::try_from(*remaining_gas).unwrap(),
        };

        let call_info = entry_point
            .execute(self.state, self.execution_resources, self.execution_context)
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        let retdata = call_info
            .execution
            .retdata
            .0
            .iter()
            .map(|felt| stark_felt_to_native_felt(*felt))
            .collect::<Vec<Felt>>();

        self.inner_calls.push(call_info);

        Ok(retdata)
    }

    fn call_contract(
        &mut self,
        address: Felt,
        entry_point_selector: Felt,
        calldata: &[Felt],
        remaining_gas: &mut u128,
    ) -> SyscallResult<Vec<Felt>> {
        let contract_address = ContractAddress::try_from(native_felt_to_stark_felt(address))
            .map_err(|error| encode_str_as_felts(&error.to_string()))?;

        if self.execution_context.execution_mode == ExecutionMode::Validate
            && self.contract_address != contract_address
        {
            let err = SyscallExecutionError::InvalidSyscallInExecutionMode {
                syscall_name: "call_contract".to_string(),
                execution_mode: ExecutionMode::Validate,
            };

            return Err(encode_str_as_felts(&err.to_string()));
        }

        let wrapper_calldata = Calldata(Arc::new(
            calldata
                .iter()
                .map(|felt| native_felt_to_stark_felt(*felt))
                .collect::<Vec<StarkFelt>>(),
        ));

        let entry_point = CallEntryPoint {
            class_hash: None,
            code_address: Some(contract_address),
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(StarkHash::from(native_felt_to_stark_felt(
                entry_point_selector,
            ))),
            calldata: wrapper_calldata,
            storage_address: contract_address,
            caller_address: self.caller_address,
            call_type: CallType::Call,
            initial_gas: u64::try_from(*remaining_gas).unwrap(),
        };

        let call_info = entry_point
            .execute(self.state, self.execution_resources, self.execution_context)
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        let retdata = call_info
            .execution
            .retdata
            .0
            .iter()
            .map(|felt| stark_felt_to_native_felt(*felt))
            .collect::<Vec<Felt>>();

        self.inner_calls.push(call_info);

        Ok(retdata)
    }

    fn storage_read(
        &mut self,
        _address_domain: u32,
        address: Felt,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Felt> {
        let key = StorageKey(
            PatriciaKey::try_from(native_felt_to_stark_felt(address))
                .map_err(|e| encode_str_as_felts(&e.to_string()))?,
        );

        let read_result = self.state.get_storage_at(self.contract_address, key);
        let value = read_result.map_err(|e| encode_str_as_felts(&e.to_string()))?;

        self.accessed_storage_keys.insert(key);
        self.storage_read_values.push(value);

        Ok(stark_felt_to_native_felt(value))
    }

    fn storage_write(
        &mut self,
        _address_domain: u32,
        address: Felt,
        value: Felt,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<()> {
        let key = StorageKey(
            PatriciaKey::try_from(native_felt_to_stark_felt(address))
                .map_err(|e| encode_str_as_felts(&e.to_string()))?,
        );
        self.accessed_storage_keys.insert(key);

        let write_result =
            self.state.set_storage_at(self.contract_address, key, native_felt_to_stark_felt(value));
        write_result.map_err(|e| encode_str_as_felts(&e.to_string()))?;

        Ok(())
    }

    fn emit_event(
        &mut self,
        keys: &[Felt],
        data: &[Felt],
        _remaining_gas: &mut u128,
    ) -> SyscallResult<()> {
        let order = self.execution_context.n_emitted_events;
        let event = EventContent {
            keys: keys
                .iter()
                .map(|felt| EventKey(native_felt_to_stark_felt(*felt)))
                .collect::<Vec<EventKey>>(),
            data: EventData(data.iter().map(|felt| native_felt_to_stark_felt(*felt)).collect()),
        };

        exceeds_event_size_limit(
            self.execution_context.versioned_constants(),
            self.execution_context.n_emitted_events + 1,
            &event,
        )
        .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        self.events.push(OrderedEvent { order, event });

        self.execution_context.n_emitted_events += 1;

        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        to_address: Felt,
        payload: &[Felt],
        _remaining_gas: &mut u128,
    ) -> SyscallResult<()> {
        let order = self.execution_context.n_sent_messages_to_l1;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message {
            order,
            message: MessageToL1 {
                to_address: EthAddress::try_from(native_felt_to_stark_felt(to_address))
                    .map_err(|e| encode_str_as_felts(&e.to_string()))?,
                payload: L2ToL1Payload(
                    payload.iter().map(|felt| native_felt_to_stark_felt(*felt)).collect(),
                ),
            },
        });

        self.execution_context.n_sent_messages_to_l1 += 1;

        Ok(())
    }

    fn keccak(&mut self, input: &[u64], _remaining_gas: &mut u128) -> SyscallResult<U256> {
        const CHUNK_SIZE: usize = 17;
        let length = input.len();

        if length % CHUNK_SIZE != 0 {
            return Err(vec![Felt::from_hex(INVALID_INPUT_LENGTH_ERROR).unwrap()]);
        }

        let n_chunks = length / CHUNK_SIZE;
        let mut state = [0u64; 25];

        for i in 0..n_chunks {
            let chunk = &input[i * CHUNK_SIZE..(i + 1) * CHUNK_SIZE];
            for (i, val) in chunk.iter().enumerate() {
                state[i] ^= val;
            }
            keccak::f1600(&mut state)
        }

        Ok(U256 {
            lo: u128::from(state[2]) | (u128::from(state[3]) << 64),
            hi: u128::from(state[0]) | (u128::from(state[1]) << 64),
        })
    }

    fn secp256k1_new(
        &mut self,
        x: U256,
        y: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        let request = SecpNewRequest { x: u256_to_biguint(x), y: u256_to_biguint(y) };
        match self.secp256k1_hint_processor.secp_new(request) {
            Ok(SecpNewResponse { optional_ec_point_id }) => {
                Ok(optional_ec_point_id.map(|_| Secp256k1Point { x, y }))
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256k1_add(
        &mut self,
        p0: Secp256k1Point,
        p1: Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        let p_p0 = allocate_point(p0.x, p0.y, &mut self.secp256k1_hint_processor)?;
        let p_p1 = allocate_point(p1.x, p1.y, &mut self.secp256k1_hint_processor)?;
        let request = SecpAddRequest { lhs_id: Felt252::from(p_p0), rhs_id: Felt252::from(p_p1) };

        match self.secp256k1_hint_processor.secp_add(request) {
            Ok(SecpAddResponse { ec_point_id: id }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256k1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;
                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Secp256k1Point { x, y })
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256k1_mul(
        &mut self,
        p: Secp256k1Point,
        m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        let p_id = allocate_point(p.x, p.y, &mut self.secp256k1_hint_processor)?;
        let request =
            SecpMulRequest { ec_point_id: Felt252::from(p_id), multiplier: u256_to_biguint(m) };

        match self.secp256k1_hint_processor.secp_mul(request) {
            Ok(SecpMulResponse { ec_point_id: id }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256k1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;
                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Secp256k1Point { x, y })
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256k1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        let request = SecpGetPointFromXRequest { x: u256_to_biguint(x), y_parity };

        match self.secp256k1_hint_processor.secp_get_point_from_x(request) {
            Ok(SecpGetPointFromXResponse { optional_ec_point_id: Some(id) }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256k1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;
                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Some(Secp256k1Point { x, y }))
            }
            Ok(SecpGetPointFromXResponse { optional_ec_point_id: None }) => Ok(None),
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256k1_get_xy(
        &mut self,
        p: Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        Ok((p.x, p.y))
    }

    fn secp256r1_new(
        &mut self,
        x: U256,
        y: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256r1Point>> {
        let request = SecpNewRequest { x: u256_to_biguint(x), y: u256_to_biguint(y) };

        match self.secp256r1_hint_processor.secp_new(request) {
            Ok(SecpNewResponse { optional_ec_point_id }) => {
                Ok(optional_ec_point_id.map(|_| Secp256r1Point { x, y }))
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256r1_add(
        &mut self,
        p0: Secp256r1Point,
        p1: Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        let p_p0 = allocate_point(p0.x, p0.y, &mut self.secp256r1_hint_processor)?;
        let p_p1 = allocate_point(p1.x, p1.y, &mut self.secp256r1_hint_processor)?;
        let request = SecpAddRequest { lhs_id: Felt252::from(p_p0), rhs_id: Felt252::from(p_p1) };

        match self.secp256r1_hint_processor.secp_add(request) {
            Ok(SecpAddResponse { ec_point_id: id }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256r1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;
                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Secp256r1Point { x, y })
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256r1_mul(
        &mut self,
        p: Secp256r1Point,
        m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        let p_id = allocate_point(p.x, p.y, &mut self.secp256k1_hint_processor)?;
        let request =
            SecpMulRequest { ec_point_id: Felt252::from(p_id), multiplier: u256_to_biguint(m) };

        match self.secp256r1_hint_processor.secp_mul(request) {
            Ok(SecpMulResponse { ec_point_id: id }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256r1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;

                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Secp256r1Point { x, y })
            }
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256r1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256r1Point>> {
        let request = SecpGetPointFromXRequest { x: u256_to_biguint(x), y_parity };

        match self.secp256r1_hint_processor.secp_get_point_from_x(request) {
            Ok(SecpGetPointFromXResponse { optional_ec_point_id: Some(id) }) => {
                let id = Felt252::from(id);

                let point = self
                    .secp256r1_hint_processor
                    .get_point_by_id(id)
                    .map_err(|error| encode_str_as_felts(&error.to_string()))?;
                let x = big4int_to_u256(point.x.0);
                let y = big4int_to_u256(point.y.0);

                Ok(Some(Secp256r1Point { x, y }))
            }
            Ok(SecpGetPointFromXResponse { optional_ec_point_id: None }) => Ok(None),
            Err(SyscallExecutionError::SyscallError { error_data }) => {
                Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
            }
            Err(error) => Err(encode_str_as_felts(&error.to_string())),
        }
    }

    fn secp256r1_get_xy(
        &mut self,
        p: Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        Ok((p.x, p.y))
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
