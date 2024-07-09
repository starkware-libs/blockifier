use std::collections::HashSet;
use std::hash::RandomState;
use std::marker::PhantomData;
use std::sync::Arc;

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use cairo_native::starknet::{
    BlockInfo, ExecutionInfoV2, Secp256k1Point, Secp256r1Point, StarknetSyscallHandler,
    SyscallResult, TxInfo, TxV2Info, U256,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::{ToPrimitive, Zero};
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
    big4int_to_u256, calculate_resource_bounds, contract_address_to_native_felt,
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
            storage_read_values: Vec::new(),
            accessed_storage_keys: HashSet::new(),
        }
    }
}

impl<'state> StarknetSyscallHandler for &mut NativeSyscallHandler<'state> {
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

    // TODO: This method is untested!!!
    fn get_execution_info(
        &mut self,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        let block_info = &self.execution_context.tx_context.block_context.block_info;
        let native_block_info: BlockInfo = if self.execution_context.execution_mode
            == ExecutionMode::Validate
        {
            // TODO: Literal copy from get execution info v2, could be refactored
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

        let tx_info = &self.execution_context.tx_context.tx_info;
        let native_tx_info = TxInfo {
            version: stark_felt_to_native_felt(tx_info.version().0),
            account_contract_address: contract_address_to_native_felt(tx_info.sender_address()),
            max_fee: tx_info.max_fee().unwrap_or_default().0,
            signature: tx_info.signature().0.into_iter().map(stark_felt_to_native_felt).collect(),
            transaction_hash: stark_felt_to_native_felt(tx_info.transaction_hash().0),
            chain_id: Felt::from_hex(
                &self.execution_context.tx_context.block_context.chain_info.chain_id.as_hex(),
            )
            .unwrap(),
            nonce: stark_felt_to_native_felt(tx_info.nonce().0),
        };

        let caller_address = contract_address_to_native_felt(self.caller_address);
        let contract_address = contract_address_to_native_felt(self.contract_address);
        let entry_point_selector = stark_felt_to_native_felt(self.entry_point_selector);

        Ok(cairo_native::starknet::ExecutionInfo {
            block_info: native_block_info,
            tx_info: native_tx_info,
            caller_address,
            contract_address,
            entry_point_selector,
        })
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
            caller_address: self.contract_address,
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

    // The secp256 syscalls are implement in impl<Curve: SWCurveConfig> SecpHintProcessor<Curve>
    // The trait methods are responsible for routing to the correct hint processor (r1 or k1).

    fn secp256k1_new(
        &mut self,
        x: U256,
        y: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        Secp256Point::new(x, y).map(|op| op.map(|p| p.into()))
    }

    fn secp256k1_add(
        &mut self,
        p0: Secp256k1Point,
        p1: Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        Ok(Secp256Point::add(p0.into(), p1.into()).into())
    }

    fn secp256k1_mul(
        &mut self,
        p: Secp256k1Point,
        m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        Ok(Secp256Point::mul(p.into(), m).into())
    }

    fn secp256k1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        Secp256Point::get_point_from_x(x, y_parity).map(|op| op.map(|p| p.into()))
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
        Secp256Point::new(x, y).map(|op| op.map(|p| p.into()))
    }

    fn secp256r1_add(
        &mut self,
        p0: Secp256r1Point,
        p1: Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        Ok(Secp256Point::add(p0.into(), p1.into()).into())
    }

    fn secp256r1_mul(
        &mut self,
        p: Secp256r1Point,
        m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        Ok(Secp256Point::mul(p.into(), m).into())
    }

    fn secp256r1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256r1Point>> {
        Secp256Point::get_point_from_x(x, y_parity).map(|op| op.map(|p| p.into()))
    }

    fn secp256r1_get_xy(
        &mut self,
        p: Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        Ok((p.x, p.y))
    }
}

use ark_ff::PrimeField;

impl<Curve: SWCurveConfig> Secp256Point<Curve>
where
    // It's not possible to directly constrain on
    // ark_secp256k1::Config and
    // ark_secp256r1::Config. The following
    // constraints have the same effect.
    Curve::BaseField: PrimeField, // constraint for get_point_by_id
    ark_ff::BigInt<4>: From<<Curve>::BaseField>, // constraint for point to bigint
{
    fn new(x: U256, y: U256) -> Result<Option<Self>, Vec<Felt>> {
        let x = u256_to_biguint(x);
        let y = u256_to_biguint(y);
        let modulos = Curve::BaseField::MODULUS.into();

        if x >= modulos || y >= modulos {
            let error =
                StarkFelt::try_from(crate::execution::syscalls::hint_processor::INVALID_ARGUMENT)
                    .map_err(|err| {
                    encode_str_as_felts(&SyscallExecutionError::from(err).to_string())
                })?;
            let error = stark_felt_to_native_felt(error);

            return Err(vec![error]);
        }

        Ok(maybe_affine(x.into(), y.into()).map(|p| p.into()))
    }

    fn add(p0: Secp256Point<Curve>, p1: Secp256Point<Curve>) -> Self {
        let lhs: Affine<Curve> = p0.into();
        let rhs: Affine<Curve> = p1.into();
        let result: Projective<Curve> = lhs + rhs;
        let result: Affine<Curve> = result.into();
        result.into()
    }

    fn mul(p: Secp256Point<Curve>, m: U256) -> Self {
        let p: Affine<Curve> = p.into();
        let result = p * Curve::ScalarField::from(u256_to_biguint(m));
        let result: Affine<Curve> = result.into();
        result.into()
    }

    fn get_point_from_x(x: U256, y_parity: bool) -> Result<Option<Self>, Vec<Felt>> {
        let modulos = Curve::BaseField::MODULUS.into();
        let x = u256_to_biguint(x);

        if x >= modulos {
            let error =
                StarkFelt::try_from(crate::execution::syscalls::hint_processor::INVALID_ARGUMENT)
                    .map_err(|err| {
                    encode_str_as_felts(&SyscallExecutionError::from(err).to_string())
                })?;
            let error = stark_felt_to_native_felt(error);

            return Err(vec![error]);
        }

        let x = x.into();
        let maybe_ec_point = Affine::<Curve>::get_ys_from_x_unchecked(x)
            .map(|(smaller, greater)| {
                // Return the correct y coordinate based on the parity.
                if ark_ff::BigInteger::is_odd(&smaller.into_bigint()) == y_parity {
                    smaller
                } else {
                    greater
                }
            })
            .map(|y| Affine::<Curve>::new_unchecked(x, y))
            .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());

        Ok(maybe_ec_point.map(|p| p.into()))
    }
}

/// Similar to Affine<Curve>::new, but with checks for 0 and doesn't panic.
fn maybe_affine<Curve: SWCurveConfig>(
    x: Curve::BaseField,
    y: Curve::BaseField,
) -> Option<Affine<Curve>> {
    // use match for a better
    let ec_point = if x.is_zero() && y.is_zero() {
        Affine::<Curve>::identity()
    } else {
        Affine::<Curve>::new_unchecked(x, y)
    };

    if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
        Some(ec_point)
    } else {
        None
    }
}

/// Note [Hint processor and Secp256Point]
/// With this data structure and its From instances we
/// tie a hint processor to the corresponding Secp256k1 or Secp256r1 point.
/// Thereby making the hint processor operations generic over the Secp256 point.
struct Secp256Point<Config> {
    x: U256,
    y: U256,
    _phantom: PhantomData<Config>,
}

use std::convert::From;

impl From<Secp256Point<ark_secp256k1::Config>> for Secp256k1Point {
    fn from(p: Secp256Point<ark_secp256k1::Config>) -> Self {
        Secp256k1Point { x: p.x, y: p.y }
    }
}

impl From<Secp256Point<ark_secp256r1::Config>> for Secp256r1Point {
    fn from(p: Secp256Point<ark_secp256r1::Config>) -> Self {
        Secp256r1Point { x: p.x, y: p.y }
    }
}

impl From<Secp256k1Point> for Secp256Point<ark_secp256k1::Config> {
    fn from(p: Secp256k1Point) -> Self {
        Self { x: p.x, y: p.y, _phantom: Default::default() }
    }
}

impl From<Secp256r1Point> for Secp256Point<ark_secp256r1::Config> {
    fn from(p: Secp256r1Point) -> Self {
        Self { x: p.x, y: p.y, _phantom: Default::default() }
    }
}

impl<Curve: SWCurveConfig> From<Secp256Point<Curve>> for Affine<Curve>
where
    Curve::BaseField: From<num_bigint::BigUint>,
{
    fn from(p: Secp256Point<Curve>) -> Self {
        Affine::<Curve>::new(u256_to_biguint(p.x).into(), u256_to_biguint(p.y).into())
    }
}

impl<Curve: SWCurveConfig> From<Affine<Curve>> for Secp256Point<Curve>
where
    ark_ff::BigInt<4>: From<<Curve>::BaseField>,
{
    fn from(point: Affine<Curve>) -> Self {
        // A workaround for turning big4int into a u256 that matches the way the
        // result of native and VM are displayed.
        // Having to swap around is most-likely a bug, but best investigated after
        // https://github.com/NethermindEth/blockifier/issues/97
        fn swap(x: U256) -> U256 {
            U256 { hi: x.lo, lo: x.hi }
        }

        // Here /into/ must be used, accessing the BigInt via .0 will lead to an
        // transformation being missed.
        let x = big4int_to_u256(point.x.into());
        let y = big4int_to_u256(point.y.into());

        Self { x: swap(x), y: swap(y), _phantom: Default::default() }
    }
}
