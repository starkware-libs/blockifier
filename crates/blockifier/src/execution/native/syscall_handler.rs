use std::collections::HashSet;
use std::hash::RandomState;
use std::marker::PhantomData;
use std::sync::Arc;

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use cairo_native::starknet::{
    BlockInfo, ExecutionInfo, ExecutionInfoV2, Secp256k1Point, Secp256r1Point,
    StarknetSyscallHandler, SyscallResult, TxInfo, TxV2Info, U256,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::{ToPrimitive, Zero};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector, EthAddress,
    PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, L2ToL1Payload,
};
use starknet_types_core::felt::Felt;

use super::utils::{
    big4int_to_u256, calculate_resource_bounds, contract_address_to_native_felt,
    default_tx_v2_info, encode_str_as_felts, u256_to_biguint,
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
    OUT_OF_GAS_ERROR,
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
    pub entry_point_selector: Felt,

    // Execution results
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub inner_calls: Vec<CallInfo>,
    // Additional execution result info
    pub storage_read_values: Vec<Felt>,
    pub accessed_storage_keys: HashSet<StorageKey, RandomState>,
}

impl<'state> NativeSyscallHandler<'state> {
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

    pub fn execute_inner_call(
        &mut self,
        entry_point: CallEntryPoint,
        remaining_gas: &mut u128,
    ) -> SyscallResult<CallInfo> {
        let call_info = entry_point
            .execute(self.state, self.execution_resources, self.execution_context)
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;
        let retdata = call_info.execution.retdata.0.clone();

        if call_info.execution.failed {
            // In VM it's wrapped into `SyscallExecutionError::SyscallError`
            return Err(retdata);
        }

        self.update_remaining_gas(remaining_gas, &call_info);

        self.inner_calls.push(call_info.clone());

        Ok(call_info)
    }

    pub fn update_remaining_gas(&mut self, remaining_gas: &mut u128, call_info: &CallInfo) {
        // create a new variable with converted type
        let mut remaining_gas_u64 = u64::try_from(*remaining_gas).unwrap();

        // pass the reference to the function
        update_remaining_gas(&mut remaining_gas_u64, call_info);

        // change the remaining gas value
        *remaining_gas = u128::from(remaining_gas_u64);
    }

    // We need to have this function since in VM we have `execute_syscall` method, which is handling
    // all gas-related logics in the native, syscalls are called directly, so we need to
    // implement this logic here
    pub fn substract_syscall_gas_cost(
        &mut self,
        remaining_gas: &mut u128,
        syscall_gas_cost: u64,
    ) -> SyscallResult<()> {
        // Refund `SYSCALL_BASE_GAS_COST` as it was pre-charged.
        let required_gas =
            u128::from(syscall_gas_cost - self.execution_context.gas_costs().syscall_base_gas_cost);

        if *remaining_gas < required_gas {
            //  Out of gas failure.
            return Err(vec![Felt::from_hex(OUT_OF_GAS_ERROR).unwrap()]);
        }

        *remaining_gas -= required_gas;

        Ok(())
    }
}

impl<'state> StarknetSyscallHandler for &mut NativeSyscallHandler<'state> {
    fn get_block_hash(
        &mut self,
        block_number: u64,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Felt> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().get_block_hash_gas_cost,
        )?;

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

            // This error is wrapped into a `SyscallExecutionError::SyscallError` in the VM
            // implementation, but here it would be more convenient to return it directly, since
            // wrapping it like VM does will result in a double encoding to felts, which adds extra
            // layer of complication
            return Err(vec![out_of_range_felt]);
        }

        let key = StorageKey::try_from(Felt::from(block_number))
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;
        let block_hash_address =
            ContractAddress::try_from(Felt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        match self.state.get_storage_at(block_hash_address, key) {
            Ok(value) => Ok(value),
            Err(e) => Err(encode_str_as_felts(&e.to_string())),
        }
    }

    fn get_execution_info(&mut self, remaining_gas: &mut u128) -> SyscallResult<ExecutionInfo> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().get_execution_info_gas_cost,
        )?;

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
            version: tx_info.version().0,
            account_contract_address: contract_address_to_native_felt(tx_info.sender_address()),
            max_fee: tx_info.max_fee().unwrap_or_default().0,
            signature: tx_info.signature().0,
            transaction_hash: tx_info.transaction_hash().0,
            chain_id: Felt::from_hex(
                &self.execution_context.tx_context.block_context.chain_info.chain_id.as_hex(),
            )
            .unwrap(),
            nonce: tx_info.nonce().0,
        };

        let caller_address = contract_address_to_native_felt(self.caller_address);
        let contract_address = contract_address_to_native_felt(self.contract_address);
        let entry_point_selector = self.entry_point_selector;

        Ok(ExecutionInfo {
            block_info: native_block_info,
            tx_info: native_tx_info,
            caller_address,
            contract_address,
            entry_point_selector,
        })
    }

    fn get_execution_info_v2(
        &mut self,
        remaining_gas: &mut u128,
    ) -> SyscallResult<ExecutionInfoV2> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().get_execution_info_gas_cost,
        )?;

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
            version: tx_info.signed_version().0,
            account_contract_address: contract_address_to_native_felt(tx_info.sender_address()),
            max_fee: max_fee_for_execution_info(tx_info).to_u128().unwrap(),
            signature: tx_info.signature().0,
            transaction_hash: tx_info.transaction_hash().0,
            chain_id: Felt::from_hex(
                &self.execution_context.tx_context.block_context.chain_info.chain_id.as_hex(),
            )
            .unwrap(),
            nonce: tx_info.nonce().0,
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
                paymaster_data: context.paymaster_data.0.clone(),
                nonce_data_availability_mode: to_u32(context.nonce_data_availability_mode),
                fee_data_availability_mode: to_u32(context.fee_data_availability_mode),
                account_deployment_data: context.account_deployment_data.0.clone(),
                ..native_tx_info
            };
        }

        let caller_address = contract_address_to_native_felt(self.caller_address);
        let contract_address = contract_address_to_native_felt(self.contract_address);
        let entry_point_selector = self.entry_point_selector;

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
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().deploy_gas_cost,
        )?;

        let deployer_address =
            if deploy_from_zero { ContractAddress::default() } else { self.contract_address };

        let class_hash = ClassHash(class_hash);
        let wrapper_calldata = Calldata(Arc::new(calldata.to_vec()));
        let calculated_contract_address = calculate_contract_address(
            ContractAddressSalt(contract_address_salt),
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
            // Warning: converting of reference would create a new reference to different data,
            // example:
            //     let mut a: u128 = 1;
            //     let a_ref: &mut u128 = &mut a;
            //
            //     let mut b: u64 = u64::try_from(*a_ref).unwrap();
            //
            //     assert_eq!(b, 1);
            //
            //     b += 1;
            //
            //     assert_eq!(b, 2);
            //     assert_eq!(a, 1);
            // in this case we don't pass a reference, so everything is OK, but still can cause
            // conversion issues
            u64::try_from(*remaining_gas).unwrap(),
        )
        .map_err(|error| encode_str_as_felts(&error.to_string()))?;

        self.update_remaining_gas(remaining_gas, &call_info);

        let return_data = call_info.execution.retdata.0[..].to_vec();
        let contract_address_felt = Felt::from(calculated_contract_address);

        self.inner_calls.push(call_info);

        Ok((contract_address_felt, return_data))
    }

    fn replace_class(&mut self, class_hash: Felt, remaining_gas: &mut u128) -> SyscallResult<()> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().replace_class_gas_cost,
        )?;

        let class_hash = ClassHash(class_hash);
        let contract_class = self
            .state
            .get_compiled_contract_class(class_hash)
            .map_err(|e| encode_str_as_felts(&e.to_string()))?;

        match contract_class {
            ContractClass::V0(_) => Err(encode_str_as_felts(
                &SyscallExecutionError::ForbiddenClassReplacement { class_hash }.to_string(),
            )),
            ContractClass::V1(_) | ContractClass::V1Native(_) => {
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
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().library_call_gas_cost,
        )?;

        let class_hash = ClassHash(class_hash);

        let wrapper_calldata = Calldata(Arc::new(calldata.to_vec()));

        let entry_point = CallEntryPoint {
            class_hash: Some(class_hash),
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(function_selector),
            calldata: wrapper_calldata,
            // The call context remains the same in a library call.
            storage_address: self.contract_address,
            caller_address: self.caller_address,
            call_type: CallType::Delegate,
            initial_gas: u64::try_from(*remaining_gas).unwrap(),
        };

        let retdata = self
            .execute_inner_call(entry_point, remaining_gas)
            .map(|call_info| call_info.execution.retdata.0.clone())?;

        Ok(retdata)
    }

    fn call_contract(
        &mut self,
        address: Felt,
        entry_point_selector: Felt,
        calldata: &[Felt],
        remaining_gas: &mut u128,
    ) -> SyscallResult<Vec<Felt>> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().call_contract_gas_cost,
        )?;

        let contract_address = ContractAddress::try_from(address)
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

        let wrapper_calldata = Calldata(Arc::new(calldata.to_vec()));

        let entry_point = CallEntryPoint {
            class_hash: None,
            code_address: Some(contract_address),
            entry_point_type: EntryPointType::External,
            entry_point_selector: EntryPointSelector(entry_point_selector),
            calldata: wrapper_calldata,
            storage_address: contract_address,
            caller_address: self.contract_address,
            call_type: CallType::Call,
            initial_gas: u64::try_from(*remaining_gas).unwrap(),
        };

        let retdata = self
            .execute_inner_call(entry_point, remaining_gas)
            .map(|call_info| call_info.execution.retdata.0.clone())?;

        Ok(retdata)
    }

    fn storage_read(
        &mut self,
        _address_domain: u32,
        address: Felt,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Felt> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().storage_read_gas_cost,
        )?;

        let key = StorageKey(
            PatriciaKey::try_from(address).map_err(|e| encode_str_as_felts(&e.to_string()))?,
        );

        let read_result = self.state.get_storage_at(self.contract_address, key);
        let value = read_result.map_err(|e| encode_str_as_felts(&e.to_string()))?;

        self.accessed_storage_keys.insert(key);
        self.storage_read_values.push(value);

        Ok(value)
    }

    fn storage_write(
        &mut self,
        _address_domain: u32,
        address: Felt,
        value: Felt,
        remaining_gas: &mut u128,
    ) -> SyscallResult<()> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().storage_write_gas_cost,
        )?;

        let key = StorageKey(
            PatriciaKey::try_from(address).map_err(|e| encode_str_as_felts(&e.to_string()))?,
        );
        self.accessed_storage_keys.insert(key);

        let write_result = self.state.set_storage_at(self.contract_address, key, value);
        write_result.map_err(|e| encode_str_as_felts(&e.to_string()))?;

        Ok(())
    }

    fn emit_event(
        &mut self,
        keys: &[Felt],
        data: &[Felt],
        remaining_gas: &mut u128,
    ) -> SyscallResult<()> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().emit_event_gas_cost,
        )?;

        let order = self.execution_context.n_emitted_events;
        let event = EventContent {
            keys: keys.iter().copied().map(EventKey).collect(),
            data: EventData(data.to_vec()),
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
        self.substract_syscall_gas_cost(
            _remaining_gas,
            self.execution_context.gas_costs().send_message_to_l1_gas_cost,
        )?;

        let order = self.execution_context.n_sent_messages_to_l1;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message {
            order,
            message: MessageToL1 {
                to_address: EthAddress::try_from(to_address)
                    .map_err(|e| encode_str_as_felts(&e.to_string()))?,
                payload: L2ToL1Payload(payload.to_vec()),
            },
        });

        self.execution_context.n_sent_messages_to_l1 += 1;

        Ok(())
    }

    fn keccak(&mut self, input: &[u64], remaining_gas: &mut u128) -> SyscallResult<U256> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().keccak_gas_cost,
        )?;

        const KECCAK_FULL_RATE_IN_WORDS: usize = 17;

        let length = input.len();
        let (n_rounds, remainder) = num_integer::div_rem(length, KECCAK_FULL_RATE_IN_WORDS);

        if remainder != 0 {
            // In VM this error is wrapped into `SyscallExecutionError::SyscallError`
            return Err(vec![Felt::from_hex(INVALID_INPUT_LENGTH_ERROR).unwrap()]);
        }

        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
        // works.
        let n_rounds_as_u64 = u64::try_from(n_rounds).expect("Failed to convert usize to u64.");
        let gas_cost = u128::from(
            n_rounds_as_u64 * self.execution_context.gas_costs().keccak_round_cost_gas_cost,
        );

        if gas_cost > *remaining_gas {
            // In VM this error is wrapped into `SyscallExecutionError::SyscallError`
            return Err(vec![Felt::from_hex(OUT_OF_GAS_ERROR).unwrap()]);
        }
        *remaining_gas -= gas_cost;

        // TODO: do we need to have syscall counter?

        let mut state = [0u64; 25];
        for chunk in input.chunks(KECCAK_FULL_RATE_IN_WORDS) {
            for (i, val) in chunk.iter().enumerate() {
                state[i] ^= val;
            }
            keccak::f1600(&mut state)
        }

        Ok(U256 {
            hi: u128::from(state[2]) | (u128::from(state[3]) << 64),
            lo: u128::from(state[0]) | (u128::from(state[1]) << 64),
        })
    }

    // The secp256 syscalls are implement in impl<Curve: SWCurveConfig> SecpHintProcessor<Curve>
    // The trait methods are responsible for routing to the correct hint processor (r1 or k1).

    fn secp256k1_new(
        &mut self,
        x: U256,
        y: U256,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256k1_new_gas_cost,
        )?;

        Secp256Point::new(x, y).map(|op| op.map(|p| p.into()))
    }

    fn secp256k1_add(
        &mut self,
        p0: Secp256k1Point,
        p1: Secp256k1Point,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256k1_add_gas_cost,
        )?;

        Ok(Secp256Point::add(p0.into(), p1.into()).into())
    }

    fn secp256k1_mul(
        &mut self,
        p: Secp256k1Point,
        m: U256,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256k1Point> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256k1_mul_gas_cost,
        )?;

        Ok(Secp256Point::mul(p.into(), m).into())
    }

    fn secp256k1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256k1Point>> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256k1_get_point_from_x_gas_cost,
        )?;

        Secp256Point::get_point_from_x(x, y_parity).map(|op| op.map(|p| p.into()))
    }

    fn secp256k1_get_xy(
        &mut self,
        p: Secp256k1Point,
        remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256k1_get_xy_gas_cost,
        )?;

        Ok((p.x, p.y))
    }

    fn secp256r1_new(
        &mut self,
        x: U256,
        y: U256,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256r1Point>> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256r1_new_gas_cost,
        )?;

        Secp256Point::new(x, y).map(|op| op.map(|p| p.into()))
    }

    fn secp256r1_add(
        &mut self,
        p0: Secp256r1Point,
        p1: Secp256r1Point,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256r1_add_gas_cost,
        )?;

        Ok(Secp256Point::add(p0.into(), p1.into()).into())
    }

    fn secp256r1_mul(
        &mut self,
        p: Secp256r1Point,
        m: U256,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Secp256r1Point> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256r1_mul_gas_cost,
        )?;

        Ok(Secp256Point::mul(p.into(), m).into())
    }

    fn secp256r1_get_point_from_x(
        &mut self,
        x: U256,
        y_parity: bool,
        remaining_gas: &mut u128,
    ) -> SyscallResult<Option<Secp256r1Point>> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256r1_get_point_from_x_gas_cost,
        )?;

        Secp256Point::get_point_from_x(x, y_parity).map(|op| op.map(|p| p.into()))
    }

    fn secp256r1_get_xy(
        &mut self,
        p: Secp256r1Point,
        remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        self.substract_syscall_gas_cost(
            remaining_gas,
            self.execution_context.gas_costs().secp256r1_get_xy_gas_cost,
        )?;

        Ok((p.x, p.y))
    }

    fn sha256_process_block(
        &mut self,
        _prev_state: &[u32; 8],
        _current_block: &[u32; 16],
        _remaining_gas: &mut u128,
    ) -> SyscallResult<[u32; 8]> {
        todo!()
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
                Felt::from_hex(crate::execution::syscalls::hint_processor::INVALID_ARGUMENT)
                    .map_err(|err| {
                        encode_str_as_felts(&SyscallExecutionError::from(err).to_string())
                    })?;

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
                Felt::from_hex(crate::execution::syscalls::hint_processor::INVALID_ARGUMENT)
                    .map_err(|err| {
                        encode_str_as_felts(&SyscallExecutionError::from(err).to_string())
                    })?;

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

/// Similar to [`Affine<Curve>::new`], but with checks for 0 and doesn't panic.
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

use crate::transaction::transaction_utils::update_remaining_gas;

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
        // Here /into/ must be used, accessing the BigInt via .0 will lead to an
        // transformation being missed.
        let x = big4int_to_u256(point.x.into());
        let y = big4int_to_u256(point.y.into());

        Self { x, y, _phantom: Default::default() }
    }
}
