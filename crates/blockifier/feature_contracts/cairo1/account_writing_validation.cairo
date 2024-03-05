use core::option::OptionTrait;
use core::traits::TryInto;
#[starknet::contract]
// A dummy account contract with faulty validations.

mod Account {
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use traits::TryInto;
    use option::{Option, OptionTrait};

    use starknet::{
        ContractAddress, call_contract_syscall, contract_address_try_from_felt252,
        get_execution_info, get_tx_info, info::SyscallResultTrait, send_message_to_l1_syscall,
        syscalls::get_block_hash_syscall, TxInfo, syscalls, StorageAddress,
    };

    // Scenarios.
    // Run the validate method, no writes inside validation or execution.
    const NO_WRITES: felt252 = 0;
    // Run the validate method, single write inside execution.
    const WRITE_SINGLE_VALUE: felt252 = 1;
    // Run the validate method, no writes inside validation, writes inside execution.
    const WRITE_EXECUTE_ONLY: felt252 = 2;
    // Run the validate method and write to storage inside validation and execution.
    const WRITE_VALIDATE_EXECUTE: felt252 = 3;
    // Run the validate method and write to storage only inside validation, no writes inside execution.
    const WRITE_VALIDATE_ONLY: felt252 = 4;
    // Run the validate method and write to storage inside validation, fail in execution.
    const WRITE_VALIDATE_FAIL_EXECUTE: felt252 = 5;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        validate_constructor: bool
    ) -> felt252 {
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate__(
        ref self: ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) -> felt252 {
        validate(ref self)
    }

    #[external(v0)]
    fn __execute__(
        ref self: ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) {
        execute(ref self)
    }

    #[constructor]
    fn constructor(ref self: ContractState, validate_constructor: bool) {}

    fn validate(ref self: ContractState) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let signature = tx_info.signature;
        let scenario = *signature[0_u32];

        if (scenario == NO_WRITES
            || scenario == WRITE_SINGLE_VALUE
            || scenario == WRITE_EXECUTE_ONLY) {
            return starknet::VALIDATED;
        }
        if (scenario == WRITE_VALIDATE_ONLY) {
            //First write to storage.
            write(*signature[1_u32], *signature[2_u32]);
            //Second write to storage.
            write(*signature[3_u32], *signature[4_u32]);
            return starknet::VALIDATED;
        }
        if (scenario == WRITE_VALIDATE_EXECUTE || scenario == WRITE_VALIDATE_FAIL_EXECUTE) {
            //Write to storage.
            write(*signature[1_u32], *signature[2_u32]);
            return starknet::VALIDATED;
        }
        // Unknown scenario.
        starknet::VALIDATED
    }

    fn execute(ref self: ContractState) {
        let tx_info = starknet::get_tx_info().unbox();
        let signature = tx_info.signature;
        let scenario = *signature[0_u32];

        if (scenario == NO_WRITES || scenario == WRITE_VALIDATE_ONLY) {}
        if (scenario == WRITE_SINGLE_VALUE || scenario == WRITE_EXECUTE_ONLY) {
            //Write to storage.
            write(*signature[1_u32], *signature[2_u32]);
        }
        if (scenario == WRITE_EXECUTE_ONLY
            || scenario == WRITE_VALIDATE_EXECUTE
            || scenario == WRITE_VALIDATE_FAIL_EXECUTE) {
            //Second write to storage.
            write(*signature[3_u32], *signature[4_u32]);
        }
        if (scenario == WRITE_VALIDATE_FAIL_EXECUTE) {
            assert(0 == 1, 'Invalid scenario');
        }
    }

    fn write(index: felt252, value: felt252) {
        let storage_address = index.try_into().unwrap();
        let address_domain = 0;
        syscalls::storage_write_syscall(address_domain, storage_address, value).unwrap_syscall();
    }
}
