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
    // Run the validate method, no writes inside validation, writes inside execution.
    const VALIDATION_WITHOUT_WRITE: felt252 = 1;
    // Run the validate method and write to storage inside validation and execution.
    const VALIDATION_WITH_WRITE: felt252 = 2;
    // Run the validate method and write to storage only inside validation, no writes inside execution.
    const VALIDATION_WITH_WRITE_ONLY_IN_VALIDATION: felt252 = 3;

    #[storage]
    struct Storage {
        my_storage_var: felt252,
        my_storage_map: LegacyMap<felt252, felt252>,
    }

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
    ) -> felt252 {
        execute(ref self)
    }

    #[constructor]
    fn constructor(ref self: ContractState, validate_constructor: bool) {}

    fn validate(ref self: ContractState) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let signature = tx_info.signature;
        let scenario = *signature[0_u32];

        if (scenario == NO_WRITES || scenario == VALIDATION_WITHOUT_WRITE) {
            return starknet::VALIDATED;
        }

        if (scenario == VALIDATION_WITH_WRITE_ONLY_IN_VALIDATION) {
            //First write to storage.
            let index = *signature[1_u32];
            let value = *signature[2_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();
            //Second write to storage.
            let index = *signature[3_u32];
            let value = *signature[4_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();
            return starknet::VALIDATED;
        }

        if (scenario == VALIDATION_WITH_WRITE) {
            let index = *signature[1_u32];
            let value = *signature[2_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();
            return starknet::VALIDATED;
        }
        // Unknown scenario.
        starknet::VALIDATED
    }

    fn execute(ref self: ContractState) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let signature = tx_info.signature;
        let scenario = *signature[0_u32];

        if (scenario == NO_WRITES || scenario == VALIDATION_WITH_WRITE_ONLY_IN_VALIDATION) {
            return starknet::VALIDATED;
        }

        if (scenario == VALIDATION_WITHOUT_WRITE) {
            //First write to storage.
            let index = *signature[1_u32];
            let value = *signature[2_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();

            //Second write to storage.
            let index = *signature[3_u32];
            let value = *signature[4_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();
            return starknet::VALIDATED;
        }

        if (scenario == VALIDATION_WITH_WRITE) {
            let index = *signature[3_u32];
            let value = *signature[4_u32];
            let storage_address = index.try_into().unwrap();
            let address_domain = 0;
            syscalls::storage_write_syscall(address_domain, storage_address, value)
                .unwrap_syscall();
            return starknet::VALIDATED;
        }
        // Unknown scenario.
        starknet::VALIDATED
    }
}
