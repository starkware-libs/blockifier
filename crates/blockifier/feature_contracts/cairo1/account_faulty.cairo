use core::option::OptionTrait;
use core::traits::TryInto;
#[starknet::contract]

// A dummy account contract with faulty validations.

mod Account {
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use traits::TryInto;
    use option::{Option, OptionTrait};

    use starknet::{ContractAddress, call_contract_syscall, contract_address_try_from_felt252,
        get_tx_info, info::SyscallResultTrait, send_message_to_l1_syscall,
        syscalls::get_block_hash_syscall, TxInfo};

    // Validate Scenarios.

    // Run the validate method with no issues.
    const VALID: felt252 = 0;
    // Logic failure.
    const INVALID: felt252 = 1;
    // Make a contract call.
    const CALL_CONTRACT: felt252 = 2;
    // Use get_block_hash syscall.
    const GET_BLOCK_HASH: felt252 = 3;

    // get_selector_from_name('foo').
    const FOO_ENTRY_POINT_SELECTOR: felt252 = (
        0x1b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d
    );

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        faulty_validate()
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        validate_constructor: bool
    ) -> felt252 {

        if (validate_constructor == false) {
            return faulty_validate();
        }

        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate__(
        self: @ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) -> felt252 {
        let to_address = 0;
        // By calling the `send_message_to_l1` function in validation and exeution, tests can now verify
        // the functionality of entry point counters.
        send_message_to_l1_syscall(
            to_address: to_address,
            payload: calldata.span()
        );
        faulty_validate()
    }

    #[external(v0)]
    fn __execute__(
        self: @ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) -> felt252 {
        let to_address = 0;

        send_message_to_l1_syscall(
            to_address: to_address,
            payload: calldata.span()
        );

        starknet::VALIDATED
    }

    #[constructor]
    fn constructor(ref self: ContractState, validate_constructor: bool) {
        if (validate_constructor == true) {
            faulty_validate();
        }
    }

    #[external(v0)]
    fn foo(self: @ContractState) {}

    fn faulty_validate() -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let signature = tx_info.signature;
        let scenario = *signature[0_u32];

        if (scenario == VALID) {
            return starknet::VALIDATED;
        }
        if (scenario == INVALID) {
            assert (0 == 1, 'Invalid scenario');
            return 'INVALID';
        }
        if (scenario == CALL_CONTRACT) {
            let contract_address: felt252 = *signature[1_u32];
            let mut calldata = Default::default();
            call_contract_syscall(
                address: contract_address_try_from_felt252(contract_address).unwrap(),
                entry_point_selector: FOO_ENTRY_POINT_SELECTOR,
                calldata: calldata.span()
            )
                .unwrap_syscall();
            return starknet::VALIDATED;
        }
        assert (scenario == GET_BLOCK_HASH, 'Unknown scenario');
        let block_number: u64 = 0;
        get_block_hash_syscall(block_number).unwrap_syscall();

        starknet::VALIDATED
    }
}
