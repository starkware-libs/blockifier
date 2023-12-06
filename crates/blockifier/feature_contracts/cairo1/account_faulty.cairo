use core::option::OptionTrait;
use core::traits::TryInto;
#[starknet::contract]

// A dummy account contract with faulty validations.

mod Account {
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use traits::TryInto;
    use option::{Option, OptionTrait};

    use starknet::{ContractAddress, call_contract_syscall, send_message_to_l1_syscall, TxInfo,
        get_tx_info, contract_address_try_from_felt252};

    // Validate Scenarios.

    // Run the validate method with no issues.
    const VALID: felt252 = 0;
    // Logic failure.
    const INVALID: felt252 = 1;
    // Make a contract call.
    const CALL_CONTRACT: felt252 = 2;

    // get_selector_from_name('foo').
    const FOO_ENTRY_POINT_SELECTOR: felt252 = (
        0x1b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d
    );

    #[storage]
    struct Storage {
    }

    trait StorageTrait {
        fn faulty_validate(self: @ContractState) -> felt252;
    }

    impl StorageImpl of StorageTrait {
        fn faulty_validate(self: @ContractState) -> felt252 {
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

            assert (scenario == CALL_CONTRACT, 'Unknown scenario');
            let contract_address: felt252 = *signature[1_u32];
            let mut calldata = Default::default();
            call_contract_syscall(
                address: contract_address_try_from_felt252(contract_address).unwrap(),
                entry_point_selector: FOO_ENTRY_POINT_SELECTOR,
                calldata: calldata.span()
            )
                .unwrap();

            starknet::VALIDATED
        }
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        self.faulty_validate()
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        validate_constructor: bool
    ) -> felt252 {

        if (validate_constructor == false) {
            return self.faulty_validate();
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
        self.faulty_validate()
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
            self.faulty_validate();
        }
    }

    #[external(v0)]
    fn foo(self: @ContractState) {}

}
