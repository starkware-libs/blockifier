#[starknet::contract]
mod Account {
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use ecdsa::check_ecdsa_signature;
    use option::OptionTrait;
    use starknet::account::Call;
    use starknet::{ContractAddress, call_contract_syscall};
    use zeroable::Zeroable;
    use array::ArraySerde;

    #[storage]
    struct Storage {
        // public_key: felt252
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252//,
        // public_key_: felt252
    ) -> felt252 {
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
        // Validate caller.
        assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');

        let mut result = ArrayTrait::new();
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    let mut res = call_contract_syscall(
                        address: call.to,
                        entry_point_selector: call.selector,
                        calldata: call.calldata.span()
                    )
                        .unwrap_syscall();
                    result.append(res);
                },
                Option::None(()) => {
                    break;
                },
            };
        };
        result
    }
}

