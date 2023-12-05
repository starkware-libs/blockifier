#[starknet::contract]
mod Account {
    use array::{ArrayTrait, SpanTrait};
    use starknet::{ContractAddress, call_contract_syscall};
    use zeroable::Zeroable;

    const GRIND_DEPTH: felt252 = 10000000;

    #[storage]
    struct Storage {
    }

    fn grind() {
        return grind_recurse(GRIND_DEPTH);
    }

    fn grind_recurse(depth: felt252) {
        if depth == 0 {
            return ();
        }
        grind_recurse(depth - 1);
    }

    #[constructor]
    fn constructor(ref self: ContractState, grind_on_deploy: felt252) {}

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        grind_on_deploy: felt252
    ) -> felt252 {
        if grind_on_deploy != 0 {
            grind();
        }
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
        grind();
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __validate__(
        self: @ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) -> felt252 {
        grind();
        starknet::VALIDATED
    }

    #[external(v0)]
    #[raw_output]
    fn __execute__(
        self: @ContractState,
        contract_address: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>
    ) -> Span<felt252> {
        // Validate caller.
        assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');

        call_contract_syscall(
            address: contract_address,
            entry_point_selector: selector,
            calldata: calldata.span()
        )
            .unwrap()
    }
}
