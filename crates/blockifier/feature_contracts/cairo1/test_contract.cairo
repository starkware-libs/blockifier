#[starknet::contract]
mod TestContract {
    use box::BoxTrait;
    use dict::Felt252DictTrait;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::StorageAddress;
    use array::ArrayTrait;
    use array::SpanTrait;
    use clone::Clone;
    use traits::Into;
    use traits::TryInto;
    use option::OptionTrait;

    const UNEXPECTED_ERROR: felt252 = 'UNEXPECTED ERROR';

    #[storage]
    struct Storage {
        my_storage_var: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, arg1: felt252, arg2: felt252) -> felt252 {
        self.my_storage_var.write(arg1 + arg2);
        arg1
    }

    #[external]
    fn test_storage_read_write(self: @ContractState, address: StorageAddress, value: felt252) -> felt252 {
        let address_domain = 0;
        starknet::syscalls::storage_write_syscall(address_domain, address, value).unwrap_syscall();
        starknet::syscalls::storage_read_syscall(address_domain, address).unwrap_syscall()
    }

    #[external]
    #[raw_output]
    fn test_call_contract(
        self: @ContractState,
        contract_address: ContractAddress,
        entry_point_selector: felt252,
        calldata: Array::<felt252>
    ) -> Span::<felt252> {
        starknet::syscalls::call_contract_syscall(
            contract_address, entry_point_selector, calldata.span()
        ).unwrap_syscall().snapshot.span()
    }

    #[external]
    fn test_emit_event(self: @ContractState, keys: Array::<felt252>, data: Array::<felt252>) {
        starknet::syscalls::emit_event_syscall(keys.span(), data.span()).unwrap_syscall();
    }

    #[external]
    fn test_get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
        starknet::syscalls::get_block_hash_syscall(block_number).unwrap_syscall()
    }

    #[external]
    fn test_get_execution_info(
        self: @ContractState,
        // Expected block info.
        block_number: felt252,
        block_timestamp: felt252,
        sequencer_address: felt252,
        // Expected transaction info.
        version: felt252,
        account_address: felt252,
        max_fee: felt252,
        chain_id: felt252,
        nonce: felt252,
        // Expected call info.
        caller_address: felt252,
        contract_address: felt252,
        entry_point_selector: felt252,
    ) {
        let execution_info = starknet::get_execution_info().unbox();
        let block_info = execution_info.block_info.unbox();
        assert(block_info.block_number.into() == block_number, UNEXPECTED_ERROR);
        assert(block_info.block_timestamp.into() == block_timestamp, UNEXPECTED_ERROR);
        assert(block_info.sequencer_address.into() == sequencer_address, UNEXPECTED_ERROR);

        let tx_info = execution_info.tx_info.unbox();
        assert(tx_info.version == version, UNEXPECTED_ERROR);
        assert(tx_info.account_contract_address.into() == account_address, UNEXPECTED_ERROR);
        assert(tx_info.max_fee.into() == max_fee, UNEXPECTED_ERROR);
        assert(tx_info.signature.len() == 1_u32, UNEXPECTED_ERROR);
        let transaction_hash = *tx_info.signature.at(0_u32);
        assert(tx_info.transaction_hash == transaction_hash, UNEXPECTED_ERROR);
        assert(tx_info.chain_id == chain_id, UNEXPECTED_ERROR);
        assert(tx_info.nonce == nonce, UNEXPECTED_ERROR);

        assert(execution_info.caller_address.into() == caller_address, UNEXPECTED_ERROR);
        assert(execution_info.contract_address.into() == contract_address, UNEXPECTED_ERROR);
        assert(
            execution_info.entry_point_selector == entry_point_selector, UNEXPECTED_ERROR
        );
    }

    #[external]
    #[raw_output]
    fn test_library_call(
        self: @ContractState,
        class_hash: ClassHash,
        function_selector: felt252,
        calldata: Array<felt252>
    ) -> Span::<felt252> {
        starknet::library_call_syscall(
            class_hash, function_selector, calldata.span()
        ).unwrap_syscall().snapshot.span()
    }

    #[external]
    #[raw_output]
    fn test_nested_library_call(
        self: @ContractState,
        class_hash: ClassHash,
        lib_selector: felt252,
        nested_selector: felt252,
        a: felt252,
        b: felt252
    ) -> Span::<felt252> {
        let mut nested_library_calldata = Default::default();
        nested_library_calldata.append(class_hash.into());
        nested_library_calldata.append(nested_selector);
        nested_library_calldata.append(2);
        nested_library_calldata.append(a + 1);
        nested_library_calldata.append(b + 1);
        let res = starknet::library_call_syscall(
            class_hash, lib_selector, nested_library_calldata.span(),
        )
            .unwrap_syscall();

        let mut calldata = Default::default();
        calldata.append(a);
        calldata.append(b);
        starknet::library_call_syscall(class_hash, nested_selector, calldata.span())
            .unwrap_syscall()
    }

    #[external]
    fn test_replace_class(self: @ContractState, class_hash: ClassHash) {
        starknet::syscalls::replace_class_syscall(class_hash).unwrap_syscall();
    }

    #[external]
    fn test_send_message_to_l1(self: @ContractState, to_address: felt252, payload: Array::<felt252>) {
        starknet::send_message_to_l1_syscall(to_address, payload.span()).unwrap_syscall();
    }

    /// An external method that requires the `segment_arena` builtin.
    #[external]
    fn segment_arena_builtin(self: @ContractState) {
        let x = felt252_dict_new::<felt252>();
        x.squash();
    }

    #[l1_handler]
    fn l1_handle(self: @ContractState, from_address: felt252, arg: felt252) -> felt252 {
        arg
    }

    #[external]
    fn test_deploy(
        self: @ContractState,
        class_hash: ClassHash,
        contract_address_salt: felt252,
        calldata: Array::<felt252>,
        deploy_from_zero: bool,
    ) {
        starknet::syscalls::deploy_syscall(
            class_hash, contract_address_salt, calldata.span(), deploy_from_zero
        ).unwrap_syscall();
    }
}
