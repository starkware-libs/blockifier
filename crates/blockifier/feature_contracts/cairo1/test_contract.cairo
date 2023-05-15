#[contract]
mod TestContract {
    use dict::Felt252DictTrait;
    use starknet::StorageAddress;
    use starknet::ClassHash;
    use array::ArrayTrait;
    use clone::Clone;

    struct Storage {
        my_storage_var: felt252
    }

    #[external]
    fn test_storage_read_write(address: StorageAddress, value: felt252) -> felt252 {
        starknet::syscalls::storage_write_syscall(0, address, value).unwrap_syscall();
        starknet::syscalls::storage_read_syscall(0, address).unwrap_syscall()
    }

    #[external]
    fn test_library_call(
        class_hash: ClassHash, function_selector: felt252, calldata: Array<felt252>
    ) -> Array<felt252> {
        starknet::library_call_syscall(
            class_hash,
            function_selector,
            calldata.span(),
        ).unwrap_syscall().snapshot.clone()
    }

    /// An external method that requires the `segment_arena` builtin.
    #[external]
    fn segment_arena_builtin() {
        let x = felt252_dict_new::<felt252>();
        x.squash();
    }

    #[l1_handler]
    fn l1_handle(from_address: felt252, arg: felt252) -> felt252 {
        arg
    }
}
