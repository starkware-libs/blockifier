#[contract]
mod TestContract {
    use dict::Felt252DictTrait;
    use starknet::StorageAddress;

    struct Storage {
        my_storage_var: felt252
    }

    #[external]
    fn test_storage_read_write(address: StorageAddress, value: felt252) -> felt252 {
        starknet::syscalls::storage_write_syscall(0, address, value).unwrap_syscall();
        starknet::syscalls::storage_read_syscall(0, address).unwrap_syscall()
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
