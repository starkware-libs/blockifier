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
    use starknet::{
    eth_address::U256IntoEthAddress, EthAddress,
    secp256_trait::{Signature, verify_eth_signature},
};

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

    #[external(v0)]
    fn test_storage_read_write(self: @ContractState, address: StorageAddress, value: felt252) -> felt252 {
        let address_domain = 0;
        starknet::syscalls::storage_write_syscall(address_domain, address, value).unwrap_syscall();
        starknet::syscalls::storage_read_syscall(address_domain, address).unwrap_syscall()
    }

    #[external(v0)]
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

    #[external(v0)]
    fn test_emit_event(self: @ContractState, keys: Array::<felt252>, data: Array::<felt252>) {
        starknet::syscalls::emit_event_syscall(keys.span(), data.span()).unwrap_syscall();
    }

    #[external(v0)]
    fn test_get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
        starknet::syscalls::get_block_hash_syscall(block_number).unwrap_syscall()
    }

    #[external(v0)]
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

    #[external(v0)]
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

    #[external(v0)]
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

    #[external(v0)]
    fn test_replace_class(self: @ContractState, class_hash: ClassHash) {
        starknet::syscalls::replace_class_syscall(class_hash).unwrap_syscall();
    }

    #[external(v0)]
    fn test_send_message_to_l1(self: @ContractState, to_address: felt252, payload: Array::<felt252>) {
        starknet::send_message_to_l1_syscall(to_address, payload.span()).unwrap_syscall();
    }

    /// An external method that requires the `segment_arena` builtin.
    #[external(v0)]
    fn segment_arena_builtin(self: @ContractState) {
        let x = felt252_dict_new::<felt252>();
        x.squash();
    }

    #[l1_handler]
    fn l1_handle(self: @ContractState, from_address: felt252, arg: felt252) -> felt252 {
        arg
    }

    #[external(v0)]
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


    #[external(v0)]
    fn test_keccak(ref self: ContractState) {
        let mut input = Default::default();
        input.append(u256 { low: 1, high: 0 });

        let res = keccak::keccak_u256s_le_inputs(input.span());
        assert(res.low == 0x587f7cc3722e9654ea3963d5fe8c0748, 'Wrong hash value');
        assert(res.high == 0xa5963aa610cb75ba273817bce5f8c48f, 'Wrong hash value');

        let mut input = Default::default();
        input.append(1_u64);
        match starknet::syscalls::keccak_syscall(input.span()) {
            Result::Ok(_) => panic_with_felt252('Should fail'),
            Result::Err(revert_reason) =>
                assert(*revert_reason.at(0) == 'Invalid input length', 'Wrong error msg'),
        }
    }

    #[external(v0)]
    fn test_secp256k1(ref self: ContractState) {
        // Test a point not on the curve.
        assert (starknet::secp256k1::secp256k1_new_syscall(
            x: 0, y: 1).unwrap_syscall().is_none(), 'Should be none');

        // Test a point with x == Secp_prime.
        match starknet::secp256k1::secp256k1_new_syscall(
            x: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, y: 1) {
            Result::Ok(_) => panic_with_felt252('Should fail'),
            Result::Err(revert_reason) =>
                assert(*revert_reason.at(0) == 'Invalid argument', 'Wrong error msg'),
        }

        // Test a point on the curve.
        let x = 0xF728B4FA42485E3A0A5D2F346BAA9455E3E70682C2094CAC629F6FBED82C07CD;
        let y = 0x8E182CA967F38E1BD6A49583F43F187608E031AB54FC0C4A8F0DC94FAD0D0611;
        let p0 = starknet::secp256k1::secp256k1_new_syscall(x, y).unwrap_syscall().unwrap();

        let (x_coord, y_coord) = starknet::secp256k1::secp256k1_get_xy_syscall(
                p0).unwrap_syscall();
        assert (
            x_coord == x && y_coord == y,
            'Unexpected coordinates');

        let y_parity = true;
        let (msg_hash, r, s, expected_public_key_x, expected_public_key_y, eth_address) =
            get_message_and_signature(
            :y_parity
        );
        verify_eth_signature::<starknet::secp256k1::Secp256k1Point>(
            :msg_hash, signature: Signature{ r, s, y_parity }, :eth_address);
    }

    /// Returns a golden valid message hash and its signature, for testing.
    fn get_message_and_signature(y_parity: bool) -> (u256, u256, u256, u256, u256, EthAddress) {
        let msg_hash = 0xe888fbb4cf9ae6254f19ba12e6d9af54788f195a6f509ca3e934f78d7a71dd85;
        let r = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
        let s = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;

        let (public_key_x, public_key_y) = if y_parity {
            (
                0xa9a02d48081294b9bb0d8740d70d3607feb20876964d432846d9b9100b91eefd,
                0x18b410b5523a1431024a6ab766c89fa5d062744c75e49efb9925bf8025a7c09e
            )
        } else {
            (
                0x57a910a2a58ef7d57f452e1f6ea7ee0080789091de946b0ca6e5c6af2c8ff5c8,
                0x249d233d0d21f35db55ce852edbd340d31e92ea4d591886149ca5d89911331ac
            )
        };
        let eth_address = 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256.into();

        (msg_hash, r, s, public_key_x, public_key_y, eth_address)
    }
}

