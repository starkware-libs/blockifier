#[starknet::contract]
mod TestContract {
    use box::BoxTrait;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::syscalls::get_execution_info_syscall;
    use starknet::info::ExecutionInfo;
    use starknet::info::BlockInfo;
    use starknet::info::TxInfo;
    use starknet::{SyscallResultTrait, SyscallResult};

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn test_get_execution_info(
        self: @ContractState,
        expected_block_number: u64,
        expected_block_timestamp: u64,
        expected_sequencer_address: ContractAddress,
        expected_tx_info: TxInfo,
        expected_caller_address: felt252,
        expected_contract_address: felt252,
        expected_entry_point_selector: felt252,
    ) {
        let execution_info = get_execution_info_syscall().unwrap_syscall().unbox();
        let block_info = execution_info.block_info.unbox();

        assert(block_info.block_number == expected_block_number, 'BLOCK_NUMBER_MISMATCH');
        assert(block_info.block_timestamp == expected_block_timestamp, 'BLOCK_TIMESTAMP_MISMATCH');
        assert(
            block_info.sequencer_address.into() == expected_sequencer_address, 'SEQUENCER_MISMATCH',
        );

        let tx_info = execution_info.tx_info.unbox();
        assert(tx_info.version == expected_tx_info.version, 'TX_INFO_VERSION_MISMATCH');
        assert(
            tx_info.account_contract_address.into() == expected_tx_info.account_contract_address,
            'ACCOUNT_C_ADDRESS_MISMATCH',
        );
        assert(tx_info.max_fee == expected_tx_info.max_fee, 'TX_INFO_MAX_FEE_MISMATCH');
        assert(tx_info.signature == expected_tx_info.signature, 'TX_INFO_SIGNATURE_MISMATCH');
        assert(
            tx_info.transaction_hash == expected_tx_info.transaction_hash, 'TX_INFO_HASH_MISMATCH',
        );
        assert(tx_info.chain_id == expected_tx_info.chain_id, 'TX_INFO_CHAIN_ID_MISMATCH');
        assert(tx_info.nonce == expected_tx_info.nonce, 'TX_INFO_NONCE_MISMATCH');

        assert(execution_info.caller_address.into() == expected_caller_address, 'CALLER_MISMATCH');
        assert(
            execution_info.contract_address.into() == expected_contract_address, 'CONTRACT_MISMATCH'
        );
        assert(
            execution_info.entry_point_selector == expected_entry_point_selector,
            'SELECTOR_MISMATCH'
        );
    }
}
