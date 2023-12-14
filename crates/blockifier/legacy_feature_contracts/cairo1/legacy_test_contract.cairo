#[starknet::contract]
mod TestContract {
    use box::BoxTrait;
    use array::SpanTrait;
    use traits::Into;

    #[storage]
    struct Storage {
        my_storage_var: felt252,
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
        signature: Span<felt252>,
        transaction_hash: felt252,
        chain_id: felt252,
        nonce: felt252,
        // Expected call info.
        caller_address: felt252,
        contract_address: felt252,
        entry_point_selector: felt252,
    ) {
        let execution_info = starknet::get_execution_info().unbox();
        let block_info = execution_info.block_info.unbox();
        assert(block_info.block_number.into() == block_number, 'BLOCK_NUMBER_MISMATCH');
        assert(block_info.block_timestamp.into() == block_timestamp, 'BLOCK_TIMESTAMP_MISMATCH');
        assert(block_info.sequencer_address.into() == sequencer_address, 'SEQUENCER_MISMATCH');

        let tx_info = execution_info.tx_info.unbox();
        assert(tx_info.version == version, 'VERSION_MISMATCH');
        assert(tx_info.account_contract_address.into() == account_address, 'ACCOUNT_MISMATCH');
        assert(tx_info.max_fee.into() == max_fee, 'MAX_FEE_MISMATCH');
        assert(tx_info.signature.len() == 0_u32, 'SIGNATURE_MISMATCH');
        assert(tx_info.transaction_hash == transaction_hash, 'TRANSACTION_HASH_MISMATCH');
        assert(tx_info.chain_id == chain_id, 'CHAIN_ID_MISMATCH');
        assert(tx_info.nonce == nonce, 'NONCE_MISMATCH');

        assert(execution_info.caller_address.into() == caller_address, 'CALLER_MISMATCH');
        assert(execution_info.contract_address.into() == contract_address, 'CONTRACT_MISMATCH');
        assert(execution_info.entry_point_selector == entry_point_selector, 'SELECTOR_MISMATCH');
    }
}
