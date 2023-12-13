%lang starknet

from starkware.cairo.common.bool import FALSE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.ec_point import EcPoint
from starkware.starknet.common.syscalls import (
    TxInfo,
    storage_read,
    storage_write,
    library_call,
    deploy,
    call_contract,
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_sequencer_address,
    replace_class,
    get_tx_info,
)
from starkware.starknet.core.os.contract_address.contract_address import get_contract_address

// selector_from_name('transferFrom').
const TRANSFER_FROM_SELECTOR = 0x0041b033f4a31df8067c24d1e9b550a2ce75fd4a29e1147af9752174f0e6cb20;

@storage_var
func number_map(key: felt) -> (value: felt) {
}

@constructor
func constructor{syscall_ptr: felt*}(address: felt, value: felt) {
    storage_write(address=address, value=value);
    return ();
}

@external
func without_arg() {
    return ();
}

@external
func with_arg(num: felt) {
    assert num = 25;
    return ();
}

@external
func return_result(num: felt) -> (result: felt) {
    return (result=num);
}

@external
func bitwise_and{bitwise_ptr: BitwiseBuiltin*}(x: felt, y: felt) {
    bitwise_ptr.x = x;
    bitwise_ptr.y = y;
    let x_and_y = bitwise_ptr.x_and_y;
    let x_xor_y = bitwise_ptr.x_xor_y;
    let x_or_y = bitwise_ptr.x_or_y;
    let bitwise_ptr = bitwise_ptr + BitwiseBuiltin.SIZE;
    assert x_and_y = 15;
    return ();
}

@external
func sqrt{range_check_ptr}(value: felt) {
    alloc_locals;
    local root: felt;

    %{
        from starkware.python.math_utils import isqrt
        value = ids.value % PRIME
        assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
        assert 2 ** 250 < PRIME
        ids.root = isqrt(value)
    %}

    assert root = 9;
    return ();
}

@external
func test_storage_read_write{syscall_ptr: felt*}(address: felt, value: felt) -> (result: felt) {
    storage_write(address=address, value=value);
    let (read_value) = storage_read(address=address);
    return (result=read_value);
}

@external
func write_a_lot{syscall_ptr: felt*}(n_writes: felt, value: felt) {
    if (n_writes == 0) {
        return ();
    }
    storage_write(address=n_writes, value=value);
    return write_a_lot(n_writes - 1, value);
}

@external
func write_and_revert{syscall_ptr: felt*}(address: felt, value: felt) {
    storage_write(address=address, value=value);
    assert 0 = 1;
    return ();
}

@external
func test_long_retdata() -> (a: felt, b: felt, c: felt, d: felt, e: felt) {
    return (a=0, b=1, c=2, d=3, e=4);
}

@external
@raw_output
func test_library_call{syscall_ptr: felt*}(
    class_hash: felt, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

@external
func test_nested_library_call{syscall_ptr: felt*}(
    class_hash: felt, lib_selector: felt, nested_selector: felt, calldata_len: felt, calldata: felt*
) -> (result: felt) {
    alloc_locals;
    assert calldata_len = 2;
    local nested_library_calldata: felt* = new (
        class_hash, nested_selector, 2, calldata[0] + 1, calldata[1] + 1
    );
    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=lib_selector,
        calldata_size=5,
        calldata=nested_library_calldata,
    );

    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=nested_selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );

    return (result=0);
}

@external
@raw_output
func test_call_contract{syscall_ptr: felt*}(
    contract_address: felt, function_selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = call_contract(
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

@external
func test_replace_class{syscall_ptr: felt*}(class_hash: felt) -> () {
    replace_class(class_hash=class_hash);
    return ();
}

@external
func test_deploy{syscall_ptr: felt*}(
    class_hash: felt,
    contract_address_salt: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*,
    deploy_from_zero: felt,
) -> (contract_address: felt) {
    let (contract_address) = deploy(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deploy_from_zero=deploy_from_zero,
    );
    return (contract_address=contract_address);
}

@external
func test_storage_var{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    number_map.write(key=1, value=39);
    let (val) = number_map.read(key=1);
    assert val = 39;
    return ();
}

@external
func test_contract_address{pedersen_ptr: HashBuiltin*, range_check_ptr}(
    salt: felt,
    class_hash: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*,
    deployer_address: felt,
) -> (contract_address: felt) {
    let (contract_address) = get_contract_address{hash_ptr=pedersen_ptr}(
        salt=salt,
        class_hash=class_hash,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deployer_address=deployer_address,
    );

    return (contract_address=contract_address);
}

@external
func foo() {
    return ();
}

@external
func recursive_fail(depth: felt) {
    if (depth == 0) {
        assert 0 = 1;
        return ();
    }
    recursive_fail(depth - 1);
    return ();
}

@external
func recurse(depth: felt) {
    if (depth == 0) {
        return ();
    }
    recurse(depth - 1);
    return ();
}

@external
func recursive_syscall{syscall_ptr: felt*}(contract_address: felt, function_selector: felt, depth: felt) {
    alloc_locals;
    if (depth == 0) {
        return ();
    }
    local calldata: felt* = new(contract_address, function_selector, depth - 1);
    call_contract(
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=3,
        calldata=calldata,
    );
    return ();
}

@external
func test_write_and_transfer{syscall_ptr: felt*}(
    key: felt, value: felt, to: felt, amount: felt, fee_token_address: felt
) -> (retdata_len: felt, retdata: felt*) {
    alloc_locals;
    storage_write(address=key, value=value);
    let caller = get_caller_address();
    local calldata: felt* = new(caller, to, amount, 0);
    let (retdata_len: felt, retdata: felt*) = call_contract(
        contract_address=fee_token_address,
        function_selector=TRANSFER_FROM_SELECTOR,
        calldata_size=4,
        calldata=calldata,
    );
    return (retdata_len=retdata_len, retdata=retdata);
}

@external
func test_get_block_number{syscall_ptr: felt*}(expected_block_number: felt) {
    let (block_number) = get_block_number();
    assert block_number = expected_block_number;
    return ();
}

@external
func test_get_block_timestamp{syscall_ptr: felt*}(expected_block_timestamp: felt) {
    let (block_timestamp) = get_block_timestamp();
    assert block_timestamp = expected_block_timestamp;
    return ();
}

@external
func test_get_sequencer_address{syscall_ptr: felt*}(expected_sequencer_address: felt) {
    let (sequencer_address) = get_sequencer_address();
    assert sequencer_address = expected_sequencer_address;
    return ();
}

@external
func test_get_tx_info{syscall_ptr: felt*, range_check_ptr}(
    expected_version: felt,
    expected_account_contract_address: felt,
    expected_max_fee: felt,
    expected_transaction_hash: felt,
    expected_chain_id: felt,
    expected_nonce: felt,
) {
    let (tx_info_ptr: TxInfo*) = get_tx_info();
    // Copy tx_info fields to make sure they were assigned a value during the system call.
    tempvar tx_info = [tx_info_ptr];

    assert tx_info.version = expected_version;
    assert tx_info.account_contract_address = expected_account_contract_address;
    assert tx_info.max_fee = expected_max_fee;
    assert tx_info.transaction_hash = expected_transaction_hash;
    assert tx_info.chain_id = expected_chain_id;
    assert tx_info.nonce = expected_nonce;
    assert tx_info.signature_len = 0;

    storage_write(address=300, value=tx_info.transaction_hash);
    storage_write(address=311, value=tx_info.chain_id);
    storage_write(address=322, value=tx_info.nonce);

    return ();
}


@external
func test_tx_version{syscall_ptr: felt*}(expected_version: felt) {
    let (tx_info: TxInfo*) = get_tx_info();
    assert tx_info.version = expected_version;

    return ();
}

@storage_var
func two_counters(index: felt) -> (res: (felt, felt)) {
}

@storage_var
func ec_point() -> (res: EcPoint) {
}

// Advances the 'two_counters' storage variable by 'diff'.
@external
func advance_counter{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt, diffs_len: felt, diff_0: felt, diff_1: felt
) {
    assert diffs_len = 2;
    let (val) = two_counters.read(index);
    two_counters.write(index, (val[0] + diff_0, val[1] + diff_1));
    return ();
}
