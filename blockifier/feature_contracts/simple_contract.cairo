%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import (
    storage_read,
    storage_write,
    library_call,
    call_contract,
)
from starkware.cairo.common.registers import get_fp_and_pc

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
func write_and_read_value{syscall_ptr: felt*}(address: felt, value: felt) -> (result: felt) {
    storage_write(address=address, value=value);
    let (read_value) = storage_read(address=address);
    return (result=read_value);
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
func test_library_call_tree{syscall_ptr: felt*}(
    class_hash: felt, lib_selector: felt, val_selector: felt, calldata_len: felt, calldata: felt*,
) -> (result: felt) {
    alloc_locals;
    local lib_calldata: (felt, felt, felt, felt, felt) = (class_hash, val_selector, calldata_len,
        calldata[0]+1, calldata[1]+1);
    let (__fp__, _) = get_fp_and_pc();
    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=lib_selector,
        calldata_size=5,
        calldata=cast(&lib_calldata, felt*),
    );

    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=val_selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );

    return (result=0);
}

@external
@raw_output
func test_call_contract{syscall_ptr: felt*}(
    contract_address: felt, function_selector, calldata_len, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = call_contract(
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}
