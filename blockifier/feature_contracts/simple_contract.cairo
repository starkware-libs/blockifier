%lang starknet

from starkware.cairo.common.bool import FALSE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import storage_read, storage_write, library_call, deploy

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
func get_value{syscall_ptr: felt*}(address: felt) -> (result: felt) {
    storage_write(address=address, value=18);
    let (value) = storage_read(address=address);
    return (result=value);
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
func test_deploy{syscall_ptr: felt*}(
    class_hash: felt,
    contract_address_salt: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*,
) -> (contract_address: felt) {
    let (contract_address) = deploy(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deploy_from_zero=FALSE,
    );
    return (contract_address=contract_address);
}
