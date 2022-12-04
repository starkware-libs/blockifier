%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import storage_read, storage_write

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
    let (value) = storage_read(address=address);
    storage_write(address=address, value=18);
    return (result=value);
}
