%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

@external
func with_arg(num: felt) {
    assert num = 25;
    ret;
}

@external
func without_arg() {
    ret;
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
    ret;
}
