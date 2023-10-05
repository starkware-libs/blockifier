%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_block_timestamp
from starkware.cairo.common.uint256 import Uint256


//
// Storage Pair
//

// @dev reserve for token0
@storage_var
func _reserve0() -> (res: Uint256) {
}

// @dev reserve for token1
@storage_var
func _reserve1() -> (res: Uint256) {
}

// @dev block timestamp for last update
@storage_var
func _block_timestamp_last() -> (ts: felt) {
}

//
// Constructor
//

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(reserve0: Uint256, reserve1: Uint256) {
    let (block_timestamp) = get_block_timestamp();
    _block_timestamp_last.write(block_timestamp);
    _reserve0.write(reserve0);
    _reserve1.write(reserve1);
    return ();
}

//
// Getters Pair
//

// @notice Current reserves for tokens in the pair
// @return reserve0 reserve for token0
// @return reserve1 reserve for token1
// @return block_timestamp_last block timestamp for last update
@view
func get_reserves{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    reserve0: Uint256, reserve1: Uint256, block_timestamp_last: felt
) {
    let (reserve0) = _reserve0.read();
    let (reserve1) = _reserve1.read();
    let (block_timestamp_last) = _block_timestamp_last.read();
    return (reserve0, reserve1, block_timestamp_last);
}
