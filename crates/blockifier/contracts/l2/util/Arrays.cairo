%lang starknet

from starkware.cairo.common.uint256 import (Uint256, uint256_add)

func uint256_array_sum{range_check_ptr}(arr_len: felt, arr: Uint256*) -> (sum: Uint256):
    if arr_len == 0:
        return (Uint256(0, 0))
    end


    let (sub_sum) = uint256_array_sum(arr_len-1, arr + Uint256.SIZE)
    let (sum, is_overflow) = uint256_add([arr], sub_sum)
    assert is_overflow = 0

    return (sum)
end

