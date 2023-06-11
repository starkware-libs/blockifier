%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_block_timestamp
from starkware.cairo.common.uint256 import Uint256, uint256_le, uint256_add, uint256_lt, uint256_sub, uint256_neg, uint256_eq, uint256_signed_lt, uint256_check
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math_cmp import is_le_felt

from contracts.tickmath import TickMath

namespace SwapUtils {
    func get_limit_price{range_check_ptr} (
        sqrt_price_limit: Uint256, 
        zero_for_one: felt
    ) -> (res: Uint256) {

        alloc_locals;

        let (flag) = uint256_eq(sqrt_price_limit, Uint256(0, 0));
        if (flag == TRUE) {
            if (zero_for_one == TRUE) {
                let res: Uint256 = Uint256(TickMath.MIN_SQRT_RATIO + 1, 0);
                return (res,);
            }
            let (res: Uint256) = uint256_sub(Uint256(TickMath.MAX_SQRT_RATIO_LOW, TickMath.MAX_SQRT_RATIO_HIGH), Uint256(1, 0));
            return (res,);
        }

        return (sqrt_price_limit,);
    }

    func check_deadline{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(deadline: felt) {
        alloc_locals;

        // Expired
        with_attr error_message("deadline") {
            let (block_timestamp) = get_block_timestamp();
            let flag = is_le_felt(block_timestamp, deadline);
            assert flag = TRUE;
        }

        return ();
    }
}