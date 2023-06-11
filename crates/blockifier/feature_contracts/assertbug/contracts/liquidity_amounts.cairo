%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_shl,
    uint256_lt,
    uint256_le,
    uint256_unsigned_div_rem,
    uint256_sub,
)
from starkware.cairo.common.bool import FALSE, TRUE

from contracts.fullmath import FullMath
from contracts.math_utils import Utils

namespace LiquidityAmounts {
    func _check_ratio{range_check_ptr}(sqrt_ratio_a: Uint256, sqrt_ratio_b: Uint256) -> (
        res1: Uint256, res2: Uint256
    ) {
        alloc_locals;
        let (is_valid) = uint256_lt(sqrt_ratio_b, sqrt_ratio_a);
        if (is_valid == TRUE) {
            return (sqrt_ratio_b, sqrt_ratio_a);
        }
        return (sqrt_ratio_a, sqrt_ratio_b);
    }

    func get_amount0_for_liquidity{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0: Uint256, sqrt_ratio1: Uint256, liquidity: felt
    ) -> (amount0: Uint256) {
        alloc_locals;

        let (new_liquidity: Uint256) = uint256_shl(Uint256(liquidity, 0), Uint256(96, 0));
        let (tmp: Uint256) = uint256_sub(sqrt_ratio1, sqrt_ratio0);
        let (tmp2: Uint256, _) = FullMath.uint256_mul_div(new_liquidity, tmp, sqrt_ratio1);

        let (amount0: Uint256, _) = uint256_unsigned_div_rem(tmp2, sqrt_ratio0);
        return (amount0,);
    }

    func get_amount1_for_liquidity{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0: Uint256, sqrt_ratio1: Uint256, liquidity: felt
    ) -> (amount1: Uint256) {
        alloc_locals;

        let (tmp: Uint256) = uint256_sub(sqrt_ratio1, sqrt_ratio0);
        let (amount1: Uint256, _) = FullMath.uint256_mul_div(Uint256(liquidity, 0), tmp, Uint256(2 ** 96, 0));
        return (amount1,);
    }

    func get_amounts_for_liquidity{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio: Uint256, sqrt_ratio_a: Uint256, sqrt_ratio_b: Uint256, liquidity: felt
    ) -> (amount0: Uint256, amount1: Uint256) {
        alloc_locals;

        let (sqrt_ratio0, sqrt_ratio1) = _check_ratio(sqrt_ratio_a, sqrt_ratio_b);

        let (is_valid) = uint256_le(sqrt_ratio, sqrt_ratio0);

        if (is_valid == TRUE) {
            let (amount0: Uint256) = get_amount0_for_liquidity(sqrt_ratio0, sqrt_ratio1, liquidity);
            return (amount0, Uint256(0, 0));
        }

        let (is_valid) = uint256_lt(sqrt_ratio, sqrt_ratio1);
        if (is_valid == TRUE) {
            let (amount0: Uint256) = get_amount0_for_liquidity(sqrt_ratio, sqrt_ratio1, liquidity);
            let (amount1: Uint256) = get_amount1_for_liquidity(sqrt_ratio0, sqrt_ratio, liquidity);
            return (amount0, amount1);
        }

        let (amount1: Uint256) = get_amount1_for_liquidity(sqrt_ratio0, sqrt_ratio1, liquidity);

        return (Uint256(0, 0), amount1);
    }

    func get_liquidity_for_amount0{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0: Uint256, sqrt_ratio1: Uint256, amount0: Uint256
    ) -> (liquidity: felt) {
        alloc_locals;

        let (tmp: Uint256, _) = FullMath.uint256_mul_div(
            sqrt_ratio0, sqrt_ratio1, Uint256(2 ** 96, 0)
        );

        let (ratio: Uint256) = uint256_sub(sqrt_ratio1, sqrt_ratio0);
        let (tmp2: Uint256, _) = FullMath.uint256_mul_div(amount0, tmp, ratio);
        assert tmp2.high = 0;

        return (tmp2.low,);
    }

    func get_liquidity_for_amount1{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0: Uint256, sqrt_ratio1: Uint256, amount1: Uint256
    ) -> (liquidity: felt) {
        alloc_locals;

        let (ratio: Uint256) = uint256_sub(sqrt_ratio1, sqrt_ratio0);
        let (tmp: Uint256, _) = FullMath.uint256_mul_div(amount1, Uint256(2 ** 96, 0), ratio);
        assert tmp.high = 0;

        return (tmp.low,);
    }

    func get_liquidity_for_amounts{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio: Uint256,
        sqrt_ratio_a: Uint256,
        sqrt_ratio_b: Uint256,
        amount0: Uint256,
        amount1: Uint256,
    ) -> (liquidity: felt) {
        alloc_locals;

        let (sqrt_ratio0, sqrt_ratio1) = _check_ratio(sqrt_ratio_a, sqrt_ratio_b);

        let (is_valid) = uint256_le(sqrt_ratio, sqrt_ratio0);

        if (is_valid == TRUE) {
            let (liquidity) = get_liquidity_for_amount0(sqrt_ratio0, sqrt_ratio1, amount0);
            return (liquidity,);
        }

        let (is_valid) = uint256_lt(sqrt_ratio, sqrt_ratio1);
        if (is_valid == TRUE) {
            let (liquidity0) = get_liquidity_for_amount0(sqrt_ratio, sqrt_ratio1, amount0);
            let (liquidity1) = get_liquidity_for_amount1(sqrt_ratio0, sqrt_ratio, amount1);
            let liquidity = Utils.min(liquidity0, liquidity1);
            return (liquidity,);
        }

        let (liquidity) = get_liquidity_for_amount1(sqrt_ratio0, sqrt_ratio1, amount1);
        return (liquidity,);
    }
}
