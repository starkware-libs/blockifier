%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_mul,
    uint256_shr,
    uint256_shl,
    uint256_lt,
    uint256_le,
    uint256_add,
    uint256_unsigned_div_rem,
    uint256_or,
    uint256_sub,
    uint256_and,
    uint256_eq,
    uint256_signed_lt,
    uint256_neg,
    uint256_signed_nn,
)
from starkware.cairo.common.bool import TRUE, FALSE

from contracts.fullmath import FullMath
from contracts.math_utils import Utils

namespace SqrtPriceMath {
    func get_amount0_delta{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0_x96: Uint256, sqrt_ratio1_x96: Uint256, liquidity: felt, roundup: felt
    ) -> (amount0: Uint256) {
        alloc_locals;

        local price_a: Uint256;
        local price_b: Uint256;
        let (is_valid) = uint256_lt(sqrt_ratio1_x96, sqrt_ratio0_x96);
        if (is_valid == TRUE) {
            price_a.low = sqrt_ratio1_x96.low;
            price_a.high = sqrt_ratio1_x96.high;
            price_b.low = sqrt_ratio0_x96.low;
            price_b.high = sqrt_ratio0_x96.high;
        } else {
            price_a.low = sqrt_ratio0_x96.low;
            price_a.high = sqrt_ratio0_x96.high;
            price_b.low = sqrt_ratio1_x96.low;
            price_b.high = sqrt_ratio1_x96.high;
        }

        let (numerator1: Uint256) = uint256_shl(Uint256(liquidity, 0), Uint256(96, 0));
        let (numerator2: Uint256) = uint256_sub(price_b, price_a);

        let (is_valid) = uint256_lt(Uint256(0, 0), price_a);
        assert is_valid = TRUE;

        if (roundup == TRUE) {
            let (tmp: Uint256) = FullMath.uint256_mul_div_roundingup(
                numerator1, numerator2, price_b
            );
            let (delta: Uint256) = FullMath.uint256_div_roundingup(tmp, price_a);
            return (delta,);
        }

        let (tmp: Uint256, _) = FullMath.uint256_mul_div(numerator1, numerator2, price_b);
        let (delta: Uint256, _) = uint256_unsigned_div_rem(tmp, price_a);
        return (delta,);
    }

    func get_amount0_delta2{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0_x96: Uint256, sqrt_ratio1_x96: Uint256, liquidity: felt
    ) -> (amount0: Uint256) {
        let (is_valid) = Utils.is_lt_signed(liquidity, 0);
        if (is_valid == TRUE) {
            let (tmp: Uint256) = get_amount0_delta(sqrt_ratio0_x96, sqrt_ratio1_x96, -liquidity, FALSE);
            let (res: Uint256) = uint256_neg(tmp);
            return (res,);
        }
        let (res: Uint256) = get_amount0_delta(sqrt_ratio0_x96, sqrt_ratio1_x96, liquidity, TRUE);
        return (res,);
    }

    func get_amount1_delta{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0_x96: Uint256, sqrt_ratio1_x96: Uint256, liquidity: felt, roundup: felt
    ) -> (amount1: Uint256) {
        let (is_valid) = uint256_lt(sqrt_ratio1_x96, sqrt_ratio0_x96);
        if (is_valid == TRUE) {
            tempvar price_a = sqrt_ratio1_x96;
            tempvar price_b = sqrt_ratio0_x96;
        } else {
            tempvar price_a = sqrt_ratio0_x96;
            tempvar price_b = sqrt_ratio1_x96;
        }

        let (tmp: Uint256) = uint256_sub(price_b, price_a);
        if (roundup == TRUE) {
            let (delta: Uint256) = FullMath.uint256_mul_div_roundingup(
                Uint256(liquidity, 0), tmp, Uint256(2 ** 96, 0)
            );
            return (delta,);
        }

        let (delta: Uint256, _) = FullMath.uint256_mul_div(
            Uint256(liquidity, 0), tmp, Uint256(2 ** 96, 0)
        );
        return (delta,);
    }

    func get_amount1_delta2{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_ratio0_x96: Uint256, sqrt_ratio1_x96: Uint256, liquidity: felt
    ) -> (amount1: Uint256) {
        let (is_valid) = Utils.is_lt_signed(liquidity, 0);
        if (is_valid == TRUE) {
            let (tmp: Uint256) = get_amount1_delta(sqrt_ratio0_x96, sqrt_ratio1_x96, -liquidity, FALSE);
            let (res: Uint256) = uint256_neg(tmp);
            return (res,);
        }

        let (res: Uint256) = get_amount1_delta(sqrt_ratio0_x96, sqrt_ratio1_x96, liquidity, TRUE);
        return (res,);
    }

    func get_next_sqrt_price_from_amount0_roundingup{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_price_x96: Uint256, liquidity: felt, amount: Uint256, add: felt
    ) -> (res: Uint256) {
        alloc_locals;

        let (is_valid) = uint256_eq(amount, Uint256(0, 0));
        if (is_valid == TRUE) {
            return (sqrt_price_x96,);
        }

        let (numerator1: Uint256) = uint256_shl(Uint256(liquidity, 0), Uint256(96, 0));

        let (product: Uint256, _) = uint256_mul(amount, sqrt_price_x96);
        let (tmp: Uint256, _) = uint256_unsigned_div_rem(product, amount);
        let (not_overflow) = uint256_eq(tmp, sqrt_price_x96);

        if (add == TRUE) {
            if (not_overflow == TRUE) {
                let (denominator: Uint256, _) = uint256_add(numerator1, product);
                let (is_valid) = uint256_le(numerator1, denominator);
                if (is_valid == TRUE) {
                    let (res: Uint256) = FullMath.uint256_mul_div_roundingup(
                        numerator1, sqrt_price_x96, denominator
                    );
                    return (res,);
                } else {
                    tempvar range_check_ptr = range_check_ptr;
                }
            } else {
                tempvar range_check_ptr = range_check_ptr;
            }

            let (tmp: Uint256, _) = uint256_unsigned_div_rem(numerator1, sqrt_price_x96);
            let (tmp2: Uint256, _) = uint256_add(tmp, amount);
            let (res: Uint256) = FullMath.uint256_div_roundingup(numerator1, tmp2);
            return (res,);
        }

        assert not_overflow = TRUE;
        let (is_valid) = uint256_lt(product, numerator1);
        assert is_valid = TRUE;

        let (denominator: Uint256) = uint256_sub(numerator1, product);
        let (res: Uint256) = FullMath.uint256_mul_div_roundingup(
            numerator1, sqrt_price_x96, denominator
        );
        return (res,);
    }

    func get_next_sqrt_price_from_amount1_roundingdown{
        range_check_ptr, bitwise_ptr: BitwiseBuiltin*
    }(sqrt_price_x96: Uint256, liquidity: felt, amount: Uint256, add: felt) -> (res: Uint256) {
        alloc_locals;

        // in both cases, avoid a mulDiv for most inputs
        if (add == TRUE) {
            // amount <= 2 ** 160 - 1
            let (is_valid) = uint256_le(amount, Uint256(2 ** 128 - 1, 2 ** 32 - 1));
            if (is_valid == TRUE) {
                let (tmp: Uint256) = uint256_shl(amount, Uint256(96, 0));
                let (quotient: Uint256, _) = uint256_unsigned_div_rem(tmp, Uint256(liquidity, 0));
                let (res: Uint256, _) = uint256_add(sqrt_price_x96, quotient);
                return (res,);
            }
            let (quotient: Uint256, _) = FullMath.uint256_mul_div(
                amount, Uint256(2 ** 96, 0), Uint256(liquidity, 0)
            );
            let (res: Uint256, _) = uint256_add(sqrt_price_x96, quotient);
            return (res,);
        }

        local quotient: Uint256;
        // amount <= 2 ** 160 - 1
        let (is_valid) = uint256_le(amount, Uint256(2 ** 128 - 1, 2 ** 32 - 1));
        if (is_valid == TRUE) {
            let (tmp: Uint256) = uint256_shl(amount, Uint256(96, 0));
            let (quotient: Uint256) = FullMath.uint256_div_roundingup(tmp, Uint256(liquidity, 0));

            let (is_valid) = uint256_lt(quotient, sqrt_price_x96);
            assert is_valid = TRUE;

            let (res: Uint256) = uint256_sub(sqrt_price_x96, quotient);
            return (res,);
        }

        let (quotient: Uint256) = FullMath.uint256_mul_div_roundingup(
            amount, Uint256(2 ** 96, 0), Uint256(liquidity, 0)
        );
        let (is_valid) = uint256_lt(quotient, sqrt_price_x96);
        assert is_valid = TRUE;

        let (res: Uint256) = uint256_sub(sqrt_price_x96, quotient);
        return (res,);
    }

    func get_next_sqrt_price_from_input{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_price_x96: Uint256, liquidity: felt, amount_in: Uint256, zero_for_one: felt
    ) -> (res: Uint256) {
        let (is_valid) = uint256_lt(Uint256(0, 0), sqrt_price_x96);
        with_attr error_message("sqrt_price_x96 must be greater than 0") {
            assert is_valid = TRUE;
        }
        let (is_valid) = Utils.is_gt(liquidity, 0);
        with_attr error_message("liquidity must be greater than 0") {
            assert is_valid = TRUE;
        }

        if (zero_for_one == TRUE) {
            let (res: Uint256) = get_next_sqrt_price_from_amount0_roundingup(
                sqrt_price_x96, liquidity, amount_in, TRUE
            );
            return (res,);
        }

        let (res: Uint256) = get_next_sqrt_price_from_amount1_roundingdown(
            sqrt_price_x96, liquidity, amount_in, TRUE
        );
        return (res,);
    }

    func get_next_sqrt_price_from_output{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        sqrt_price_x96: Uint256, liquidity: felt, amount_out: Uint256, zero_for_one: felt
    ) -> (res: Uint256) {
        let (is_valid) = uint256_lt(Uint256(0, 0), sqrt_price_x96);
        with_attr error_message("sqrt_price_x96 must be greater than 0") {
            assert is_valid = TRUE;
        }
        let (is_valid) = Utils.is_gt(liquidity, 0);
        with_attr error_message("liquidity must be greater than 0") {
            assert is_valid = TRUE;
        }

        if (zero_for_one == TRUE) {
            let (res: Uint256) = get_next_sqrt_price_from_amount1_roundingdown(
                sqrt_price_x96, liquidity, amount_out, FALSE
            );
            return (res,);
        }

        let (res: Uint256) = get_next_sqrt_price_from_amount0_roundingup(
            sqrt_price_x96, liquidity, amount_out, FALSE
        );
        return (res,);
    }
}
