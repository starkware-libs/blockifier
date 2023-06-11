%lang starknet

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
    uint256_xor,
    uint256_mul_div_mod,
)
from starkware.cairo.common.math import abs_value
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math_cmp import is_nn
from starkware.cairo.common.bool import TRUE, FALSE

from contracts.math_utils import Utils

namespace FullMath {

    //func uint256_add_rem{range_check_ptr}(
    //    a: Uint256, b: Uint256, denominator: Uint256, rem_256: Uint256
    //) -> (rem: Uint256) {
    //    alloc_locals;
    //    let (res: Uint256, carry) = uint256_add(a, b);
    //    let (_, rem: Uint256) = uint256_unsigned_div_rem(res, denominator);
    //    let (is_valid) = Utils.is_gt(carry, 0);
    //    if (is_valid == TRUE) {
    //        let (res: Uint256) = uint256_add_rem(rem, rem_256, denominator, rem_256);
    //        return (res,);
    //    }
    //    return (rem,);
    //}

    //func uint512_div_rem{range_check_ptr}(
    //    low: Uint256, high: Uint256, denominator: Uint256, rem_256: Uint256
    //) -> (remainder: Uint256) {
    //    alloc_locals;

    //    // high * 256_rem % c
    //    let (_, rem_low: Uint256) = uint256_unsigned_div_rem(low, denominator);

    //    let (tmp: Uint256, tmp2: Uint256) = uint256_mul(rem_256, high);
    //    let (is_valid) = uint256_eq(Uint256(0, 0), tmp2);
    //    if (is_valid == FALSE) {
    //        let (rem_high: Uint256) = uint512_div_rem(tmp, tmp2, denominator, rem_256);
    //        let (res) = uint256_add_rem(rem_low, rem_high, denominator, rem_256);
    //        return (res,);
    //    }

    //    let (_, rem_high: Uint256) = uint256_unsigned_div_rem(tmp, denominator);
    //    let (res) = uint256_add_rem(rem_low, rem_high, denominator, rem_256);
    //    return (res,);
    //}

    // a * b / c
    func uint256_mul_div{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        a: Uint256, b: Uint256, c: Uint256
    ) -> (res: Uint256, rem_final: Uint256) {
        alloc_locals;

        local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;

        let (is_valid) = uint256_eq(c, Uint256(0, 0));
        with_attr error_message("denominator is zero") {
            assert is_valid = FALSE;
        }

        let (low: Uint256, high: Uint256) = uint256_mul(a, b);
        let (_, _, rem_final: Uint256) = uint256_mul_div_mod(a, b, c);

        // check if high < c
        let (is_valid) = uint256_lt(high, c);
        with_attr error_message("overflows uint256") {
            assert is_valid = TRUE;
        }

        // check if high is 0
        let (is_valid) = uint256_eq(Uint256(0, 0), high);
        if (is_valid == TRUE) {
            let (res: Uint256, rem_low: Uint256) = uint256_unsigned_div_rem(low, c);
            return (res, rem_low);
        }

        // Subtract 256 bit number from 512 bit number
        let (is_valid) = uint256_lt(low, rem_final);
        let (prod1: Uint256) = uint256_sub(high, Uint256(is_valid, 0));
        let (prod0: Uint256) = uint256_sub(low, rem_final);

        // Factor powers of two out of denominator
        // Compute largest power of two divisor of denominator.
        // Always >= 1.
        let (minus_c: Uint256) = uint256_neg(c);
        let (twos: Uint256) = uint256_and(minus_c, c);

        // Divide denominator by power of two
        let (denominator: Uint256, _) = uint256_unsigned_div_rem(c, twos);

        // Divide [prod1 prod0] by the factors of two
        let (prod0: Uint256, _) = uint256_unsigned_div_rem(prod0, twos);

        let (tmp: Uint256) = uint256_neg(twos);
        let (tmp: Uint256, _) = uint256_unsigned_div_rem(tmp, twos);
        let (twos: Uint256, _) = uint256_add(tmp, Uint256(1, 0));

        let (tmp: Uint256, _) = uint256_mul(prod1, twos);

        let (prod0: Uint256, _) = uint256_add(prod0, tmp);

        let (tmp: Uint256, _) = uint256_mul(Uint256(3, 0), denominator);
        let (inv: Uint256) = uint256_xor(tmp, Uint256(2, 0));

        // inverse mod 2**8
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        // inverse mod 2**16
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        // inverse mod 2**32
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        // inverse mod 2**64
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        // inverse mod 2**128
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        // inverse mod 2**256
        let (tmp: Uint256, _) = uint256_mul(denominator, inv);
        let (tmp: Uint256) = uint256_sub(Uint256(2, 0), tmp);
        let (inv: Uint256, _) = uint256_mul(inv, tmp);

        let (result: Uint256, _) = uint256_mul(prod0, inv);
        return (result, rem_final);
    }

    func uint256_mul_div_roundingup{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        a: Uint256, b: Uint256, c: Uint256
    ) -> (res: Uint256) {
        alloc_locals;

        let (res: Uint256, rem: Uint256) = uint256_mul_div(a, b, c);
        let (is_valid) = uint256_lt(Uint256(0, 0), rem);
        if (is_valid == TRUE) {
            let (is_valid) = uint256_lt(res, Uint256(Utils.MAX_UINT128, Utils.MAX_UINT128));
            with_attr error_message("overflows uint256") {
                assert is_valid = TRUE;
            }
            let (tmp: Uint256, _) = uint256_add(res, Uint256(1, 0));
            return (tmp,);
        }
        return (res,);
    }

    func uint256_div_roundingup{range_check_ptr}(a: Uint256, b: Uint256) -> (res: Uint256) {
        alloc_locals;

        let (is_valid) = uint256_eq(Uint256(0, 0), b);
        if (is_valid == TRUE) {
            return (Uint256(0, 0),);
        }

        let (res: Uint256, rem: Uint256) = uint256_unsigned_div_rem(a, b);
        let (is_valid) = uint256_lt(Uint256(0, 0), rem);
        if (is_valid == TRUE) {
            let (tmp: Uint256, _) = uint256_add(res, Uint256(1, 0));
            return (tmp,);
        }
        return (res,);
    }
}
