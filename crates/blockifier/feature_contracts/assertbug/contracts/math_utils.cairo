%lang starknet

from starkware.cairo.common.math_cmp import is_nn, is_le, is_le_felt
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_shr,
    uint256_pow2,
    uint256_sub,
    uint256_add,
    uint256_signed_nn,
    uint256_lt,
    uint256_check
)
from starkware.cairo.common.bool import TRUE, FALSE

namespace Utils {
    // P = 2 ** 251 + 17 * (2 ** 192) + 1
    // const MAX_FELT_INT = 1809251394333065606848661391547535052811553607665798349986546028067936010240 # p // 2

    const MAX_UINT128 = 0xffffffffffffffffffffffffffffffff;

    func is_eq(a: felt, b: felt) -> (res: felt) {
        if (a == b) {
            return (1,);
        }
        return (0,);
    }

    func is_gt{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        let is_valid = is_nn(b - a);
        if (is_valid == TRUE) {
            return (0,);
        }
        return (1,);
    }

    func is_ge{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        let is_valid = is_nn(a - b);
        return (is_valid,);
    }

    func is_lt_signed{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        let is_valid = is_nn(a - b);
        if (is_valid == FALSE) {
            return (1,);
        }
        return (0,);
    }

    // 0 <= res < 2 ** 128
    func u128_safe_add{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        let res = a + b;
        let is_valid = is_nn(res);
        with_attr error_message("safe_add: minus result") {
            assert is_valid = TRUE;
        }

        let is_valid = is_le(res, Utils.MAX_UINT128);
        with_attr error_message("safe_add: overflow") {
            assert is_valid = TRUE;
        }

        return (res,);
    }

    func cond_assign{range_check_ptr}(cond: felt, new_value: felt, old_value: felt) -> (res: felt) {
        if (cond == TRUE) {
            return (new_value,);
        }
        return (old_value,);
    }

    func cond_assign_uint256{range_check_ptr}(
        cond: felt, new_value: Uint256, old_value: Uint256
    ) -> (res: Uint256) {
        if (cond == TRUE) {
            return (new_value,);
        }
        return (old_value,);
    }

    func int256_shr{range_check_ptr}(a: Uint256, b: felt) -> (res: Uint256) {
        alloc_locals;
        let (res: Uint256) = uint256_shr(a, Uint256(b, 0));
        let (is_valid) = uint256_signed_nn(a);
        if (is_valid == FALSE) {
            let (tmp1: Uint256) = uint256_pow2(Uint256(256 - b, 0));
            let (tmp2: Uint256) = uint256_sub(tmp1, Uint256(1, 0));
            let (tmp3: Uint256) = uint256_sub(Uint256(2 ** 128 - 1, 2 ** 128 - 1), tmp2);
            let (res2: Uint256, _) = uint256_add(res, tmp3);
            return (res2,);
        }

        return (res,);
    }

    func min{range_check_ptr}(a: felt, b: felt) -> felt {
        let is_valid = is_le_felt(a, b);
        if (is_valid == TRUE) {
            return a;
        }
        return b;
    }

    func max{range_check_ptr}(a: felt, b: felt) -> felt {
        let is_valid = is_le_felt(a, b);
        if (is_valid == TRUE) {
            return b;
        }
        return a;
    }

    func assert_is_uint128{range_check_ptr}(a: felt) {
        let is_valid = is_le(a, MAX_UINT128);
        with_attr error_message("assert_uint128: overflow") {
            assert is_valid = TRUE;
        }
        return ();
    }

    func assert_is_uint160{range_check_ptr}(a: Uint256) {
        uint256_check(a);
        let (is_valid) = uint256_lt(a, Uint256(0, 2 ** 32));
        with_attr error_message("assert_uint160: overflow") {
            assert is_valid = TRUE;
        }
        return ();
    }
}
