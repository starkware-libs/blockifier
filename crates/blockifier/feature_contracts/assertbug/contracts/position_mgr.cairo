%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_lt, uint256_sub, uint256_signed_nn, uint256_add
from starkware.cairo.common.bool import TRUE, FALSE

from contracts.fullmath import FullMath
from contracts.math_utils import Utils

struct PositionInfo {
    liquidity: felt,
    fee_growth_inside0_x128: Uint256,
    fee_growth_inside1_x128: Uint256,
    tokens_owed0: felt,
    tokens_owed1: felt,
}

@storage_var
func PositionMgr_data(address: felt, tick_lower: felt, tick_upper: felt) -> (position: PositionInfo) {
}

namespace PositionMgr {
    func _update_position_1{range_check_ptr}(liquidity_delta: felt, liquidity: felt) -> (
        res: felt
    ) {
        // TODO: use uint128 and int128 to replace felt
        if (liquidity_delta == 0) {
            let (is_valid) = Utils.is_gt(liquidity, 0);
            with_attr error_message("disallow pokes for 0 liquidity positions") {
                assert is_valid = TRUE;
            }
            return (liquidity,);
        }

        let (liquidity_next) = Utils.u128_safe_add(liquidity, liquidity_delta);
        return (liquidity_next,);
    }

    func update_position{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        bitwise_ptr: BitwiseBuiltin*,
    }(
        position: PositionInfo,
        liquidity_delta: felt, // int128
        fee_growth_inside0_x128: Uint256,
        fee_growth_inside1_x128: Uint256,
        address: felt,
        tick_lower: felt,
        tick_upper: felt,
    ) -> (new_position: PositionInfo) {
        alloc_locals;

        let (liquidity) = _update_position_1(liquidity_delta, position.liquidity);

        let (tmp256: Uint256) = uint256_sub(
            fee_growth_inside0_x128, position.fee_growth_inside0_x128
        );
        // TODO: check if minus
        //let (is_valid) = uint256_signed_nn(tmp256);
        //assert is_valid = TRUE;
        let (tmp256_2: Uint256, _) = FullMath.uint256_mul_div(
            tmp256, Uint256(position.liquidity, 0), Uint256(0, 1)
        );
        let tokens_owed0 = tmp256_2.low;

        let (tmp256: Uint256) = uint256_sub(
            fee_growth_inside1_x128, position.fee_growth_inside1_x128
        );
        // TODO: check if minus
        //let (is_valid) = uint256_signed_nn(tmp256);
        //assert is_valid = TRUE;
        let (tmp256_2: Uint256, _) = FullMath.uint256_mul_div(
            tmp256, Uint256(position.liquidity, 0), Uint256(0, 1)
        );
        let tokens_owed1 = tmp256_2.low;

        let (tmp) = Utils.is_lt_signed(0, tokens_owed0);
        let (tmp2) = Utils.is_lt_signed(0, tokens_owed1);
        let (is_valid) = Utils.is_lt_signed(0, tmp + tmp2);
        if (is_valid == TRUE) {
            // overflow is acceptable, have to withdraw before you hit type(uint128).max fees
            // ignore overflows
            let (res0: Uint256, _) = uint256_add(Uint256(position.tokens_owed0, 0), Uint256(tokens_owed0, 0));
            let (res1: Uint256, _) = uint256_add(Uint256(position.tokens_owed1, 0), Uint256(tokens_owed1, 0));
            let position: PositionInfo = PositionInfo(
                liquidity=liquidity,
                fee_growth_inside0_x128=fee_growth_inside0_x128,
                fee_growth_inside1_x128=fee_growth_inside1_x128,
                tokens_owed0=res0.low,
                tokens_owed1=res1.low,
            );
            PositionMgr_data.write(address, tick_lower, tick_upper, position);
            return (position,);
        }

        let position: PositionInfo = PositionInfo(
            liquidity=liquidity,
            fee_growth_inside0_x128=fee_growth_inside0_x128,
            fee_growth_inside1_x128=fee_growth_inside1_x128,
            tokens_owed0=position.tokens_owed0,
            tokens_owed1=position.tokens_owed1,
        );
        PositionMgr_data.write(address, tick_lower, tick_upper, position);
        return (position,);
    }

    func get{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        address: felt, tick_lower: felt, tick_upper: felt
    ) -> (position: PositionInfo) {
        let (position: PositionInfo) = PositionMgr_data.read(address, tick_lower, tick_upper);
        return (position,);
    }

    func set{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        address: felt, tick_lower: felt, tick_upper: felt, position: PositionInfo
    ) {
        PositionMgr_data.write(address, tick_lower, tick_upper, position);
        return ();
    }
}
