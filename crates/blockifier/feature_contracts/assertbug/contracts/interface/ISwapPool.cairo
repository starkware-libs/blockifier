%lang starknet

from starkware.cairo.common.uint256 import Uint256

from contracts.position_mgr import PositionInfo

@contract_interface
namespace ISwapPool {

    // view

    func get_cur_slot() -> (sqrt_price_x96: Uint256, tick: felt) {
    }

    func get_position(owner: felt, tick_lower: felt, tick_upper: felt) -> (position: PositionInfo) {
    }

    func get_swap_results(
        zero_for_one: felt,
        amount_specified: Uint256, // int256
        sqrt_price_limit_x96: Uint256 // uint160
    ) -> (amount0: Uint256, amount1: Uint256) {
    }

    func get_position_token_fee(
        tick_lower: felt,
        tick_upper: felt,
    ) -> (token0_fee: Uint256, token1_fee: Uint256) {
    }

    // external

    func initializer(
        tick_spacing: felt, 
        fee: felt, 
        token_a: felt, 
        token_b: felt, 
        owner: felt 
    ) {
    }

    func initialize_price(sqrt_price_x96: Uint256) {
    }

    func add_liquidity(recipient: felt, tick_lower: felt, tick_upper: felt, liquidity: felt, data: felt) -> (
        amount0: Uint256, amount1: Uint256
    ) {
    }

    func remove_liquidity(tick_lower: felt, tick_upper: felt, liquidity: felt) -> (
        amount0: Uint256, amount1: Uint256
    ) {
    }

    func swap(
        recipient: felt,
        zero_for_one: felt,
        amount_specified: Uint256, // int256
        sqrt_price_limit_x96: Uint256, // uint160
        sender: felt,
        data_len: felt,
        data: felt*
    ) -> (amount0: Uint256, amount1: Uint256) {
    }

    func collect(
        recipient: felt,
        tick_lower: felt,
        tick_upper: felt,
        amount0_requested: felt,
        amount1_requested: felt,
    ) -> (amount0: felt, amount1: felt) {
    }

    func collect_protocol(recipient: felt, amount0_requested: felt, amount1_requested: felt) -> (
        amount0: felt, amount1: felt
    ) {
    }

    func set_fee_protocol(fee_protocol0: felt, fee_protocol1: felt) {
    }

    func upgrade(new_implementation: felt) {
    }
}
