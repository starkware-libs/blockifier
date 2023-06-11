%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.registers import get_label_location
from starkware.cairo.common.registers import get_fp_and_pc

from starkware.cairo.common.math import (assert_lt, assert_not_zero, assert_le)
from starkware.starknet.common.syscalls import (get_caller_address, get_contract_address)
from starkware.cairo.common.uint256 import (Uint256, uint256_lt, uint256_le, uint256_add, uint256_eq, uint256_mul, uint256_unsigned_div_rem)
from starkware.starknet.common.messages import send_message_to_l1

from contracts.l2.open_zeppelin.token.IERC20 import IERC20
from contracts.l2.open_zeppelin.utils.constants import TRUE
from contracts.l2.open_zeppelin.Ownable_base import (Ownable_initializer, Ownable_only_owner, Ownable_get_owner)

from contracts.l2.starkgate.token_bridge_interface import ITokenBridge

from contracts.l2.util.Arrays import uint256_array_sum

from contracts.l2.util.FleetManager import (
    Ship,
    ShipDetails,
    CrewMember,
    Cargo,
    RETURNED,

    FleetManager_initialise,
    FleetManager_deposit,
    FleetManager_disembark,
    FleetManager_depart,
    FleetManager_shipDetails,
    FleetManager_rideContribution,
    FleetManager_rideContributions,
    FleetManager_findShipByAmount,
    FleetManager_markReturned,
    FleetManager_finalize,
    FleetManager_updateOldestIndex,

    FleetManager_shipMetadata,
    FleetManager_openShipIndex,
    FleetManager_oldestActiveShipIdx,
    FleetManager_fleetSize,
    FleetManager_fleet
)

@storage_var
func sv_l1_contract_address() -> (address: felt):
end

@storage_var
func sv_l2_starkgate_address() -> (address: felt):
end

@storage_var
func sv_pooling_token_address() -> (address: felt):
end

@storage_var
func sv_payout_token_address() -> (address: felt):
end

@storage_var
func sv_keeper_address() -> (address: felt):
end

@storage_var
func sv_max_fleet_size() -> (max_size: felt):
end

@storage_var
func sv_min_deposit() -> (min_deposit: Uint256):
end

@storage_var
func sv_unload_batch_size() -> (batch_size: felt):
end

@event
func ev_deposited(contributor: felt, amount: Uint256):
end

@event
func ev_departed(idx: felt, crew: felt, total: Uint256):
end

@event
func ev_finalised(idx: felt):
end

@event
func ev_returned(idx: felt):
end

@event
func ev_l1_message_received(from_address: felt, cargo_len: felt, cargo: Uint256*, total_loot: Uint256, gas_used: Uint256):
end

const MESSAGE_DEPART = 0
const MESSAGE_FINALISE = 1

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
                    l2_starkgate_address: felt,
                    pooling_token_address: felt,
                    payout_token_address: felt,
                    governor_address: felt
                ):

    sv_l2_starkgate_address.write(l2_starkgate_address)
    sv_pooling_token_address.write(pooling_token_address)
    sv_payout_token_address.write(payout_token_address)
    Ownable_initializer(governor_address)

    sv_min_deposit.write(Uint256(0, 0))
    sv_keeper_address.write(governor_address)
    sv_max_fleet_size.write(20)
    sv_unload_batch_size.write(5)

    FleetManager_initialise()
    return ()
end

@external
func set_l1_conductor_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(address: felt):
    let (l1_address) = sv_l1_contract_address.read()
    assert l1_address = 0

    #Ownable_only_owner() # TODO: enable this and fix up the deployment scripts
    sv_l1_contract_address.write(address)

    return ()
end

@external
func deposit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(amount: Uint256):
    alloc_locals

    let (self) = get_contract_address()
    let (account) = get_caller_address()
    let (min_deposit) = sv_min_deposit.read()
    let (token_address) = sv_pooling_token_address.read()

    with_attr error_message("Deposit amount must be >= ${min_deposit}"):
        let (is_deposit_greater_equal_minimum) = uint256_le(min_deposit, amount)
        assert is_deposit_greater_equal_minimum = 1
    end

    # Add the deposit to internal bookkeeping
    FleetManager_deposit(account, amount)

    # Transfer tokens from sender account into L2Conductor
    IERC20.transferFrom(contract_address=token_address, sender=account, recipient=self, amount=amount)
    ev_deposited.emit(account, amount)

    return ()
end

#@external
#func collect_loot{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt):
    #alloc_locals
    #let (__fp__, _) = get_fp_and_pc()
    #let (crew_account) = get_caller_address()
    #let (ship: Ship) = FleetManager_shipMetadata(ship_idx)

    #with_attr error_message("Ship must be in returned status"):
        #assert ship.status = RETURNED
    #end

    #let (crew_cargo, was_finalised) = FleetManager_disembark(ship_idx, crew_account)

    #with_attr error_message("No loot to collect"):
        #let (has_contributed) = uint256_lt(Uint256(0,0), crew_cargo)
        #assert has_contributed = 1
    #end

    #let (local ctx: PayoutCtx) = sv_payout_ctx.read(ship_idx)
    #_transfer_loot_to_crew(crew_account, crew_cargo, &ctx)

    ##if we only had one crew then the ship was finalised and we need to clean up
    #if was_finalised == 1:
        #sv_payout_ctx.write(ship_idx, PayoutCtx(Uint256(0,0), Uint256(0,0), Uint256(0,0), 0))
        #FleetManager_updateOldestIndex()
        #ev_finalised.emit(ship_idx)
        #return ()
    #else:
        #return ()
    #end
#end

@external
func depart{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt):
    alloc_locals

    let (l1_contract_address: felt) = sv_l1_contract_address.read()
    let (l2_starkgate_address: felt) = sv_l2_starkgate_address.read()
    let (caller_address: felt) = get_caller_address()
    let (keeper: felt) = sv_keeper_address.read()
    let (open_ship_idx) = FleetManager_openShipIndex()
    let (max_fleet_size: felt) = sv_max_fleet_size.read()
    let (fleet_size: felt) = FleetManager_fleetSize()

    assert_not_zero(l1_contract_address)
    assert_not_zero(l2_starkgate_address)


    with_attr error_message("Only current ship can be departed"):
        assert open_ship_idx = ship_idx
    end

    with_attr error_message("Maximum fleet size exceeded"):
        assert_lt(fleet_size, max_fleet_size)
    end

    with_attr error_message("Ships can only be departed by active crew"):
        let (ship: Ship, contribution: CrewMember) = FleetManager_rideContribution(ship_idx, caller_address)
        let (is_caller_crew) = uint256_lt(Uint256(0, 0), contribution.cargo)

        if keeper != caller_address:
            assert is_caller_crew = 1
        end
    end

    let (ship_idx: felt, ship: Ship) = FleetManager_depart()
    ITokenBridge.initiate_withdraw(contract_address=l2_starkgate_address, l1_recipient=l1_contract_address, amount=ship.cargo)

    let (message_payload : felt*) = alloc()
    assert message_payload[0] = ship.cargo.low
    assert message_payload[1] = ship.cargo.high
    send_message_to_l1(l1_contract_address, 2, message_payload)

    ev_departed.emit(ship_idx, ship.crew, ship.cargo)

    return ()
end

struct PayoutCtx:
    member shipCargo: Uint256
    member allShipsCargo: Uint256
    member allShipsLoot: Uint256
    member loot_token_address: felt
end

@storage_var
func sv_payout_ctx(ship_idx: felt) -> (ctx: PayoutCtx):
end

# Process returns from vault and pay all contributors accordingly
# @param crew_account          Account to pay to
# @param crew_cargo     amount contributed by this account
# Formula:
#    shipCargo        crewCargo                              crewCargo * payoutAllShips
# --------------- * ------------ * payoutAllShips   ===>   ----------------------------
#  allShipsCargo      shipCargo                                     allShipsCargo
func _transfer_loot_to_crew{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(crew_account: felt, crew_cargo: Uint256, ctx: PayoutCtx*) -> ():
    alloc_locals

    let (result: Uint256, overflow: Uint256) = uint256_mul(crew_cargo, ctx.allShipsLoot)
    let (payout: Uint256, _: Uint256) = uint256_unsigned_div_rem(result, ctx.allShipsCargo)

    assert overflow = Uint256(0, 0)

    let (success) = IERC20.transfer(contract_address=ctx.loot_token_address, recipient=crew_account, amount=payout)
    assert success = TRUE
    # TODO what should we do if transfer out fails?

    return ()
end


func process_amounts{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(amount: Uint256*, end_ptr: Uint256*, total: Uint256, total_loot: Uint256) -> (res: felt):
    alloc_locals
    if amount == end_ptr:
        return (0)
    end

    let (payout_token_address: felt) = sv_payout_token_address.read()
    let (conductor_address) = get_contract_address()

    let amount_to_find: Uint256 = [amount]

    let (r, overflow) = uint256_mul(amount_to_find, total_loot)
    let (payout_share, remainder) = uint256_unsigned_div_rem(r, total)

    let (matched_ship_index) = FleetManager_findShipByAmount(amount_to_find)
    assert_lt(-1, matched_ship_index) # Assert that we found a matching ship

    let ctx: PayoutCtx = PayoutCtx(amount_to_find, total, total_loot, payout_token_address)
    sv_payout_ctx.write(matched_ship_index, ctx)

    ev_returned.emit(matched_ship_index)
    FleetManager_markReturned(matched_ship_index)

    return process_amounts(amount+Uint256.SIZE, end_ptr, total, total_loot)
end

@external
func process_msg_from_l1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(from_address: felt, ships_cargo_len: felt, ships_cargo: Uint256*, total_loot: Uint256, gas_used: Uint256):
    alloc_locals
    assert_lt(0, ships_cargo_len)
    let (l1_contract_address: felt) = sv_l1_contract_address.read()
    assert from_address = l1_contract_address

    ev_l1_message_received.emit(from_address, ships_cargo_len, ships_cargo, total_loot, gas_used)

    let (total_amount) = uint256_array_sum(ships_cargo_len, ships_cargo)

    #TODO: should we delete the below?
    # it is not necessary becasue if we get passed an array with more amounts than we have
    # the TX will fail with a "ship not found" assertion
    let (active_count) = FleetManager_fleetSize()
    assert_lt(0, active_count) # We have unfinished ships
    assert_le(ships_cargo_len, active_count) # Array is smaller or equal than number of unfinalized ships

    process_amounts(ships_cargo, ships_cargo + (ships_cargo_len * Uint256.SIZE), total_amount, total_loot)
    FleetManager_updateOldestIndex()
    return ()
end

@external
func unload_ship{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(idx: felt) -> (success: felt):
    alloc_locals
    let (ship: Ship) = FleetManager_shipMetadata(idx)
    let (batch_size) = sv_unload_batch_size.read()

    # Return if ship is not in correct status
    if ship.status != RETURNED:
        return (success=0)
    end

    let (local ctx: PayoutCtx) = sv_payout_ctx.read(idx)
    let (cb: felt*) = get_label_location(_transfer_loot_to_crew)

    let (__fp__, _) = get_fp_and_pc()
    let (was_finalised) = FleetManager_finalize(idx, batch_size, cb, &ctx)

    if was_finalised == 1:
        ev_finalised.emit(idx)
        sv_payout_ctx.write(idx, PayoutCtx(Uint256(0,0), Uint256(0,0), Uint256(0,0), 0))
        FleetManager_updateOldestIndex()
        return (success=1)
    end

    return (success=1)
end

#####################################################################
# Governance
#####################################################################

@external
func set_min_deposit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(min_deposit: Uint256) -> ():
    let (is_min_geq_zero) = uint256_le(Uint256(0, 0), min_deposit)
    assert is_min_geq_zero = 1

    Ownable_only_owner()
    return sv_min_deposit.write(min_deposit)
end

@external
func set_keeper_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(address: felt) -> ():
    Ownable_only_owner()

    sv_keeper_address.write(address)
    return ()
end

@external
func set_max_fleet_size{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(max_size: felt) -> ():
    Ownable_only_owner()

    sv_max_fleet_size.write(max_size)
    return ()
end

@external
func set_unload_batch_size{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(batch_size: felt) -> ():
    Ownable_only_owner()

    sv_unload_batch_size.write(batch_size)
    return ()
end

#####################################################################
# View functions
#####################################################################

# Field getters
@view
func get_l1_contract_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (address: felt):
    return sv_l1_contract_address.read()
end

@view
func get_l2_starkgate_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (address: felt):
    return sv_l2_starkgate_address.read()
end

@view
func get_pooling_token_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (address: felt):
    return sv_pooling_token_address.read()
end

@view
func get_payout_token_address{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (address: felt):
    return sv_payout_token_address.read()
end
# END field getters

struct Token:
    member address: felt
    member symbol: felt
    member name: felt
    member decimals: felt
end

func token_meta{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(token_address: felt) -> (token: Token):
    let (symbol)   = IERC20.symbol(contract_address=token_address)
    let (name)     = IERC20.name(contract_address=token_address)
    let (decimals) = IERC20.decimals(contract_address=token_address)

    return (Token(token_address, symbol, name, decimals))
end


@view
func get_metadata{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (cargo_token: Token, loot_token: Token, min_deposit: Uint256, max_fleet_size: felt):
    let (pooling_token_address) = sv_pooling_token_address.read()
    let (payout_token_address) = sv_payout_token_address.read()
    let (pooling_token) = token_meta(pooling_token_address)
    let (payout_token) = token_meta(payout_token_address)
    let (min_deposit) = sv_min_deposit.read()
    let (max_fleet_size) = sv_max_fleet_size.read()

    return (pooling_token, payout_token, min_deposit, max_fleet_size)
end

@view
func get_balances{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(account: felt) -> (cargo_token_balance: Uint256, loot_token_balance: Uint256, cargo_len: felt, cargo: Cargo*):
    alloc_locals
    let (pooling_token_address) = sv_pooling_token_address.read()
    let (payout_token_address) = sv_payout_token_address.read()

    let (pooling_token_balance) = IERC20.balanceOf(contract_address=pooling_token_address, account=account)
    let (payout_token_balance) = IERC20.balanceOf(contract_address=payout_token_address, account=account)

    let (balances_len, balances) = FleetManager_rideContributions(account)

    return (pooling_token_balance, payout_token_balance, balances_len, balances)
end

@view
func get_ship{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (ship: Ship, contribution: CrewMember):
    let (account: felt) = get_caller_address()
    let (ship_idx: felt) = FleetManager_openShipIndex()

    return FleetManager_rideContribution(ship_idx, account)
end

@view
func get_ship_status{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt) -> (ship_idx: felt, ship_cargo: Uint256, status: felt, crew_len: felt, crew: CrewMember*):
    let (details: ShipDetails) = FleetManager_shipDetails(ship_idx)
    let (ctx: PayoutCtx) = sv_payout_ctx.read(ship_idx)

    return (details.idx, details.cargo, details.status, details.crew_len, details.crew)
end

@view
func get_open_ship_status{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (ship_idx: felt, ship_cargo: Uint256, status: felt, crew_len: felt, crew: CrewMember*):
    let (open_ship_idx: felt) = FleetManager_openShipIndex()
    return get_ship_status(open_ship_idx)
end

@view
func get_oldest_active_ship_idx{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (ship_idx: felt):
    return FleetManager_oldestActiveShipIdx()
end

@view
func get_fleet_size{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (count: felt):
    return FleetManager_fleetSize()
end

@view
func get_fleet{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (start_idx: felt, ships_len: felt, ships: Ship*):
    return FleetManager_fleet()
end

