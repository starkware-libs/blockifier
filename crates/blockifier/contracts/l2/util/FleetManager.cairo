%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.invoke import invoke

from starkware.cairo.common.math import (assert_le, assert_lt, assert_nn, assert_not_equal)
from starkware.cairo.common.math_cmp import is_le
from starkware.starknet.common.syscalls import (get_caller_address, get_contract_address)
from starkware.cairo.common.uint256 import (Uint256, uint256_lt, uint256_add, uint256_sub, uint256_eq)

from contracts.l2.open_zeppelin.utils.constants import (TRUE, FALSE)


# Status values for Ships
const FINALISED        = 0
const OPEN             = 1
const AT_SEA           = 2
const RETURNED         = 3

struct Ship:
    member cargo: Uint256
    member crew: felt
    member status: felt
end

struct Crew:
    member idx: felt
    member cargo: Uint256
end


@storage_var
func sv_open_ship_idx() -> (ship_idx: felt):
end

@storage_var
func sv_oldest_active_ship_idx() -> (ship_idx: felt):
end

@storage_var
func sv_fleet(ship_idx: felt) -> (ship: Ship):
end

@storage_var
func sv_crew_cargo(ship_idx: felt, account: felt) -> (crew: Crew):
end

@storage_var
func sv_crew_list(ship_idx: felt, crew_idx: felt) -> (account: felt):
end

func FleetManager_initialise{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    sv_open_ship_idx.write(1)
    sv_oldest_active_ship_idx.write(1)
    sv_fleet.write(1, Ship(Uint256(0, 0), 0, OPEN))

    return ()
end

func FleetManager_depart{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (idx: felt, res: Ship):

    let (ship_idx: felt) = sv_open_ship_idx.read()
    let (ship: Ship) = sv_fleet.read(ship_idx)

    let next_idx = ship_idx + 1
    sv_open_ship_idx.write( next_idx  )

    sv_fleet.write( ship_idx, Ship(ship.cargo, ship.crew, AT_SEA))
    sv_fleet.write( next_idx, Ship(Uint256(0, 0), 0, OPEN) )

    return (ship_idx, ship)
end

func FleetManager_deposit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(account: felt, amount: Uint256):
    alloc_locals

    let (local ship_idx: felt) = sv_open_ship_idx.read()
    let (ship: Ship) = sv_fleet.read(ship_idx)
    let (crew: Crew) = sv_crew_cargo.read(ship_idx, account) #defaults to Crew(0, 0)

    with_attr error_message("Deposit must be > 0"):
        let (is_deposit_greater_zero) = uint256_lt(Uint256(0, 0), amount)
        assert is_deposit_greater_zero = 1
    end

    #Update contribution for this account to active ship
    let (new_contribution: Uint256, is_overflow) = uint256_add(crew.cargo, amount)
    assert (is_overflow) = 0

    let (cargo: Uint256, is_overflow) = uint256_add(ship.cargo, amount)
    assert (is_overflow) = 0

    let (is_first_contribution) = uint256_eq(Uint256(0,0), crew.cargo)
    if is_first_contribution == 1:
        # account has not yet contributed to this ship. Add them to bookkeeping
        sv_crew_list.write(ship_idx=ship_idx, crew_idx=ship.crew, value=account)
        sv_crew_cargo.write(ship_idx, account, Crew(ship.crew, new_contribution))
        sv_fleet.write(ship_idx, Ship(cargo, ship.crew+1, ship.status))
        return ()
    end

    sv_crew_cargo.write(ship_idx, account, Crew(crew.idx, new_contribution))
    sv_fleet.write(ship_idx, Ship(cargo, ship.crew, ship.status))
    return ()
end

func FleetManager_disembark{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt, account: felt) -> (crew_cargo: Uint256, was_finalised: felt):
    alloc_locals

    let (ship: Ship) = sv_fleet.read(ship_idx)

    with_attr error_message("Can't disembark ships at sea"):
        if ship.status == AT_SEA:
            assert 1 = 0
        end
    end

    let (crew: Crew) = sv_crew_cargo.read(ship_idx, account) #defaults to Crew(0, 0)

    let (has_contributed) = uint256_eq(Uint256(0,0), crew.cargo)
    if has_contributed == 1:

        if ship.crew - 1 == 0:
            #Ship is now empty, finalise it
            sv_crew_list.write(ship_idx, ship.crew - 1, 0)
            sv_crew_cargo.write(ship_idx, account, Crew(0, Uint256(0, 0)))

            if ship.status == OPEN:
                #Don't finalise open ship
                return (crew.cargo, 0)
            else:
                sv_fleet.write(ship_idx, Ship(Uint256(0,0), 0, FINALISED))
                return (crew.cargo, 1)
            end

        else:
            #Ship is not yet empty, replace crew slot with last crew
            let (last_crew_account) = sv_crew_list.read(ship_idx, ship.crew - 1)

            sv_crew_list.write(ship_idx, crew.idx, last_crew_account)
            sv_fleet.write(ship_idx, Ship(ship.cargo, ship.crew - 1, ship.status))

            sv_crew_list.write(ship_idx, ship.crew - 1, 0)

            sv_crew_cargo.write(ship_idx, account, Crew(0, Uint256(0, 0)))
            return (crew.cargo, 0)
        end
    end

    return (Uint256(0, 0), 0)
end

struct CrewMember:
    member account: felt
    member cargo: Uint256
end

struct ShipDetails:
    member idx: felt
    member cargo: Uint256
    member status: felt
    member crew_len: felt
    member crew: CrewMember*
end


func _collect_contributions{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt, next_crew: felt, remaining_crew: felt, contributions: CrewMember*):
    if remaining_crew == 0:
        return()
    end

    let (crew_account) = sv_crew_list.read(ship_idx, next_crew)
    let (crew: Crew) = sv_crew_cargo.read(ship_idx, crew_account)

    assert contributions[next_crew] = CrewMember(crew_account, crew.cargo)

    return _collect_contributions(ship_idx, next_crew+1, remaining_crew-1, contributions)
end

func FleetManager_shipDetails{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(idx: felt) -> (res: ShipDetails):
    alloc_locals
    let (local ship: Ship) = sv_fleet.read(idx)
    let (local contributions: CrewMember*) = alloc()

    _collect_contributions(idx, 0, ship.crew, contributions)

    let details: ShipDetails = ShipDetails(idx, ship.cargo, ship.status, ship.crew, contributions)
    return  (details)
end

func FleetManager_rideContribution{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt, account: felt) -> (ship: Ship, contribution: CrewMember):
    let (ship: Ship) = sv_fleet.read(ship_idx)
    let (crew: Crew) = sv_crew_cargo.read(ship_idx, account)

    return (ship, CrewMember(account, crew.cargo))
end

struct Cargo:
    member ship_idx: felt
    member amount: Uint256
end

func _account_balances{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(account: felt, balances: Cargo*, ship_idx: felt, last_idx: felt) -> (count: felt):
    alloc_locals
    if ship_idx == last_idx + 1:
        return (0)
    end

    let (contributions_count: felt) = _account_balances(account, balances, ship_idx + 1, last_idx)

    let (crew: Crew) = sv_crew_cargo.read(ship_idx, account)
    let (has_contributed: felt) = uint256_lt(Uint256(0, 0), crew.cargo)

    if has_contributed == 1:
        assert balances[contributions_count] = Cargo(ship_idx, crew.cargo)
        return (contributions_count + 1)
    else:
        return (contributions_count)
    end
end


func FleetManager_rideContributions{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(account: felt) -> (balances_len: felt, balances: Cargo*):
    alloc_locals
    let (start: felt) = sv_oldest_active_ship_idx.read()
    let (ship_idx: felt) = sv_open_ship_idx.read()
    let (local balances: Cargo*) = alloc()

    let (count: felt) = _account_balances(account, balances, start, ship_idx)

    return (count, balances)
end


# This function finds the oldest active ship that matches the specified amount
func _find_ship_by_amount{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(current_index: felt, num_to_check: felt, amount: Uint256) -> (res: felt):
    alloc_locals
    if num_to_check == 0:
        return (-1)
    end

    let (ship: Ship) = sv_fleet.read(current_index)
    let (is_eq) = uint256_eq(ship.cargo, amount)

    if ship.status == AT_SEA:
        if is_eq == TRUE:
            return (current_index)
        end
    end

    return _find_ship_by_amount(current_index+1, num_to_check-1, amount)
end

# Find the oldest active ship by matching the total amount to the given parameter
# @returns -1 if no match found
# @returns >0 index of ship that matched
func FleetManager_findShipByAmount{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(amount: Uint256) -> (res: felt):
    let (oldest_active_ship_idx) = sv_oldest_active_ship_idx.read()
    let (ship_idx) = sv_open_ship_idx.read()

    return _find_ship_by_amount(oldest_active_ship_idx, ship_idx - oldest_active_ship_idx, amount)
end


########### Finalisation
func _finalize_crew{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt, crew_count: felt, stop_crew_count: felt, callback: felt*, ctx: felt*) -> (finalised_cargo: Uint256):
    alloc_locals
    if crew_count == stop_crew_count:
        return (Uint256(0,0))
    end

    let contributor_idx = crew_count - 1

    let (local crew_account) = sv_crew_list.read(ship_idx, contributor_idx)
    let (crew: Crew) = sv_crew_cargo.read(ship_idx, crew_account)

    [ap] = syscall_ptr; ap++
    [ap] = pedersen_ptr; ap++
    [ap] = range_check_ptr; ap++
    [ap] = crew_account; ap++
    [ap] = crew.cargo.low; ap++
    [ap] = crew.cargo.high; ap++
    [ap] = ctx; ap++

    call abs callback

    let syscall_ptr = cast([ap-3], felt*)
    let pedersen_ptr = cast([ap-2], HashBuiltin*)
    let range_check_ptr = [ap-1]

    sv_crew_list.write(ship_idx, contributor_idx, 0)
    sv_crew_cargo.write(ship_idx, crew_account, Crew(0, Uint256(0,0)))

    let (accumulator) = _finalize_crew(ship_idx, contributor_idx, stop_crew_count, callback, ctx)
    let (finalised_cargo, _) = uint256_add(crew.cargo, accumulator)
    return (finalised_cargo)
end

func FleetManager_finalize{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt, batch_size: felt, cb: felt*, ctx: felt*) -> (finalised: felt):
    alloc_locals
    let (ship) = sv_fleet.read(ship_idx)
    let (disembark_all_users) = is_le(ship.crew, batch_size)
    # TODO: do we need to assert ship exists?

    if disembark_all_users == 1:
        let (finalised_cargo) = _finalize_crew(ship_idx, ship.crew, 0, cb, ctx)
        sv_fleet.write(ship_idx, Ship(Uint256(0,0), 0, FINALISED))

        # TODO: this is for sequential finalisation, we also do an update outside
        # check what we want to do and keep only one?
        let (oldest_idx) = sv_oldest_active_ship_idx.read()
        if ship_idx == oldest_idx:
            sv_oldest_active_ship_idx.write(ship_idx + 1)
            return (1)
        else:
            return (1)
        end
    else:
        let (finalised_cargo) = _finalize_crew(ship_idx, ship.crew, ship.crew - batch_size, cb, ctx)
        let (cargo_remaining) = uint256_sub(ship.cargo, finalised_cargo)
        sv_fleet.write(ship_idx, Ship(cargo_remaining, ship.crew - batch_size, ship.status))
        return (0)
    end

end

func FleetManager_shipMetadata{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(idx: felt) -> (ship: Ship):
    let (ship: Ship) = sv_fleet.read(idx)

    # fail if ship was finalized or doesn't yet exist
    assert_lt(0, ship.status)

    return (ship)
end

func _find_new_oldest_active_ship_idx{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(idx: felt) -> (idx: felt):
    let (ship: Ship) = sv_fleet.read(idx)
    if ship.status == FINALISED:
        return _find_new_oldest_active_ship_idx(idx+1)
    else:
        return (idx)
    end
end

func FleetManager_updateOldestIndex{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}():
    let (idx) = sv_oldest_active_ship_idx.read()

    let (updated_oldest_index) = _find_new_oldest_active_ship_idx(idx)

    #it should not be possible to run past the next ship
    let (next_idx) = sv_open_ship_idx.read()
    assert_le(updated_oldest_index, next_idx)

    sv_oldest_active_ship_idx.write(updated_oldest_index)
    return ()
end


#Flat a ship as pending finalisation. This makes the ship eligible for finalisation by users
#@param ship_idx: Index of the ship to be flagged
func FleetManager_markReturned{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(ship_idx: felt):
    let (ship) = sv_fleet.read(ship_idx)
    sv_fleet.write(ship_idx, Ship(ship.cargo, ship.crew, RETURNED) )

    return ()
end

#Get the index/timestamp of the ship that is currently taking deposits will be departing next
# @return ship_idx: Index of ship that will depart next
func FleetManager_openShipIndex{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (ship_idx: felt):
    return sv_open_ship_idx.read()
end

#Get the index/timestamp of the ship that is currently taking deposits will be departing next
# @return ship_idx: Index of ship that will depart next
func FleetManager_oldestActiveShipIdx{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (ship_idx: felt):
    return sv_oldest_active_ship_idx.read()
end


# Count all ships in given status in the range [from, to)
#
# @param wanted_status: status to count
# @param start_idx:  index to start from, inclusive
# @param end_idx:    index to end at, exclusive
#
func _count_ships{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(wanted_status: felt, start_idx: felt, end_idx: felt) -> (count: felt):
    if start_idx == end_idx:
        return (0)
    end

    let (ship: Ship) = sv_fleet.read(start_idx)
    if ship.status == wanted_status:
        let (r) = _count_ships(wanted_status, start_idx+1, end_idx)
        return (1 + r)
    end

    return _count_ships(wanted_status, start_idx+1, end_idx)
end

# Get the count of active ships
func FleetManager_fleetSize{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (count: felt):
    let (oldest_active_ship_idx) = sv_oldest_active_ship_idx.read()
    let (next_ship_idx) = sv_open_ship_idx.read()

    assert_le(oldest_active_ship_idx, next_ship_idx)
    return _count_ships(AT_SEA, oldest_active_ship_idx, next_ship_idx)
end

func _collect_ships{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(start_idx: felt, end_idx: felt, i: felt, ships: Ship*) -> (count: felt):

    let (ship: Ship) = sv_fleet.read(start_idx + i)
    assert ships[i] = ship

    if (start_idx + i) == end_idx:
        return (1)
    end

    let (r) = _collect_ships(start_idx, end_idx, i+1, ships)
    return (r + 1)
end

# Collect all ships in the fleet metadata into an array of Ship
func FleetManager_fleet{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (start_idx: felt, ships_len: felt, ships: Ship*):
    alloc_locals
    let (local ships: Ship*) = alloc()

    let (oldest_active_ship_idx) = sv_oldest_active_ship_idx.read()
    let (next_ship_idx) = sv_open_ship_idx.read()

    assert_le(oldest_active_ship_idx, next_ship_idx)
    let (count) = _collect_ships(oldest_active_ship_idx, next_ship_idx, 0, ships)
    return (oldest_active_ship_idx, count, ships)
end





