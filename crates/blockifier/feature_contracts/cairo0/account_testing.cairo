// A dummy account contract with logic inside validations.

%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    TxInfo,
    storage_read,
    storage_write,
    call_contract,
    get_block_number,
    get_block_timestamp,
    get_sequencer_address,
    get_tx_info
)

// Run the validate method, no writes inside validation.
const VALID_WITHOUT_WRITE = 0;
// Run the validate method and write to storage inside validation.
const VALID_WITH_WRITE = 1;

@external
func __validate_declare__{syscall_ptr: felt*}(class_hash: felt) {
    return ();
}

@external
func __validate_deploy__{syscall_ptr: felt*}(
    class_hash: felt, contract_address_salt: felt, validate_constructor: felt
) {
    return ();
}

@external
func __validate__{syscall_ptr: felt*}(
    contract_address: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    validate_functionality();
    return ();
}

@external
func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_address: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    execute_functionality();
    return ();
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    validate_constructor: felt
) {
    return ();
}

func validate_functionality{syscall_ptr: felt*}() {
    let (tx_info: TxInfo*) = get_tx_info();
    // Functionality of validation according to the scenario.
    let scenario = tx_info.signature[0];

    if (scenario == VALID_WITHOUT_WRITE) {
        return ();
    }

    if (scenario == VALID_WITH_WRITE) {
        let storage_ptr = tx_info.signature[1];
        let storage_value = tx_info.signature[2];
        storage_write(address=storage_ptr, value=storage_value);
        return ();
    }
    // Unknown scenario.
    return();
}

func execute_functionality{syscall_ptr: felt*}() {
    let (tx_info: TxInfo*) = get_tx_info();
    // Functionality of execution according to the scenario.
    let scenario = tx_info.signature[0];

    if (scenario == VALID_WITHOUT_WRITE) {
        return ();
    }

    if (scenario == VALID_WITH_WRITE) {
        let storage_ptr = tx_info.signature[3];
        let storage_value = tx_info.signature[4];
        storage_write(address=storage_ptr, value=storage_value);
        return ();
    }
    
    // Unknown scenario.
    return ();
}