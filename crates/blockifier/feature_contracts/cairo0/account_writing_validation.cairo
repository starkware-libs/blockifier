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

// Run the validate method, no writes inside validation or execution.
const NO_WRITES = 0;
// Run the validate method, no writes inside validation, writes inside execution.
const WRITE_EXECUTE_ONLY = 1;
// Run the validate method and write to storage inside validation and execution.
const WRITE_VALIDATE_EXECUTE = 2;
// Run the validate method and write to storage only inside validation, no writes inside execution.
const WRITE_VALIDATE_ONLY = 3;

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
    validate();
    return ();
}

@external
func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_address: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    execute();
    return ();
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    validate_constructor: felt
) {
    return ();
}

func validate{syscall_ptr: felt*}() {
    let (tx_info: TxInfo*) = get_tx_info();
    // Functionality of validation according to the scenario.
    let scenario = tx_info.signature[0];

    if (scenario == NO_WRITES) {
        return ();
    }
    if (scenario == WRITE_EXECUTE_ONLY) {
        return ();
    }
    if (scenario == WRITE_VALIDATE_ONLY) {
        // First write to storage.
        storage_write(address=tx_info.signature[1], value=tx_info.signature[2]);
        // Second write to storage.
        storage_write(address=tx_info.signature[3], value=tx_info.signature[4]);
        return ();
    }
    if (scenario == WRITE_VALIDATE_EXECUTE) {
        storage_write(address=tx_info.signature[1], value=tx_info.signature[2]);
        return ();
    }
    // Unknown scenario.
    return();
}

func execute{syscall_ptr: felt*}() {
    let (tx_info: TxInfo*) = get_tx_info();
    // Functionality of execution according to the scenario.
    let scenario = tx_info.signature[0];

    if (scenario == NO_WRITES) {
        return ();
    }
    if (scenario == WRITE_VALIDATE_ONLY) {
        return ();
    }
    if (scenario == WRITE_EXECUTE_ONLY) {
        // First write to storage.
        storage_write(address=tx_info.signature[1], value=tx_info.signature[2]);
        // Second write to storage.
        storage_write(address=tx_info.signature[3], value=tx_info.signature[4]);
        return ();
    }
    if (scenario == WRITE_VALIDATE_EXECUTE) {
        storage_write(address=tx_info.signature[3], value=tx_info.signature[4]);
        return ();
    }
    // Unknown scenario.
    return ();
}
