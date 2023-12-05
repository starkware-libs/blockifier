// A dummy account contract without validations that require many cairo steps.

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import call_contract

@storage_var
    func ctor_arg() -> (arg: felt) {
}

const GRIND_DEPTH = 10000000;

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    grind_on_deploy: felt,
    arg: felt,
) {
    ctor_arg.write(arg);
    return ();
}

func grind() {
    return grind_recurse(depth=GRIND_DEPTH);
}

func grind_recurse(depth: felt) {
    if (depth == 0) {
        return ();
    }
    return grind_recurse(depth=depth - 1);
}

@external
func __validate_declare__(class_hash: felt) {
    grind();
    return ();
}

@external
func __validate_deploy__(
    class_hash: felt, contract_address_salt: felt, grind_on_deploy: felt, arg: felt
) {
    if (grind_on_deploy != 0) {
        grind();
    }
    return ();
}

@external
func __validate__(contract_address, selector: felt, calldata_len: felt, calldata: felt*) {
    grind();
    return ();
}

@external
@raw_output
func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    contract_address, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = call_contract(
        contract_address=contract_address,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}
