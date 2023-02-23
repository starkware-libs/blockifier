// The fee token contract used in tests; allow easy initialization using a single DeployAccount
// transaction; also serves as a faucet account.

%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.starknet.common.syscalls import get_contract_address
from starkware.starknet.core.test_contract.dummy_account import (
    __execute__,
    __validate__,
    __validate_declare__,
    __validate_deploy__,
    deploy_contract,
)
from starkware.starknet.std_contracts.ERC20.ERC20 import initialize, permissionedMint, transfer
from starkware.starknet.std_contracts.ERC20.ERC20_base import ERC20_mint, balanceOf, name

const AMOUNT_TO_MINT = 2 ** 127;

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (self_address: felt) = get_contract_address();
    let (init_vector: felt*) = alloc();

    // Name.
    assert init_vector[0] = 'Wrapped Ether';
    // Symbol.
    assert init_vector[1] = 'WETH';
    // Decimals.
    assert init_vector[2] = 18;
    // Minter address.
    assert init_vector[3] = self_address;

    initialize(init_vector_len=4, init_vector=init_vector);
    ERC20_mint(recipient=self_address, amount=Uint256(low=AMOUNT_TO_MINT, high=0));
    return ();
}
