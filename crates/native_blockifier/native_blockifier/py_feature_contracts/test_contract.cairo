%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bitwise import bitwise_xor
from starkware.cairo.common.bool import FALSE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, EcOpBuiltin, HashBuiltin
from starkware.cairo.common.ec import ec_op
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.starknet.common.messages import send_message_to_l1
from starkware.starknet.common.syscalls import (
    TxInfo,
    call_contract,
    deploy,
    emit_event,
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_contract_address,
    get_sequencer_address,
    get_tx_info,
    get_tx_signature,
    library_call,
    library_call_l1_handler,
    replace_class,
    storage_read,
    storage_write,
)
from starkware.starknet.core.os.constants import TRANSACTION_VERSION
from starkware.starknet.core.test_contract.deprecated_syscalls import delegate_call
from starkware.starknet.core.test_contract.test_contract_interface import StorageCell, TestContract

@storage_var
func two_counters(index: felt) -> (res: (felt, felt)) {
}

@storage_var
func impl_address() -> (address: felt) {
}

// Advances the 'two_counters' storage variable by 'diff'.
@external
func advance_counter{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt, diffs_len: felt, diffs: felt*
) {
    assert diffs_len = 2;
    let (val) = two_counters.read(index);
    two_counters.write(index, (val[0] + diffs[0], val[1] + diffs[1]));
    return ();
}

struct IndexAndValues {
    index: felt,
    values: (x: felt, y: felt),
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    address: felt, value: felt
) {
    storage_write(address=address, value=value);
    return ();
}

@external
func xor_counters{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(index_and_x: IndexAndValues) {
    let index = index_and_x.index;
    let x0 = index_and_x.values[0];
    let x1 = index_and_x.values[1];
    let (val) = two_counters.read(index);
    let (res0) = bitwise_xor(val[0], x0);
    let (res1) = bitwise_xor(val[1], x1);
    two_counters.write(index, (res0, res1));
    return ();
}

@external
func foo() -> (res: felt) {
    return (res=123);
}

@storage_var
func ec_point() -> (res: EcPoint) {
}

@external
func test_ec_op{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, ec_op_ptr: EcOpBuiltin*
}() {
    let p = EcPoint(
        0x654fd7e67a123dd13868093b3b7777f1ffef596c2e324f25ceaf9146698482c,
        0x4fad269cbf860980e38768fe9cb6b0b9ab03ee3fe84cfde2eccce597c874fd8,
    );
    let q = EcPoint(
        0x3dbce56de34e1cfe252ead5a1f14fd261d520d343ff6b7652174e62976ef44d,
        0x4b5810004d9272776dec83ecc20c19353453b956e594188890b48467cb53c19,
    );
    let m = 0x6d232c016ef1b12aec4b7f88cc0b3ab662be3b7dd7adbce5209fcfdbd42a504;
    let (res) = ec_op(p=p, m=m, q=q);
    ec_point.write(res);
    return ();
}

@contract_interface
namespace MyContract {
    func xor_counters(index_and_x: IndexAndValues) {
    }
    func foo() -> (res: felt) {
    }
}

@external
func call_xor_counters{syscall_ptr: felt*, range_check_ptr}(
    address: felt, index_and_x: IndexAndValues
) {
    MyContract.xor_counters(address, index_and_x);
    return ();
}

@external
func add_signature_to_counters{pedersen_ptr: HashBuiltin*, range_check_ptr, syscall_ptr: felt*}(
    index: felt
) {
    let (signature_len: felt, signature: felt*) = get_tx_signature();
    assert signature_len = 2;
    let (val) = two_counters.read(index);
    two_counters.write(index, (val[0] + signature[0], val[1] + signature[1]));
    return ();
}

@external
func set_value{syscall_ptr: felt*}(address: felt, value: felt) {
    return storage_write(address=address, value=value);
}

@external
func get_value{syscall_ptr: felt*}(address: felt) -> (res: felt) {
    let (value) = storage_read(address=address);
    return (res=value);
}

@external
func entry_point{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*}() {
    const address = 15;

    let (value) = storage_read(address=address);
    storage_write(address=address, value=value + 1);
    let (new_value) = storage_read(address=address);

    assert new_value = value + 1;
    return ();
}

@external
func test_builtins{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (result: felt) {
    assert_nn_le(17, 85);
    let (result) = hash2{hash_ptr=pedersen_ptr}(x=1, y=2);
    assert result = 2592987851775965742543459319508348457290966253241455514226127639100457844774;
    return (result=result);
}

@external
func send_message{syscall_ptr: felt*}(to_address: felt) {
    alloc_locals;
    local payload: (felt, felt) = (12, 34);
    let (__fp__, _) = get_fp_and_pc();
    send_message_to_l1(to_address=to_address, payload_size=2, payload=cast(&payload, felt*));
    return ();
}

@external
func test_emit_event{syscall_ptr: felt*}(keys_len: felt, keys: felt*, data_len: felt, data: felt*) {
    emit_event(keys_len=keys_len, keys=keys, data_len=data_len, data=data);
    return ();
}

@event
func log_storage_cells(storage_cells_len: felt, storage_cells: StorageCell*) {
}

@external
func test_high_level_event{syscall_ptr: felt*, range_check_ptr}(
    storage_cells_len: felt, storage_cells: StorageCell*
) {
    log_storage_cells.emit(storage_cells_len=storage_cells_len, storage_cells=storage_cells);
    return ();
}

@external
func test_call_contract{syscall_ptr: felt*}(
    contract_address: felt, function_selector, calldata_len, calldata: felt*
) {
    call_contract(
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return ();
}

@external
func test_deploy{syscall_ptr: felt*}(
    class_hash: felt,
    contract_address_salt: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*,
) -> (contract_address: felt) {
    let (contract_address) = deploy(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deploy_from_zero=FALSE,
    );
    return (contract_address=contract_address);
}

// This function is designed to deploy test_contract.cairo and call it.
// The param class_hash is expected to be the hash of this contract.
@external
func test_deploy_and_call{syscall_ptr: felt*, range_check_ptr}(
    class_hash: felt,
    contract_address_salt: felt,
    deploy_from_zero: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*,
    key: felt,
    value: felt,
) -> (contract_address: felt) {
    let (contract_address) = deploy(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deploy_from_zero=deploy_from_zero,
    );
    TestContract.set_value(contract_address=contract_address, address=key, value=value);
    return (contract_address=contract_address);
}

@l1_handler
func deposit{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    from_address: felt, amount: felt
) {
    let (diffs: felt*) = alloc();
    assert (diffs[0], diffs[1]) = (amount, 0);
    advance_counter(index=from_address, diffs_len=2, diffs=diffs);
    return ();
}

@external
func test_get_caller_address{syscall_ptr: felt*}(expected_address: felt) {
    let (caller_address) = get_caller_address();
    assert caller_address = expected_address;
    return ();
}

@external
func test_get_sequencer_address{syscall_ptr: felt*}(expected_address: felt) {
    let (sequencer_address) = get_sequencer_address();
    assert sequencer_address = expected_address;
    return ();
}

@external
func test_get_block_timestamp{syscall_ptr: felt*}(expected_timestamp: felt) {
    let (block_timestamp) = get_block_timestamp();
    assert block_timestamp = expected_timestamp;
    return ();
}

@external
func test_get_contract_address{syscall_ptr: felt*}(expected_address: felt) {
    let (contract_address) = get_contract_address();
    assert contract_address = expected_address;
    return ();
}

@external
func test_get_block_number{syscall_ptr: felt*}(expected_block_number: felt) {
    let (block_number) = get_block_number();
    assert block_number = expected_block_number;
    return ();
}

@external
func test_call_storage_consistency{syscall_ptr: felt*, range_check_ptr}(
    other_contract_address: felt, address: felt
) {
    // Set 1991 to the given address in this contract.
    set_value(address=address, value=1991);

    // Set 2021 to the given address in the other contract.
    TestContract.set_value(contract_address=other_contract_address, address=address, value=2021);

    // Verify that this contract's storage did not change.
    let (value) = get_value(address=address);
    assert value = 1991;

    let (other_value) = TestContract.get_value(
        contract_address=other_contract_address, address=address
    );
    assert other_value = 2021;

    return ();
}

@external
func test_re_entrance{syscall_ptr: felt*, range_check_ptr}(
    other_contract_address: felt, depth: felt
) {
    // Reset storage at address 5.
    set_value(address=5, value=100);

    // Call add_value on a different contract address.
    TestContract.add_value(contract_address=other_contract_address, value=depth);

    // Check calculation result.
    let (final_value) = get_value(address=5);
    assert final_value = 100 + depth;

    // Check that the dummy value was written to the correct storage.
    let (dummy_value) = TestContract.get_value(contract_address=other_contract_address, address=5);
    assert dummy_value = 555 * depth;
    return ();
}

// This function changes the caller storage, thus cannot be called directly as a main transaction.
@external
func add_value{syscall_ptr: felt*, range_check_ptr}(value: felt) {
    let (caller_address) = get_caller_address();
    assert_not_zero(caller_address);

    // Call recursive_add_value on the caller contract.
    TestContract.recursive_add_value(
        contract_address=caller_address, self_address=caller_address, value=value
    );

    // Add noise to the call: write dummy value to self storage;
    // This should not affect the caller storage.
    set_value(address=5, value=555 * value);
    return ();
}

@external
func recursive_add_value{syscall_ptr: felt*, range_check_ptr}(self_address: felt, value: felt) {
    if (value == 0) {
        return ();
    }

    increase_value(address=5);

    // Call recursive_add_value with the same contract address.
    TestContract.recursive_add_value(
        contract_address=self_address, self_address=self_address, value=value - 1
    );

    // Send message: put the current call height (distance from the deepest call) as to_address,
    // for messages order checks. We should see [1, 2, ... ,depth].
    send_message(to_address=value);
    return ();
}

@external
func increase_value{syscall_ptr: felt*}(address: felt) {
    let (prev_value) = storage_read(address=address);
    storage_write(address, value=prev_value + 1);
    return ();
}

@external
func test_call_with_array{syscall_ptr: felt*, range_check_ptr}(
    self_address, arr_len: felt, arr: felt*
) {
    if (arr_len == 0) {
        return ();
    }
    TestContract.test_call_with_array(
        contract_address=self_address, self_address=self_address, arr_len=arr_len - 1, arr=arr
    );
    return ();
}

@external
func test_call_with_struct_array{syscall_ptr: felt*, range_check_ptr}(
    self_address, arr_len: felt, arr: StorageCell*
) {
    if (arr_len == 0) {
        return ();
    }

    set_value(address=arr.key, value=arr.value);

    TestContract.test_call_with_struct_array(
        contract_address=self_address,
        self_address=self_address,
        arr_len=arr_len - 1,
        arr=arr + StorageCell.SIZE,
    );
    return ();
}

@external
func test_library_call_syntactic_sugar{syscall_ptr: felt*, range_check_ptr}(class_hash: felt) {
    // Set value in this contract context.
    set_value(address=444, value=555);
    let (value) = storage_read(address=444);
    assert value = 555;

    // Set value in this contract context using library call.
    TestContract.library_call_set_value(class_hash=class_hash, address=444, value=666);
    let (value) = storage_read(address=444);
    assert value = 666;

    return ();
}

@external
func test_get_tx_info{syscall_ptr: felt*, range_check_ptr}(expected_account_contract_address) {
    let (tx_info_ptr: TxInfo*) = get_tx_info();
    // Copy tx_info fields to make sure they were assigned a value during the system call.
    tempvar tx_info = [tx_info_ptr];
    tempvar signature0 = tx_info.signature[0];

    assert tx_info.version = TRANSACTION_VERSION;
    assert tx_info.account_contract_address = expected_account_contract_address;
    assert tx_info.max_fee = 2 ** 100;
    assert tx_info.signature_len = 1;
    assert signature0 = 100;

    storage_write(address=300, value=tx_info.transaction_hash);
    storage_write(address=311, value=tx_info.chain_id);
    storage_write(address=322, value=tx_info.nonce);

    return ();
}

@external
func test_tx_version{syscall_ptr: felt*}(expected_version: felt) {
    let (tx_info: TxInfo*) = get_tx_info();
    assert tx_info.version = expected_version;

    return ();
}

@external
@raw_output
func test_delegate_call{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    code_address: felt, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = delegate_call(
        contract_address=code_address,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

@external
@raw_output
func test_library_call{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    class_hash: felt, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

@external
func test_library_call_l1_handler{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    class_hash: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    library_call_l1_handler(
        class_hash=class_hash,
        function_selector=selector,
        calldata_size=calldata_len,
        calldata=calldata,
    );
    return ();
}

@external
func test_count_actual_storage_changes{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*}() {
    const address = 15;
    storage_write(address=address, value=0);
    storage_write(address=address, value=1);
    return ();
}

@external
func test_replace_class{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    class_hash: felt
) {
    // TODO(Arni, 1/2/2023): Use 'get_class_hash_at' syscall, once exists, to test the class hash
    //  before and after the 'replace_class' syscall.
    let (self_address) = get_contract_address();
    // Call self; the old class should be invoked.
    let (foo_result) = MyContract.foo(contract_address=self_address);
    assert foo_result = 123;
    replace_class(class_hash=class_hash);
    // Call self; the new class should be invoked.
    let (second_foo_result) = MyContract.foo(contract_address=self_address);
    assert second_foo_result = 234;
    // Use the implementation from this contract; the old class should be invoked.
    let (third_foo_result) = foo();
    assert third_foo_result = 123;

    return ();
}
