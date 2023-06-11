use std::collections::HashSet;

use cairo_vm::vm::runners::builtin_runner::{
    BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
    OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME,
    SEGMENT_ARENA_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
};
use strum::IntoEnumIterator;

use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::fee::os_usage::OS_RESOURCES;
use crate::transaction::transaction_types::TransactionType;

#[test]
fn test_resources_entries() {
    for tx_type in TransactionType::iter() {
        assert!(OS_RESOURCES.execute_txs_inner.get(&tx_type).is_some());
    }
    for syscall_selector in DeprecatedSyscallSelector::iter() {
        assert!(OS_RESOURCES.execute_syscalls.get(&syscall_selector).is_some());
    }
}

#[test]
fn test_resource_name_consistency() {
    let known_builtin_names: HashSet<&str> = HashSet::from([
        OUTPUT_BUILTIN_NAME,
        HASH_BUILTIN_NAME,
        RANGE_CHECK_BUILTIN_NAME,
        SIGNATURE_BUILTIN_NAME,
        BITWISE_BUILTIN_NAME,
        EC_OP_BUILTIN_NAME,
        KECCAK_BUILTIN_NAME,
        POSEIDON_BUILTIN_NAME,
        SEGMENT_ARENA_BUILTIN_NAME,
    ]);
    for resources in OS_RESOURCES.execute_syscalls.values() {
        for builtin_name in resources.builtin_instance_counter.keys() {
            assert!(known_builtin_names.contains(builtin_name.as_str()));
        }
    }
}
