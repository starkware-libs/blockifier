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
