use strum::IntoEnumIterator;

use crate::execution::syscalls::SyscallSelector;
use crate::fee::os_resources_0_10_3::OS_RESOURCES_0_10_3;
use crate::fee::os_resources_0_11_0::OS_RESOURCES_0_11_0;
use crate::transaction::transaction_types::TransactionType;

#[test]
fn test_resources_entries() {
    for tx_type in TransactionType::iter() {
        assert!(OS_RESOURCES_0_10_3.execute_txs_inner.get(&tx_type).is_some());
        assert!(OS_RESOURCES_0_11_0.execute_txs_inner.get(&tx_type).is_some());
    }
    for syscall_selector in SyscallSelector::iter() {
        assert!(OS_RESOURCES_0_10_3.execute_syscalls.get(&syscall_selector).is_some());
        assert!(OS_RESOURCES_0_11_0.execute_syscalls.get(&syscall_selector).is_some());
    }
}
