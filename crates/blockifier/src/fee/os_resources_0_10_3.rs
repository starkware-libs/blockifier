use once_cell::sync::Lazy;
use serde_json::json;

use crate::fee::os_usage::OsResources;

pub static OS_RESOURCES_0_10_3: Lazy<OsResources> = Lazy::new(|| {
    serde_json::from_value(os_resources())
        .expect("os_resources json does not exist or cannot be deserialized.")
});

fn os_resources() -> serde_json::Value {
    json!({
        "execute_syscalls": {
            "CallContract": {
                "builtin_instance_counter": {
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 545
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 567
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 13
                },
                "n_memory_holes": 0,
                "n_steps": 546
            },
            "Deploy": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 7,
                    "range_check_builtin": 16
                },
                "n_memory_holes": 0,
                "n_steps": 800
            },
            "EmitEvent": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 18
            },
            "GetBlockNumber": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 38
            },
            "GetBlockTimestamp": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 36
            },
            "GetCallerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 30
            },
            "GetContractAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 34
            },
            "GetSequencerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 32
            },
            "GetTxInfo": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 28
            },
            "GetTxSignature": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 43
            },
            "LibraryCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 535
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 13
                },
                "n_memory_holes": 0,
                "n_steps": 514
            },
            "SendMessageToL1": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 81
            },
            "StorageRead": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 42
            },
            "StorageWrite": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 44
            }
        },
        "execute_txs_inner": {
            "Declare": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 15,
                    "range_check_builtin": 57
                },
                "n_memory_holes": 0,
                "n_steps": 2336
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 23,
                    "range_check_builtin": 74
                },
                "n_memory_holes": 0,
                "n_steps": 3098
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 16,
                    "range_check_builtin": 70
                },
                "n_memory_holes": 0,
                "n_steps": 2839
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 11,
                    "range_check_builtin": 13
                },
                "n_memory_holes": 0,
                "n_steps": 877
            }
        }
    })
}
