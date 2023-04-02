use once_cell::sync::Lazy;
use serde_json::json;

use crate::fee::os_usage::OsResources;

pub static OS_RESOURCES: Lazy<OsResources> = Lazy::new(|| {
    serde_json::from_value(os_resources())
        .expect("os_resources json does not exist or cannot be deserialized.")
});

fn os_resources() -> serde_json::Value {
    json!({
        "execute_syscalls": {
            "CallContract": {
                "builtin_instance_counter": {
                    "range_check_builtin": 18
                },
                "n_memory_holes": 0,
                "n_steps": 630
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 18
                },
                "n_memory_holes": 0,
                "n_steps": 652
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 14
                },
                "n_memory_holes": 0,
                "n_steps": 631
            },
            "Deploy": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 7,
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 878
            },
            "EmitEvent": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 19
            },
            "GetBlockNumber": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 40
            },
            "GetBlockTimestamp": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 38
            },
            "GetCallerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 32
            },
            "GetContractAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 36
            },
            "GetSequencerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 34
            },
            "GetTxInfo": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 29
            },
            "GetTxSignature": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 44
            },
            "LibraryCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 18
                },
                "n_memory_holes": 0,
                "n_steps": 619
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 14
                },
                "n_memory_holes": 0,
                "n_steps": 598
            },
            "SendMessageToL1": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 84
            },
            "StorageRead": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 44
            },
            "StorageWrite": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 46
            }
        },
        "execute_txs_inner": {
            "Declare": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 15,
                    "range_check_builtin": 61
                },
                "n_memory_holes": 0,
                "n_steps": 2581
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 23,
                    "range_check_builtin": 80
                },
                "n_memory_holes": 0,
                "n_steps": 3434
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 16,
                    "range_check_builtin": 77
                },
                "n_memory_holes": 0,
                "n_steps": 3181
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 11,
                    "range_check_builtin": 16
                },
                "n_memory_holes": 0,
                "n_steps": 1006
            }
        }
    })
}
