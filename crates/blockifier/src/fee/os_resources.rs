use serde_json::json;

use crate::fee::os_usage::OsResources;

#[ctor::ctor]
pub static OS_RESOURCES: OsResources = {
    serde_json::from_value(os_resources())
        .expect("os_resources json does not exist or cannot be deserialized.")
};

fn os_resources() -> serde_json::Value {
    json!({
        "execute_syscalls": {
            "CallContract": {
                "builtin_instance_counter": {
                    "range_check": 19
                },
                "n_memory_holes": 0,
                "n_steps": 677
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    "range_check": 19
                },
                "n_memory_holes": 0,
                "n_steps": 699
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    "range_check": 15
                },
                "n_memory_holes": 0,
                "n_steps": 678
            },
            "Deploy": {
                "builtin_instance_counter": {
                    "pedersen": 7,
                    "range_check": 18
                },
                "n_memory_holes": 0,
                "n_steps": 920
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
            "GetExecutionInfo": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 29
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
                    "range_check": 19
                },
                "n_memory_holes": 0,
                "n_steps": 666
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check": 15
                },
                "n_memory_holes": 0,
                "n_steps": 645
            },
            "ReplaceClass": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 73
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
                    "pedersen": 15,
                    "range_check": 63
                },
                "n_memory_holes": 0,
                "n_steps": 2676
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    "pedersen": 23,
                    "range_check": 83
                },
                "n_memory_holes": 0,
                "n_steps": 3571
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    "pedersen": 16,
                    "range_check": 80,
                },
                "n_memory_holes": 0,
                "n_steps": 3323
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    "pedersen": 11,
                    "range_check": 17
                },
                "n_memory_holes": 0,
                "n_steps": 1054
            }
        }
    })
}
