use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use serde_json::json;

use crate::abi::constants::N_STEPS_RESOURCE;
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
                    RANGE_CHECK_BUILTIN_NAME: 19
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 690
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    RANGE_CHECK_BUILTIN_NAME: 19
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 712
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    RANGE_CHECK_BUILTIN_NAME: 15
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 691
            },
            "Deploy": {
                "builtin_instance_counter": {
                    HASH_BUILTIN_NAME: 7,
                    RANGE_CHECK_BUILTIN_NAME: 18
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 936
            },
            "EmitEvent": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 19
            },
            "GetBlockNumber": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 40
            },
            "GetBlockTimestamp": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 38
            },
            "GetCallerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 32
            },
            "GetContractAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 36
            },
            "GetExecutionInfo": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 29
            },
            "GetSequencerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 34
            },
            "GetTxInfo": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 29
            },
            "GetTxSignature": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 44
            },
            "LibraryCall": {
                "builtin_instance_counter": {
                    RANGE_CHECK_BUILTIN_NAME: 19
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 679
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    RANGE_CHECK_BUILTIN_NAME: 15
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 658
            },
            "ReplaceClass": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 73
            },
            "SendMessageToL1": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 84
            },
            "StorageRead": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 44
            },
            "StorageWrite": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 46
            }
        },
        "execute_txs_inner": {
            "Declare": {
                "builtin_instance_counter": {
                    HASH_BUILTIN_NAME: 15,
                    RANGE_CHECK_BUILTIN_NAME: 63
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 2703
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    HASH_BUILTIN_NAME: 23,
                    RANGE_CHECK_BUILTIN_NAME: 83
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 3612
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    HASH_BUILTIN_NAME: 16,
                    RANGE_CHECK_BUILTIN_NAME: 80,
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 3363
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    HASH_BUILTIN_NAME: 11,
                    RANGE_CHECK_BUILTIN_NAME: 17
                },
                "n_memory_holes": 0,
                N_STEPS_RESOURCE: 1068
            }
        }
    })
}
