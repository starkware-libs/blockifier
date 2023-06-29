use serde_json::json;

use crate::fee::os_usage::OsResources;

#[ctor::ctor]
pub static OS_RESOURCES: OsResources = {
    serde_json::from_value(os_resources())
        .expect("os_resources json does not exist or cannot be deserialized.")
};

// TODO(Arni, 14/6/2023): Update `GetBlockHash` values.
fn os_resources() -> serde_json::Value {
    json!({
        "execute_syscalls": {
            "CallContract": {
                "builtin_instance_counter": {
                    "range_check_builtin": 19
                },
                "n_memory_holes": 0,
                "n_steps": 690
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 19
                },
                "n_memory_holes": 0,
                "n_steps": 712
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 15
                },
                "n_memory_holes": 0,
                "n_steps": 691
            },
            "Deploy": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 7,
                    "range_check_builtin": 18
                },
                "n_memory_holes": 0,
                "n_steps": 936
            },
            "EmitEvent": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 19
            },
            "GetBlockHash": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 44
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
            // The following is the cost of one Keccak round.
            // TODO(ilya): Consider moving the resources of a keccak round to a seperate dict.
            "Keccak": {
                "builtin_instance_counter": {
                    "bitwise_builtin": 6,
                    "keccak_builtin": 1,
                    "range_check_builtin": 56
                },
                "n_memory_holes": 0,
                "n_steps": 381
            },
            "LibraryCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 19
                },
                "n_memory_holes": 0,
                "n_steps": 679
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 15
                },
                "n_memory_holes": 0,
                "n_steps": 658
            },
            "ReplaceClass": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 73
            },
            "Secp256k1GetXy": {
                "builtin_instance_counter": {
                    "range_check_builtin": 9
                },
                "n_memory_holes": 0,
                "n_steps": 124
            },
            "Secp256k1New": {
                "builtin_instance_counter": {
                    "range_check_builtin": 36
                },
                "n_memory_holes": 0,
                "n_steps": 440
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
                    "range_check_builtin": 63
                },
                "n_memory_holes": 0,
                "n_steps": 2703
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 23,
                    "range_check_builtin": 83
                },
                "n_memory_holes": 0,
                "n_steps": 3612
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 16,
                    "range_check_builtin": 80,
                },
                "n_memory_holes": 0,
                "n_steps": 3363
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 11,
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 1068
            }
        }
    })
}
