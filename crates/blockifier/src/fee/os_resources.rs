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
                "n_steps": 691
            },
            "DelegateCall": {
                "builtin_instance_counter": {
                    "range_check_builtin": 19
                },
                "n_memory_holes": 0,
                "n_steps": 713
            },
            "DelegateL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 15
                },
                "n_memory_holes": 0,
                "n_steps": 692
            },
            "Deploy": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 7,
                    "range_check_builtin": 18
                },
                "n_memory_holes": 0,
                "n_steps": 944
            },
            "EmitEvent": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 19
            },
            "GetBlockHash": {
                "builtin_instance_counter": {
                    "range_check_builtin": 2
                },
                "n_memory_holes": 0,
                "n_steps": 74
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
                "n_steps": 680
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 15
                },
                "n_memory_holes": 0,
                "n_steps": 659
            },
            "ReplaceClass": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 73
            },
            "Secp256k1Add": {
                "builtin_instance_counter": {
                    "range_check_builtin": 29
                },
                "n_memory_holes": 0,
                "n_steps": 354
            },
            "Secp256k1GetPointFromX": {
                "builtin_instance_counter": {
                    "range_check_builtin": 30
                },
                "n_memory_holes": 0,
                "n_steps": 360
            },
            "Secp256k1GetXy": {
                "builtin_instance_counter": {
                    "range_check_builtin": 9
                },
                "n_memory_holes": 0,
                "n_steps": 124
            },
            "Secp256k1Mul": {
                "builtin_instance_counter": {
                    "range_check_builtin": 10739
                },
                "n_memory_holes": 0,
                "n_steps": 121910
            },
            "Secp256k1New": {
                "builtin_instance_counter": {
                    "range_check_builtin": 36
                },
                "n_memory_holes": 0,
                "n_steps": 440
            },
            "Secp256r1Add": {
                "builtin_instance_counter": {
                    "range_check_builtin": 57
                },
                "n_memory_holes": 0,
                "n_steps": 578
            },
            "Secp256r1GetPointFromX": {
                "builtin_instance_counter": {
                    "range_check_builtin": 44
                },
                "n_memory_holes": 0,
                "n_steps": 535
            },
            "Secp256r1GetXy": {
                "builtin_instance_counter": {
                    "range_check_builtin": 9
                },
                "n_memory_holes": 0,
                "n_steps": 159
            },
            "Secp256r1Mul": {
                "builtin_instance_counter": {
                    "range_check_builtin": 21477
                },
                "n_memory_holes": 0,
                "n_steps": 196096
            },
            "Secp256r1New": {
                "builtin_instance_counter": {
                    "range_check_builtin": 49
                },
                "n_memory_holes": 0,
                "n_steps": 616
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
                "n_steps": 2711
            },
            "DeployAccount": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 23,
                    "range_check_builtin": 83
                },
                "n_memory_holes": 0,
                "n_steps": 3628
            },
            "InvokeFunction": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 16,
                    "range_check_builtin": 80,
                },
                "n_memory_holes": 0,
                "n_steps": 3382
            },
            "L1Handler": {
                "builtin_instance_counter": {
                    "pedersen_builtin": 11,
                    "range_check_builtin": 17
                },
                "n_memory_holes": 0,
                "n_steps": 1069
            }
        }
    })
}
