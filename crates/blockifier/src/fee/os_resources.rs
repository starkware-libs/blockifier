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
                    "range_check_builtin": 20
                },
                "n_memory_holes": 4,
                "n_steps": 760
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
                    "range_check_builtin": 19
                },
                "n_memory_holes": 13,
                "n_steps": 1010
            },
            "EmitEvent": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 61
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
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 62
            },
            "GetContractAddress": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 62
            },
            "GetExecutionInfo": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 62
            },
            "GetSequencerAddress": {
                "builtin_instance_counter": {},
                "n_memory_holes": 0,
                "n_steps": 34
            },
            "GetTxInfo": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 62
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
                    "range_check_builtin": 20
                },
                "n_memory_holes": 4,
                "n_steps": 751
            },
            "LibraryCallL1Handler": {
                "builtin_instance_counter": {
                    "range_check_builtin": 15
                },
                "n_memory_holes": 0,
                "n_steps": 659
            },
            "ReplaceClass": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 98
            },
            "Secp256k1Add": {
                "builtin_instance_counter": {
                    "range_check_builtin": 29
                },
                "n_memory_holes": 0,
                "n_steps": 406
            },
            "Secp256k1GetPointFromX": {
                "builtin_instance_counter": {
                    "range_check_builtin": 30
                },
                "n_memory_holes": 18,
                "n_steps": 391
            },
            "Secp256k1GetXy": {
                "builtin_instance_counter": {
                    "range_check_builtin": 11
                },
                "n_memory_holes": 40,
                "n_steps": 239
            },
            "Secp256k1Mul": {
                "builtin_instance_counter": {
                    "range_check_builtin": 7045
                },
                "n_memory_holes": 2,
                "n_steps": 76501
            },
            "Secp256k1New": {
                "builtin_instance_counter": {
                    "range_check_builtin": 35
                },
                "n_memory_holes": 40,
                "n_steps": 475
            },
            "Secp256r1Add": {
                "builtin_instance_counter": {
                    "range_check_builtin": 57
                },
                "n_memory_holes": 0,
                "n_steps": 589
            },
            "Secp256r1GetPointFromX": {
                "builtin_instance_counter": {
                    "range_check_builtin": 44
                },
                "n_memory_holes": 20,
                "n_steps": 510
            },
            "Secp256r1GetXy": {
                "builtin_instance_counter": {
                    "range_check_builtin": 11
                },
                "n_memory_holes": 40,
                "n_steps": 241
            },
            "Secp256r1Mul": {
                "builtin_instance_counter": {
                    "range_check_builtin": 13961
                },
                "n_memory_holes": 2,
                "n_steps": 125340
            },
            "Secp256r1New": {
                "builtin_instance_counter": {
                    "range_check_builtin": 49
                },
                "n_memory_holes": 40,
                "n_steps": 594
            },
            "SendMessageToL1": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 139
            },
            "StorageRead": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 87
            },
            "StorageWrite": {
                "builtin_instance_counter": {
                    "range_check_builtin": 1
                },
                "n_memory_holes": 0,
                "n_steps": 89
            }
        },
        "execute_txs_inner": {
            "Declare": {
                    "Constant": {
                        "builtin_instance_counter": {
                            "pedersen_builtin": 15,
                            "range_check_builtin": 63
                        },
                        "n_memory_holes": 66,
                        "n_steps": 2843
                    },
                "Slope": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 0,
                        "range_check_builtin": 0
                    },
                    "n_memory_holes": 0,
                    "n_steps": 0
                }
            },
                "DeployAccount": {
                "Constant": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 23,
                        "range_check_builtin": 83
                    },
                    "n_memory_holes": 82,
                    "n_steps": 3798
                },
                // Calculation of transaction hash + contract address + memcpy.
                "Slope":{
                    "builtin_instance_counter": {
                        "pedersen_builtin": 2,
                        "range_check_builtin": 0
                    },
                    "n_memory_holes": 0,
                    "n_steps": 21
                },
            },
                "InvokeFunction": {
                    "Constant": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 16,
                        "range_check_builtin": 80
                    },
                    "n_memory_holes": 68,
                    "n_steps": 3549
                },
                // Calculation of transaction hash.
                "Slope": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 1,
                        "range_check_builtin": 0
                    },
                    "n_memory_holes": 0,
                    "n_steps": 8
                }
            },
                "L1Handler": {
                    "Constant": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 11,
                        "range_check_builtin": 17
                    },
                    "n_memory_holes": 0,
                    "n_steps": 1157
                },
                // Calculation of transaction hash + memcpy.
                "Slope": {
                    "builtin_instance_counter": {
                        "pedersen_builtin": 1,
                        "range_check_builtin": 0
                    },
                    "n_memory_holes": 0,
                    "n_steps": 13
                }
            }
        }
    })
}
