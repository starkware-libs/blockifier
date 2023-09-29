use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_lang_casm::hints::Hint;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::{
    ApTracking, Attribute, BuiltinName, FlowTrackingData, HintParams, Identifier,
    InstructionLocation, ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::{HintsCollection, Program, SharedProgramData};
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, POSEIDON_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::de::{self, Error as DeserializationError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointOffset, EntryPointType,
    Program as DeprecatedProgram,
};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{self, CONSTRUCTOR_ENTRY_POINT_NAME};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::PreExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, sn_api_to_cairo_vm_program};
/// Represents a runnable Starknet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Clone, Debug, Eq, PartialEq, derive_more::From, Serialize, Deserialize)]
pub enum ContractClass {
    V0(ContractClassV0),
    V1(ContractClassV1),
}

impl ContractClass {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        match self {
            ContractClass::V0(class) => class.constructor_selector(),
            ContractClass::V1(class) => class.constructor_selector(),
        }
    }

    pub fn estimate_casm_hash_computation_resources(&self) -> VmExecutionResources {
        match self {
            ContractClass::V0(class) => class.estimate_casm_hash_computation_resources(),
            ContractClass::V1(_class) => {
                let bytecode_len: usize = 1;
                poseidon_hash_many_cost(bytecode_len)
            }
        }
    }
}

// V0.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ContractClassV0(pub Arc<ContractClassV0Inner>);
impl Deref for ContractClassV0 {
    type Target = ContractClassV0Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ContractClassV0 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    fn n_entry_points(&self) -> usize {
        self.entry_points_by_type.values().map(|vec| vec.len()).sum()
    }

    pub fn n_builtins(&self) -> usize {
        self.program.builtins_len()
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    fn estimate_casm_hash_computation_resources(&self) -> VmExecutionResources {
        let hashed_data_size = (constants::CAIRO0_ENTRY_POINT_STRUCT_SIZE * self.n_entry_points())
            + self.n_builtins()
            + self.bytecode_length()
            + 1; // Hinted class hash.
        // The hashed data size is approximately the number of hashes (invoked in hash chains).
        let n_steps = constants::N_STEPS_PER_PEDERSEN * hashed_data_size;

        VmExecutionResources {
            n_steps,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(
                HASH_BUILTIN_NAME.to_string(),
                hashed_data_size,
            )]),
        }
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<ContractClassV0, ProgramError> {
        let contract_class: ContractClassV0Inner = serde_json::from_str(raw_contract_class)?;
        Ok(ContractClassV0(Arc::new(contract_class)))
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV0Inner {
    #[serde(with = "serde_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl TryFrom<DeprecatedContractClass> for ContractClassV0 {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassV0Inner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

// V1.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV1(pub Arc<ContractClassV1Inner>);
impl Deref for ContractClassV1 {
    type Target = ContractClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ContractClassV1 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.0.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    pub fn get_entry_point(
        &self,
        call: &CallEntryPoint,
    ) -> Result<EntryPointV1, PreExecutionError> {
        if call.entry_point_type == EntryPointType::Constructor
            && call.entry_point_selector != selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME)
        {
            return Err(PreExecutionError::InvalidConstructorEntryPointName);
        }

        let entry_points_of_same_type = &self.0.entry_points_by_type[&call.entry_point_type];
        let filtered_entry_points: Vec<_> = entry_points_of_same_type
            .iter()
            .filter(|ep| ep.selector == call.entry_point_selector)
            .collect();

        match &filtered_entry_points[..] {
            [] => Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector)),
            [entry_point] => Ok((*entry_point).clone()),
            _ => Err(PreExecutionError::DuplicatedEntryPointSelector {
                selector: call.entry_point_selector,
                typ: call.entry_point_type,
            }),
        }
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<ContractClassV1, ProgramError> {
        let casm_contract_class: CasmContractClass = serde_json::from_str(raw_contract_class)?;
        let contract_class: ContractClassV1 = casm_contract_class.try_into()?;

        Ok(contract_class)
    }

    /// Returns an empty contract class for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn empty_for_testing() -> Self {
        Self(Arc::new(ContractClassV1Inner {
            program: Default::default(),
            entry_points_by_type: Default::default(),
            hints: Default::default(),
        }))
    }
}

/// Returns the VM resources required for running `poseidon_hash_many` in the Starknet OS.
fn poseidon_hash_many_cost(data_length: usize) -> VmExecutionResources {
    VmExecutionResources {
        n_steps: (data_length / 10) * 55
            + ((data_length % 10) / 2) * 18
            + (data_length % 2) * 3
            + 21,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(
            POSEIDON_BUILTIN_NAME.to_string(),
            data_length / 2 + 1,
        )]),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV1Inner {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPointV1>>,
    pub hints: HashMap<String, Hint>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EntryPointV1 {
    pub selector: EntryPointSelector,
    pub offset: EntryPointOffset,
    pub builtins: Vec<String>,
}

impl EntryPointV1 {
    pub fn pc(&self) -> usize {
        self.offset.0
    }
}

impl TryFrom<CasmContractClass> for ContractClassV1 {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        let data: Vec<MaybeRelocatable> = class
            .bytecode
            .into_iter()
            .map(|x| MaybeRelocatable::from(Felt252::from(x.value)))
            .collect();

        let mut hints: HashMap<usize, Vec<HintParams>> = HashMap::new();
        for (i, hint_list) in class.hints.iter() {
            let hint_params: Result<Vec<HintParams>, ProgramError> =
                hint_list.iter().map(hint_to_hint_params).collect();
            hints.insert(*i, hint_params?);
        }

        // Collect a sting to hint map so that the hint processor can fetch the correct [Hint]
        // for each instruction.
        let mut string_to_hint: HashMap<String, Hint> = HashMap::new();
        for (_, hint_list) in class.hints.iter() {
            for hint in hint_list.iter() {
                string_to_hint.insert(serde_json::to_string(hint)?, hint.clone());
            }
        }

        let builtins = vec![]; // The builtins are initialize later.
        let main = Some(0);
        let reference_manager = ReferenceManager { references: Vec::new() };
        let identifiers = HashMap::new();
        let error_message_attributes = vec![];
        let instruction_locations = None;

        let program = Program::new(
            builtins,
            data,
            main,
            hints,
            reference_manager,
            identifiers,
            error_message_attributes,
            instruction_locations,
        )?;

        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            convert_entry_points_v1(class.entry_points_by_type.constructor)?,
        );
        entry_points_by_type.insert(
            EntryPointType::External,
            convert_entry_points_v1(class.entry_points_by_type.external)?,
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            convert_entry_points_v1(class.entry_points_by_type.l1_handler)?,
        );

        Ok(Self(Arc::new(ContractClassV1Inner {
            program,
            entry_points_by_type,
            hints: string_to_hint,
        })))
    }
}

// V0 utilities.

mod serde_program {
    use super::*;

    // We have this because `hints` field is a hashmap from <uisze, HintParams>
    // When deserializing from JSON, for untagged enum it will only match for <string,
    // HintParams>
    #[derive(Deserialize, Serialize)]
    struct TmpSharedProgram {
        data: Vec<MaybeRelocatable>,
        hints: BTreeMap<String, Vec<HintParams>>,
        main: Option<usize>,
        start: Option<usize>,
        end: Option<usize>,
        error_message_attributes: Vec<Attribute>,
        instruction_locations: Option<HashMap<usize, InstructionLocation>>,
        identifiers: HashMap<String, Identifier>,
        reference_manager: Vec<HintReference>,
    }

    impl From<SharedProgramData> for TmpSharedProgram {
        fn from(shared_program_data: SharedProgramData) -> Self {
            Self {
                data: shared_program_data.data,
                hints: Into::<BTreeMap<usize, Vec<HintParams>>>::into(
                    &shared_program_data.hints_collection,
                )
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
                main: shared_program_data.main,
                start: shared_program_data.start,
                end: shared_program_data.end,
                error_message_attributes: shared_program_data.error_message_attributes,
                instruction_locations: shared_program_data.instruction_locations,
                identifiers: shared_program_data.identifiers,
                reference_manager: shared_program_data.reference_manager,
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct TmpProgram {
        pub shared_program_data: TmpSharedProgram,
        pub constants: HashMap<String, Felt252>,
        pub builtins: Vec<BuiltinName>,
    }

    pub(crate) fn serialize<S>(program: &Program, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let shared_program_data = program.shared_program_data.as_ref().clone().into();
        let constants = program.constants.clone();
        let builtins = program.builtins.clone();

        let tmp_program = TmpProgram { shared_program_data, constants, builtins };

        tmp_program.serialize(serializer)
    }

    /// Converts the program type from SN API into a Cairo VM-compatible type.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Program, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Tmp {
            /// Box the variant in order to reduce the size of the enum (clippy suggestion).
            CairoVM(Box<TmpProgram>),
            SNProgram(DeprecatedProgram),
        }

        let program: Tmp = Tmp::deserialize(deserializer)?;

        match program {
            Tmp::CairoVM(tmp_program) => {
                let hints: BTreeMap<usize, Vec<HintParams>> = tmp_program
                    .shared_program_data
                    .hints
                    .into_iter()
                    .map(|(k, v)| {
                        let key = k.parse::<usize>().map_err(|error| {
                            de::Error::custom(format!(
                                "failed to convert value {} to usize, \n error {}",
                                k, error
                            ))
                        })?;

                        Ok((key, v))
                    })
                    .collect::<Result<_, D::Error>>()?;

                let hints_collection =
                    HintsCollection::new(&hints, tmp_program.shared_program_data.data.len())
                        .map_err(|err| de::Error::custom(err.to_string()))?;

                let shared_program_data = SharedProgramData {
                    data: tmp_program.shared_program_data.data,
                    hints_collection,
                    main: tmp_program.shared_program_data.main,
                    start: tmp_program.shared_program_data.start,
                    end: tmp_program.shared_program_data.end,
                    error_message_attributes: tmp_program
                        .shared_program_data
                        .error_message_attributes,
                    identifiers: tmp_program.shared_program_data.identifiers,
                    instruction_locations: tmp_program.shared_program_data.instruction_locations,
                    reference_manager: tmp_program.shared_program_data.reference_manager,
                };

                let program = Program {
                    shared_program_data: Arc::new(shared_program_data),
                    constants: tmp_program.constants,
                    builtins: tmp_program.builtins,
                };
                Ok(program)
            }
            Tmp::SNProgram(deprecated_program) => sn_api_to_cairo_vm_program(deprecated_program)
                .map_err(|err| DeserializationError::custom(err.to_string())),
        }
    }
}

// V1 utilities.

// TODO(spapini): Share with cairo-lang-runner.
fn hint_to_hint_params(hint: &cairo_lang_casm::hints::Hint) -> Result<HintParams, ProgramError> {
    Ok(HintParams {
        code: serde_json::to_string(hint)?,
        accessible_scopes: vec![],
        flow_tracking_data: FlowTrackingData {
            ap_tracking: ApTracking::new(),
            reference_ids: HashMap::new(),
        },
    })
}

fn convert_entry_points_v1(
    external: Vec<CasmContractEntryPoint>,
) -> Result<Vec<EntryPointV1>, ProgramError> {
    external
        .into_iter()
        .map(|ep| -> Result<_, ProgramError> {
            Ok(EntryPointV1 {
                selector: EntryPointSelector(felt_to_stark_felt(&Felt252::from(ep.selector))),
                offset: EntryPointOffset(ep.offset),
                builtins: ep.builtins.into_iter().map(|builtin| builtin + "_builtin").collect(),
            })
        })
        .collect()
}

#[cfg(test)]
mod test {
    use std::fs;

    use crate::execution::contract_class::ContractClassV0;

    #[test]
    fn test_deserialization_of_contract_class_v_0() {
        let contract_class = fs::read("./tests/counter.json").unwrap();
        let contract_class: ContractClassV0 = serde_json::from_slice(&contract_class)
            .expect("failed to deserialize contract class from file");

        let serialized_contract_class = serde_json::to_string_pretty(&contract_class)
            .expect("failed to serialize contract class");
        let _: ContractClassV0 = serde_json::from_str(&serialized_contract_class)
            .expect("failed to deserialize contract class from serialized string");
    }
}
