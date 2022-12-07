use std::any::Any;
use std::collections::HashMap;

use anyhow::{bail, Result};
use cairo_rs::bigint;
use cairo_rs::serde::deserialize_program::{
    deserialize_array_of_bigint_hex, deserialize_bigint_hex, Attribute, HintParams, Identifier,
    ReferenceManager,
};
use cairo_rs::types::errors::program_errors::ProgramError;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::MaybeRelocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use starknet_api::hash::StarkFelt;

use crate::execution::entry_point::{CallEntryPoint, EntryPointResult};
use crate::execution::syscall_handling::initialize_syscall_handler;

#[derive(Debug)]
pub enum Layout {
    All,
}

impl From<Layout> for String {
    fn from(layout: Layout) -> Self {
        // The Cairo runner is expecting `layout` to be a lowercase string.
        format!("{:?}", layout).to_ascii_lowercase()
    }
}

pub struct CairoRunConfig {
    pub enable_trace: bool,
    pub layout: Layout,
}

impl CairoRunConfig {
    pub fn default() -> Self {
        Self { enable_trace: false, layout: Layout::All }
    }
}

pub fn felt_to_bigint(felt: StarkFelt) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, felt.bytes())
}

pub fn bigint_to_felt(bigint: &BigInt) -> Result<StarkFelt> {
    // TODO(Adi, 29/11/2022): Make sure lambdaclass always maintain that their bigints' are
    // non-negative.
    if bigint.is_negative() {
        bail!("The given BigInt, {}, is negative.", bigint)
    }

    let bigint_hex = format!("{bigint:#x}");
    match StarkFelt::try_from(bigint_hex.as_str()) {
        Ok(felt) => Ok(felt),
        Err(e) => bail!(e),
    }
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_call_entry_point(
    call_entry_point: &CallEntryPoint,
    config: CairoRunConfig,
) -> Result<Vec<StarkFelt>> {
    // Instantiate Cairo runner.
    let program = convert_program_to_cairo_runner_format(&call_entry_point.contract_class.program)?;
    let layout: String = config.layout.into();
    let mut cairo_runner = CairoRunner::new(&program, &layout, false)?;
    let mut vm =
        VirtualMachine::new(program.prime, config.enable_trace, program.error_message_attributes);
    cairo_runner.initialize_builtins(&mut vm)?;
    cairo_runner.initialize_segments(&mut vm, None);
    let (syscall_segment, hint_processor) = initialize_syscall_handler(&mut cairo_runner, &mut vm);

    // Prepare arguments for run.
    let mut args: Vec<Box<dyn Any>> = Vec::new();
    // TODO(AlonH, 21/12/2022): Push the entry point selector to args once it is used.
    let mut implicit_args = Vec::<MaybeRelocatable>::new();
    implicit_args.push(syscall_segment.into());
    implicit_args.extend(
        vm.get_builtin_runners()
            .iter()
            .flat_map(|(_name, builtin_runner)| builtin_runner.initial_stack()),
    );
    args.push(Box::new(implicit_args));
    // TODO(AlonH, 21/12/2022): Consider using StarkFelt.
    // TODO(Adi, 29/11/2022): Remove the '.0' access, once derive-more is used in starknet_api.
    let calldata = &call_entry_point.calldata.0;
    args.push(Box::new(MaybeRelocatable::Int(bigint!(calldata.len()))));
    args.push(Box::new(
        calldata
            .iter()
            .map(|arg| MaybeRelocatable::Int(felt_to_bigint(*arg)))
            .collect::<Vec<MaybeRelocatable>>(),
    ));

    // Resolve initial PC from EP indicator.
    let entry_point = call_entry_point.find_entry_point_in_contract()?;
    let entry_point_pc = entry_point.offset.0;

    // Run.
    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        args.iter().map(|x| x.as_ref()).collect(),
        false,
        true,
        true,
        &mut vm,
        &hint_processor,
    )?;

    Ok(extract_execution_return_data(&vm)?)
}

fn extract_execution_return_data(vm: &VirtualMachine) -> EntryPointResult<Vec<StarkFelt>> {
    let [return_data_size, return_data_ptr]: [MaybeRelocatable; 2] = vm
        .get_return_values(2)?
        .try_into()
        .unwrap_or_else(|_| panic!("Return values should be of size 2."));

    let return_data_size = match return_data_size {
        // TODO(AlonH, 21/12/2022): Handle case where res_data_size is larger than usize.
        MaybeRelocatable::Int(return_data_size) => return_data_size.bits() as usize,
        relocatable => return Err(VirtualMachineError::ExpectedInteger(relocatable)),
    };

    let values = vm.get_continuous_range(&return_data_ptr, return_data_size)?;
    // Extract values as `StarkFelt`.
    let values: EntryPointResult<Vec<StarkFelt>> =
        values.into_iter().map(|x| get_felt_from_memory_cell(Some(x))).collect();
    values
}

// TODO(Noa, 01/12/2022): Change this temporary solution.
pub fn convert_program_to_cairo_runner_format(
    program: &starknet_api::state::Program,
) -> Result<Program, ProgramError> {
    let program = program.clone();
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;

    let start = match identifiers.get("__main__.__start__") {
        Some(identifier) => identifier.pc,
        None => None,
    };
    let end = match identifiers.get("__main__.__end__") {
        Some(identifier) => identifier.pc,
        None => None,
    };

    Ok(Program {
        builtins: serde_json::from_value::<Vec<String>>(program.builtins)?,
        prime: deserialize_bigint_hex(program.prime)?,
        data: deserialize_array_of_bigint_hex(program.data)?,
        constants: {
            let mut constants = HashMap::new();
            for (key, value) in identifiers.iter() {
                if value.type_.as_deref() == Some("const") {
                    let value = value
                        .value
                        .clone()
                        .ok_or_else(|| ProgramError::ConstWithoutValue(key.to_owned()))?;
                    constants.insert(key.to_owned(), value);
                }
            }

            constants
        },
        main: None,
        start,
        end,
        hints: serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?,
        reference_manager: serde_json::from_value::<ReferenceManager>(program.reference_manager)?,
        identifiers,
        error_message_attributes: serde_json::from_value::<Vec<Attribute>>(program.attributes)?
            .into_iter()
            .filter(|attr| attr.name == "error_message")
            .collect(),
    })
}

pub fn get_felt_from_memory_cell(
    memory_cell: Option<MaybeRelocatable>,
) -> EntryPointResult<StarkFelt> {
    match memory_cell {
        Some(MaybeRelocatable::Int(value)) => {
            // TODO(AlonH, 21/12/2022): Return appropriate error.
            bigint_to_felt(&value).map_err(|_| VirtualMachineError::BigintToUsizeFail)
        }
        Some(relocatable) => Err(VirtualMachineError::ExpectedInteger(relocatable)),
        None => Err(VirtualMachineError::NoneInMemoryRange),
    }
}
