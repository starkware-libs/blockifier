use pyo3::prelude::*;

use crate::PyFelt;

#[derive(FromPyObject)]
pub struct PyBlockInfo {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub gas_price: u128,
    pub sequencer_address: PyFelt,
}
