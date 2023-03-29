use std::collections::HashMap;

use crate::transaction::objects::ResourcesMapping;

pub fn extract_l1_gas_and_cairo_usage(
    resources: &ResourcesMapping,
) -> (usize, HashMap<String, usize>) {
    let mut cairo_resource_usage = resources.0.clone();
    let l1_gas_usage = match cairo_resource_usage.remove("l1_gas_usage") {
        Some(l1_gas_usage) => l1_gas_usage,
        None => panic!("ResourcesMapping does not have the key l1_gas_usage."),
    };
    (l1_gas_usage, cairo_resource_usage)
}
