use crate::transaction::objects::ResourcesMapping;
use std::collections::HashMap;

pub fn extract_l1_gas_and_cairo_usage(resources: &ResourcesMapping) -> (usize, HashMap<std::string::String, usize>){
    let mut cairo_resource_usage = resources.0.clone();
    let l1_gas_usage = match cairo_resource_usage.get("l1_gas_usage") {
        Some(l1_gas_usage) => *l1_gas_usage,
        _ => panic!("ResourcesMapping does not have the key l1_gas_usage.")
    };
    cairo_resource_usage.remove("l1_gas_usage");
    (l1_gas_usage, cairo_resource_usage)
}
