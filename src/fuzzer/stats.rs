use std::collections::HashMap;
use crate::{
    mutator::{types::Type as FuzzerType}};
#[derive(Clone)]
pub struct Stats {
    pub crashes: u64,
    pub unique_crashes: u64,
    pub execs: u64,
    pub time_running: u64,
    pub execs_per_sec: u64,
    pub coverage_size: u64,
    pub secs_since_last_cov: u64,
    pub gas_map: HashMap<String, u64>
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            crashes: 0,
            unique_crashes: 0,
            time_running: 0,
            execs: 0,
            coverage_size: 0,
            execs_per_sec: 0,
            secs_since_last_cov: 0,
            gas_map: HashMap::new()
        }
    }
    pub fn update_gas_usage(&mut self, function: &FuzzerType, gas: u64){
        let key = function.as_function().unwrap().0.clone();
        let entry = self.gas_map.entry(key).or_insert(0);
        if gas > *entry {
            *entry = gas;
        }
    }
    pub fn get_max_gas(&self, function: &FuzzerType) -> u64 {
        let key = function.as_function().unwrap().0.clone();
        *self.gas_map.get(&key).unwrap_or(&0)
    }
}
