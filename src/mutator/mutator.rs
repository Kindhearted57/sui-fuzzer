use super::types::Type;
use std::any::Any;

pub trait Mutator {
    fn mutate(&mut self, inputs: &Vec<Type>, nb_mutation: usize) -> Vec<Type>;
    fn generate_number(&self, min: u64, max: u64) -> u64;
    fn as_any(&self) -> &dyn Any;

    // Default implementation that ignores gas
    fn mutate_with_gas(&mut self, inputs: &Vec<Type>, nb_mutation: usize, _target_gas: Option<u64>) -> Vec<Type> {
        self.mutate(inputs, nb_mutation)
    }
}
