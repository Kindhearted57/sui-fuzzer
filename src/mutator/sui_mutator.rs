use crate::mutator::mutator::Mutator;
use basic_mutator::{self, EmptyDatabase};
use super::{rng::Rng, types::Type};

pub struct SuiMutator {
    seed: u64,
    mutator: basic_mutator::Mutator,
}

impl SuiMutator {
    pub fn new(seed: u64, max_input_size: usize) -> Self {
        let mutator = basic_mutator::Mutator::new()
            .seed(seed)
            .max_input_size(max_input_size);
        SuiMutator { seed, mutator }
    }
}

impl Mutator for SuiMutator {
    fn mutate(&mut self, inputs: &Vec<Type>, nb_mutation: usize) -> Vec<Type> {
        self.mutate_with_gas(inputs, nb_mutation, None)
    }

    fn generate_number(&self, min: u64, max: u64) -> u64 {
        let mut rng = Rng {
            seed: self.seed,
            exp_disabled: false,
        };
        rng.rand(min.try_into().unwrap(), max.try_into().unwrap())
            .try_into()
            .unwrap()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}


impl SuiMutator {
    pub fn mutate_with_gas(&mut self, inputs: &Vec<Type>, nb_mutation: usize, target_gas: Option<u64>) -> Vec<Type> {
        let mut res = vec![];

        // Calculate gas bias - higher gas leads to more mutations
        let gas_bias_multiplier = if let Some(gas) = target_gas {
            // Use logarithmic scaling to prevent excessive mutations
            let normalized_gas = (gas as f64).ln().max(1.0);
            // Scale to reasonable range (1.0 to 3.0 multiplier)
            1.0 + (normalized_gas / 10.0).min(2.0)
        } else {
            1.0
        };

        for input in inputs {
            self.mutator.input.clear();
            match input {
                Type::U8(v) => self.mutator.input.extend_from_slice(&v.to_be_bytes()),
                Type::U16(v) => self.mutator.input.extend_from_slice(&v.to_be_bytes()),
                Type::U32(v) => self.mutator.input.extend_from_slice(&v.to_be_bytes()),
                Type::U64(v) => self.mutator.input.extend_from_slice(&v.to_be_bytes()),
                Type::U128(v) => self.mutator.input.extend_from_slice(&v.to_be_bytes()),
                Type::Bool(b) => self
                    .mutator
                    .input
                    .extend_from_slice(&[if *b { 1 } else { 0 }]),
                Type::Vector(_, vec) => {
                    let buffer: Vec<u8> = vec
                        .iter()
                        .map(|v| {
                            if let Type::U8(a) = v {
                                a.to_owned()
                            } else {
                                todo!()
                            }
                        })
                        .collect();
                    self.mutator.input.extend_from_slice(&buffer);
                }
                Type::Struct(_) => (),
                Type::Reference(_, _) => (),
                _ => unimplemented!(),
            }

            // Apply gas bias to number of mutations
            let biased_mutations = ((nb_mutation as f64) * gas_bias_multiplier).round() as usize;
            let final_mutations = biased_mutations.max(1).min(nb_mutation * 3); // Cap at 3x original

            self.mutator.mutate(final_mutations, &EmptyDatabase);
            // The size of the input needs to be the right size
            res.push(match input {
                Type::U8(_) => {
                    let mut v = self.mutator.input.clone();
                    v.resize(1, 0);

                    Type::U8(u8::from_be_bytes(v[0..1].try_into().unwrap()))
                }
                Type::U16(_) => {
                    let mut v = self.mutator.input.clone();
                    v.resize(2, 0);

                    Type::U16(u16::from_be_bytes(v[0..2].try_into().unwrap()))
                }
                Type::U32(_) => {
                    let mut v = self.mutator.input.clone();
                    v.resize(4, 0);

                    Type::U32(u32::from_be_bytes(v[0..4].try_into().unwrap()))
                }
                Type::U64(_) => {
                    let mut v = self.mutator.input.clone();
                    v.resize(8, 0);

                    Type::U64(u64::from_be_bytes(v[0..8].try_into().unwrap()) % 1000)
                }
                Type::U128(_) => {
                    let mut v = self.mutator.input.clone();
                    v.resize(16, 0);

                    Type::U128(u128::from_be_bytes(v[0..16].try_into().unwrap()))
                }
                Type::Bool(_) => Type::Bool(self.mutator.input[0] != 0),
                Type::Vector(_, _) => Type::Vector(
                    Box::new(Type::U8(0)),
                    self.mutator
                        .input
                        .iter()
                        .map(|a| Type::U8(a.to_owned()))
                        .collect(),
                ),
                Type::Struct(types) => Type::Struct(self.mutate(types, nb_mutation)),
                Type::Reference(_, _) => input.clone(),
                _ => unimplemented!(),
            });
        }
        res
    }
}
