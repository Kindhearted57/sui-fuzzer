use bcs;

#[cfg(feature = "aptos")]
use aptos_language_e2e_tests::executor::FakeExecutor;
#[cfg(feature = "aptos")]
use aptos_types::{
    transaction::{
        EntryFunction,
        TransactionPayload, 
        TransactionArgument,
        TransactionStatus,
    },
};
#[cfg(feature = "aptos")]
use move_core_types::{
    account_address::AccountAddress,
    value::{MoveValue, MoveStruct},
};

use crate::runner::runner::{Runner, StatefulRunner};
use crate::{
    fuzzer::{coverage::Coverage, error::Error},
    mutator::types::Type as FuzzerType,
};
use move_core_types::{identifier::Identifier, language_storage::ModuleId};

#[cfg(feature = "aptos")]
pub fn generate_inputs(inputs: Vec<FuzzerType>) -> Vec<MoveValue> {
    let mut res = vec![];
    for i in inputs {
        match i {
            FuzzerType::U8(value) => res.push(MoveValue::U8(value)),
            FuzzerType::U16(value) => res.push(MoveValue::U16(value)),
            FuzzerType::U32(value) => res.push(MoveValue::U32(value)),
            FuzzerType::U64(value) => res.push(MoveValue::U64(value)),
            FuzzerType::U128(value) => res.push(MoveValue::U128(value)),
            FuzzerType::Bool(value) => res.push(MoveValue::Bool(value)),
            FuzzerType::Vector(_, vec) => {
                res.push(MoveValue::Vector(generate_inputs(vec)))
            }
            FuzzerType::Struct(values) => res.push(MoveValue::Struct(
                MoveStruct::Runtime(generate_inputs(values)), 
            )),
            FuzzerType::Reference(_, _) => {
                res.push(MoveValue::Address(AccountAddress::random()))
            }
            _ => unimplemented!(),
        }
    }
    res
}
#[cfg(feature = "aptos")]
pub struct AptosRunner {
    target_module: String,
    target_function: Option<FuzzerType>,
    modules: Vec<Vec<u8>>,
    package_address: AccountAddress,
    account_address: AccountAddress,
}

#[cfg(feature = "aptos")]
impl AptosRunner {
    pub fn new(target_module: &str, modules: Vec<Vec<u8>>) -> Self {
        let mut runner = Self {
            target_module: target_module.to_string(),
            target_function: None,
            modules,
            package_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            account_address: AccountAddress::random(),
        };
        
        runner.setup();
        runner
    }

    fn convert_move_value_to_aptos_arg(&self, value: &move_core_types::value::MoveValue) -> Option<TransactionArgument> {
        #[cfg(feature = "aptos")]
        use move_core_types::value::MoveValue;
        
        match value {
            MoveValue::Bool(v) => Some(TransactionArgument::Bool(*v)),
            MoveValue::U8(v) => Some(TransactionArgument::U8(*v)),
            MoveValue::U64(v) => Some(TransactionArgument::U64(*v)),
            MoveValue::U128(v) => Some(TransactionArgument::U128(*v)),
            MoveValue::Address(addr) => Some(TransactionArgument::Address(*addr)),
            MoveValue::Vector(vec) => {
                if let Some(MoveValue::U8(_)) = vec.first() {
                    let bytes: Vec<u8> = vec.iter()
                        .filter_map(|v| if let MoveValue::U8(b) = v { Some(*b) } else { None })
                        .collect();
                    Some(TransactionArgument::U8Vector(bytes))
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    fn send_transaction(
        &mut self,
        target_function: &str,
        args: Vec<TransactionArgument>,
    ) -> Result<(TransactionStatus, u64), Error> {

        let mut executor = FakeExecutor::from_head_genesis();
        let account_data = executor.new_account_data_at(self.account_address);
        let account = account_data.account();
        let module_id = ModuleId::new(
            self.package_address,
            Identifier::new(self.target_module.as_str()).map_err(|e| Error::Unknown {
                message: format!("Invalid module name: {}", e),
            })?,
        );
        
        let function_id = Identifier::new(target_function).map_err(|e| Error::Unknown {
            message: format!("Invalid function name: {}", e),
        })?;

        // Convert TransactionArguments to bytes for EntryFunction
        let args_bytes: Vec<Vec<u8>> = args.into_iter().map(|arg| {
            match arg {
                TransactionArgument::U8(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U16(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U32(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U64(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U128(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U256(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::Bool(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::Address(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U8Vector(v) => bcs::to_bytes(&v).unwrap(),
            }
        }).collect();
        
        let entry_function = EntryFunction::new(module_id, function_id, vec![], args_bytes);
        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create and execute transaction
        let txn = account
            .transaction()
            .payload(payload)
            .sequence_number(0)
            .sign();

        let output = executor.execute_transaction(txn);
        let gas_used = output.gas_used();
        
        Ok((output.status().clone(), gas_used))
    }
}

#[cfg(feature = "aptos")]
impl Runner for AptosRunner {
    fn execute(
        &mut self,
        inputs: Vec<FuzzerType>,
    ) -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        let mut args = vec![];
        let inputs_clone = inputs.clone();

        // Convert fuzzer inputs to transaction arguments
        for input in &generate_inputs(inputs_clone) {
            if let Some(arg) = self.convert_move_value_to_aptos_arg(input) {
                args.push(arg);
            }
        }

        let response = self.send_transaction(
            &self
                .target_function
                .clone()
                .unwrap()
                .as_function()
                .unwrap()
                .0,
            args,
        );

        match response {
            Ok((status, gas_used)) => {
                match status {
                    TransactionStatus::Keep(_) => {
                        // Successful execution
                        Ok((None, gas_used))
                    },
                    TransactionStatus::Discard(_) => Err((
                        None,
                        Error::Unknown {
                            message: "Transaction was discarded".to_string(),
                        },
                    )),
                    TransactionStatus::Retry => Err((
                        None,
                        Error::Unknown {
                            message: "Transaction should be retried".to_string(),
                        },
                    )),
                }
            },
            Err(err) => Err((None, err)),
        }
    }

    fn get_target_parameters(&self) -> Vec<FuzzerType> {
        self.target_function
            .clone()
            .unwrap()
            .as_function()
            .unwrap()
            .1
            .clone()
    }

    fn get_target_module(&self) -> String {
        self.target_module.clone()
    }

    fn get_target_function(&self) -> FuzzerType {
        self.target_function.clone().unwrap()
    }

    fn get_max_coverage(&self) -> usize {
        100 // Place holder, gas meter is used instead
    }

    fn set_target_function(&mut self, function: &FuzzerType) {
        self.target_function = Some(function.clone());
    }
}

#[cfg(feature = "aptos")]
impl StatefulRunner for AptosRunner {
    fn setup(&mut self) {
        // Setup is now minimal since we create executor/account on-demand
        // TODO: Publish modules - this needs to be implemented based on how 
        // modules are compiled and published in Aptos
        // For now, we'll use a placeholder address
        self.package_address = AccountAddress::from_hex_literal("0x1").unwrap();
        self.account_address = AccountAddress::random();
    }
}

// Stub implementation when aptos feature is not enabled
#[cfg(not(feature = "aptos"))]
pub struct AptosRunner {
    target_module: String,
    target_function: Option<FuzzerType>,
    modules: Vec<Vec<u8>>,
}

#[cfg(not(feature = "aptos"))]
impl AptosRunner {
    pub fn new(_target_module: &str, _modules: Vec<Vec<u8>>) -> Self {
        panic!("Aptos support not compiled. Please enable the 'aptos' feature.");
    }
}

#[cfg(not(feature = "aptos"))]
impl Runner for AptosRunner {
    fn execute(
        &mut self,
        _inputs: Vec<FuzzerType>,
    ) -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_parameters(&self) -> Vec<FuzzerType> {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_module(&self) -> String {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_function(&self) -> FuzzerType {
        unreachable!("Aptos support not compiled");
    }

    fn get_max_coverage(&self) -> usize {
        unreachable!("Aptos support not compiled");
    }

    fn set_target_function(&mut self, _function: &FuzzerType) {
        unreachable!("Aptos support not compiled");
    }
}

#[cfg(not(feature = "aptos"))]
impl StatefulRunner for AptosRunner {
    fn setup(&mut self) {
        unreachable!("Aptos support not compiled");
    }
}