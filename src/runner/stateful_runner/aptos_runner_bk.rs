use bcs;
use std::hash::{Hash, Hasher};

#[cfg(feature = "aptos")]
use aptos_language_e2e_tests::executor::FakeExecutor;
use aptos_language_e2e_tests::{
    account_universe::AccountCurrent, 
    account::{AccountData,Account}};
#[cfg(feature = "aptos")]
use aptos_types::{
    transaction::{
        EntryFunction,
        TransactionPayload,
        DeprecatedPayload, 
        TransactionArgument,
        TransactionStatus,
        RawTransaction,
        ModuleBundle,
        SignedTransaction,
        TransactionOutput,
        Transaction,
        signature_verified_transaction::SignatureVerifiedTransaction,
    },
    chain_id::ChainId,
};
#[cfg(feature = "aptos")]
use move_core_types::{
    account_address::AccountAddress,
    value::{MoveValue, MoveStruct},
    ident_str, identifier::Identifier, language_storage::ModuleId,
    transaction_argument
};

use crate::runner::runner::{Runner, StatefulRunner};
use crate::{
    fuzzer::{coverage::Coverage, error::Error},
    mutator::types::Type as FuzzerType,
};

use tokio::runtime::Runtime;
use rand::rngs::OsRng;
use aptos_crypto::{HashValue,ed25519::{Ed25519PrivateKey, Ed25519PublicKey}};
use aptos_sdk::transaction_builder::TransactionBuilder;

use aptos_vm::AptosVM;
use aptos_vm::aptos_vm::{VMBlockExecutor, AptosVMBlockExecutor};
use aptos_vm::VMBlockExecutor;
use std::sync::Arc;
use aptos_secure_storage::InMemoryStorage;
use aptos_block_executor::{executor::BlockExecutor, config::BlockExecutorConfigFromOnchain}; 
use aptos_executor_types::{BlockExecutorTrait};
use aptos_types::block_executor::partitioner::{ExecutableBlock,ExecutableTransactions};
use aptos_types::state_store::in_memory_state_view::InMemoryStateView;
use aptos_crypto::hash::DefaultHasher;
use aptos_block_executor::txn_provider::default::DefaultTxnProvider;
use anyhow;
type Txn = SignatureVerifiedTransaction;
type VM = AptosVM;
type State = InMemoryStorage;
type Hook = (); // No commit hook
type Exec = (); // Minimal Executable

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
    executor: AptosVMBlockExecutor,
    target_module: String,
    target_function: Option<FuzzerType>,
    modules: Vec<Vec<u8>>,
    package_address: AccountAddress,
    account_current: AccountCurrent,
}

#[cfg(feature = "aptos")]
impl AptosRunner {
    pub fn new(target_module: &str, modules: Vec<Vec<u8>>) -> Self {
        
        let account = Account::new();
        let mut runner = Self {
            executor: Option<AptosVMBlockExecutor>,
            target_module: target_module.to_string(),
            target_function: None,
            modules,
            package_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            account_current: AccountCurrent::new(AccountData::with_account(account, 1_000_000, 0, true, true)),
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

        // Initialize executor
        let mut executor = AptosVMBlockExecutor::new();
        // 4. Store executor + account
        self.executor = executor;
        let account_data = executor.new_account_data_at(*self.account_current.account().address());
        
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

        let entry_function = EntryFunction::new(module_id, function_id, vec![], transaction_argument::convert_txn_args(&args));
        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create and execute transaction
        let txn = account
            .transaction()
            .payload(payload)
            .sequence_number(0)
            .sign();
        let txn_provider = DefaultTxnProvider::new(txn, vec![]);
        let state_view = InMemoryStateView::default();
        let config = BlockExecutorConfigFromOnchain::default();
        let output = executor.execute_block(txn_provider, state_view, config, TransactionSliceMetadata::new_for_test() );
        let gas_used = output.gas_used();
        
        Ok((output.status().clone(), gas_used))
    }

    pub fn publish(
        account: &mut AccountCurrent,
        modules: Vec<Vec<u8>>,   // compiled bytecode
        executor: &mut AptosVMBlockExecutor,
    ) -> anyhow::Result<TransactionOutput> {
        let account_data = executor.new_account_data_at(*self.account_current.account().address());
        
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

        let entry_function = EntryFunction::new(module_id, function_id, vec![], transaction_argument::convert_txn_args(&args));
        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create and execute transaction
        let txn = account
            .transaction()
            .payload(payload)
            .sequence_number(0)
            .sign();
        let txn_provider = DefaultTxnProvider::new(txn, vec![]);
        let state_view = InMemoryStateView::default();
        let config = BlockExecutorConfigFromOnchain::default();
        // Execute in executor
        let output = executor.execute_block(txn_provider, state_view, config, TransactionSliceMetadata::new_for_test() );
        outputs?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Empty transaction outputs"))
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

        // Initialize executor
        let mut executor = AptosVMBlockExecutor::new();
        // 4. Store executor + account
        self.executor = executor.clone();
        // 3. Publish fuzzing Move package
        let output = Self::publish(
            & mut self.account_current,
            self.modules.clone(),
            &mut executor,
        ).expect("publish failed");
        // 5. Run fuzz_init entry function (if present in the module)
        let _ = self.send_transaction("fuzz_init", vec![])
            .expect("Could not init fuzzing!");
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