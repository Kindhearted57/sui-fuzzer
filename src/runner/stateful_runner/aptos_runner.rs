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
        TransactionArgument,
        TransactionStatus,
        RawTransaction,
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

use std::sync::Arc;
use aptos_secure_storage::InMemoryStorage;
use aptos_executor::block_executor::{BlockExecutor, TransactionBlockExecutor};
use aptos_types::block_executor::partitioner::{ExecutableTransactions};
use aptos_types::block_executor::config::BlockExecutorConfigFromOnchain;
use aptos_storage_interface::{DbReaderWriter, cached_state_view::CachedStateView};
use aptos_crypto::hash::DefaultHasher;
use aptos_storage_interface::state_view::LatestDbStateCheckpointView;
use aptos_storage_interface::mock::MockDbReaderWriter;
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
    executor: Option<BlockExecutor<AptosVM>>,
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
            executor: None,
            target_module: target_module.to_string(),
            target_function: None,
            modules,
            package_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            account_current: AccountCurrent::new(AccountData::with_account(account, 1_000_000, 0)),
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

        let account = self.account_current.account();
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

        // Create raw transaction
        let raw_txn = RawTransaction::new(
            *account.address(),
            0, // sequence number
            payload,
            1_000_000, // max gas
            1, // gas price
            10, // expiration
            ChainId::test(),
        );

        // Sign the transaction
        let signed_txn: SignedTransaction = raw_txn
            .sign(&account.privkey, account.pubkey.as_ed25519().expect("pubkey error").clone())
            .map_err(|e| Error::Unknown {
                message: format!("Failed to sign transaction: {}", e),
            })?
            .into_inner();
        let transaction: Transaction = Transaction::UserTransaction(signed_txn);
        let sv_txn: SignatureVerifiedTransaction = transaction.into();

        // Create executable transactions
        let transactions = ExecutableTransactions::Unsharded(vec![sv_txn]);
        
        // Get executor and create state view
        let executor = self.executor.as_ref().ok_or_else(|| Error::Unknown {
            message: "Executor not initialized".to_string(),
        })?;

        let version = executor.db.reader.get_latest_state_checkpoint_version()
            .map_err(|e| Error::Unknown {
                message: format!("Failed to get version: {}", e),
            })?
            .unwrap_or(0);
        let state_view = CachedStateView::new(
            aptos_types::state_store::StateViewId::Miscellaneous,
            executor.db.reader.clone(),
            version,
            aptos_scratchpad::SparseMerkleTree::new_empty(),
            std::sync::Arc::new(aptos_storage_interface::async_proof_fetcher::AsyncProofFetcher::new(executor.db.reader.clone())),
        ).map_err(|e| Error::Unknown {
            message: format!("Failed to create state view: {}", e),
        })?;
        let config = BlockExecutorConfigFromOnchain::new_no_block_limit();

        // Execute using AptosVM
        let chunk_output = AptosVM::execute_transaction_block(transactions, state_view, config)
            .map_err(|e| Error::Unknown {
                message: format!("Transaction execution failed: {}", e),
            })?;
  
        // Extract result
        if let Some(output) = chunk_output.transaction_outputs.first() {
            let gas_used = output.gas_used();
            Ok((output.status().clone(), gas_used))
        } else {
            Err(Error::Unknown {
                message: "No transaction output".to_string(),
            })
        }
    }

    pub fn publish(
        account: &mut AccountCurrent,
        modules: Vec<Vec<u8>>,   // compiled bytecode
        executor: &BlockExecutor<AptosVM>,
    ) -> anyhow::Result<TransactionOutput> {

        let empty_metadata:Vec<u8> = vec![];
        // Create a transaction payload
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(
                AccountAddress::from_hex_literal("0x1").unwrap(),
                ident_str!("code").to_owned(),
            ),
            ident_str!("publish_package_txn").to_owned(),
            vec![],
            vec![
                bcs::to_bytes(&empty_metadata).unwrap(),
                bcs::to_bytes(&modules).unwrap(),
            ],
        ));
        // Sequence number for sender
        let seq_num = 0;

        // Create raw transaction
        let raw_txn = RawTransaction::new(
            *account.account().address(),
            seq_num,
            payload,
            1_000_000,
            1,
            10,
            ChainId::test(),
        );

        // Sign the txn
        let signed_txn: SignedTransaction = raw_txn
            .sign(&account.account().privkey, account.account().pubkey.as_ed25519().expect("pubkey error").clone())?
            .into_inner();
        let transaction: Transaction = Transaction::UserTransaction(signed_txn);
        let sv_txn: SignatureVerifiedTransaction = transaction.into();
        let transactions = ExecutableTransactions::Unsharded(vec![sv_txn]);
        let config = BlockExecutorConfigFromOnchain::new_no_block_limit();

        // Create state view using the executor's database
        let version = executor.db.reader.get_latest_state_checkpoint_version()?.unwrap_or(0);
        let state_view = CachedStateView::new(
            aptos_types::state_store::StateViewId::Miscellaneous,
            executor.db.reader.clone(),
            version,
            aptos_scratchpad::SparseMerkleTree::new_empty(),
            std::sync::Arc::new(aptos_storage_interface::async_proof_fetcher::AsyncProofFetcher::new(executor.db.reader.clone())),
        )?;

        // Execute using AptosVM
        let chunk_output = AptosVM::execute_transaction_block(transactions, state_view, config)?;

        // Extract result
        if let Some(output) = chunk_output.transaction_outputs.first() {
            Ok(output.clone())
        } else {
            Err(anyhow::anyhow!("No transaction output"))
        }
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
        // Create mock database for testing
        let db = DbReaderWriter::new(MockDbReaderWriter);
        let executor = BlockExecutor::<AptosVM>::new(db);
        self.executor = Some(executor);

        // 3. Publish fuzzing Move package
        let output = Self::publish(
            &mut self.account_current,
            self.modules.clone(),
            self.executor.as_ref().unwrap(),
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
