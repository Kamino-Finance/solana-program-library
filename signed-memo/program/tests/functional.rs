#![cfg(feature = "test-bpf")]

use solana_program::{
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
};
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use spl_signed_memo::*;

fn program_test() -> ProgramTest {
    ProgramTest::new(
        "spl_signed_memo",
        id(),
        processor!(processor::process_instruction),
    )
}

#[tokio::test]
async fn test_signed_memo() {
    let memo = "🐆".as_bytes();
    let (mut banks_client, payer, recent_blockhash) = program_test().start().await;

    let keypairs = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let pubkeys: Vec<Pubkey> = keypairs.iter().map(|keypair| keypair.pubkey()).collect();

    // Test complete signing
    let signer_key_refs: Vec<&Pubkey> = pubkeys.iter().collect();
    let mut transaction = Transaction::new_with_payer(
        &[signed_memo(memo, &signer_key_refs)],
        Some(&payer.pubkey()),
    );
    let mut signers = vec![&payer];
    for keypair in keypairs.iter() {
        signers.push(keypair);
    }
    transaction.sign(&signers, recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Test unsigned memo
    let mut transaction =
        Transaction::new_with_payer(&[signed_memo(memo, &[])], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Demonstrate success on signature provided, regardless of specific signed-memo AccountMeta
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new_readonly(keypairs[0].pubkey(), true),
                AccountMeta::new_readonly(keypairs[1].pubkey(), true),
                AccountMeta::new_readonly(payer.pubkey(), false),
            ],
            data: memo.to_vec(),
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &keypairs[0], &keypairs[1]], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Test missing signer(s)
    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new_readonly(keypairs[0].pubkey(), true),
                AccountMeta::new_readonly(keypairs[1].pubkey(), false),
                AccountMeta::new_readonly(keypairs[2].pubkey(), true),
            ],
            data: memo.to_vec(),
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &keypairs[0], &keypairs[2]], recent_blockhash);
    assert_eq!(
        banks_client
            .process_transaction(transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
    );

    let mut transaction = Transaction::new_with_payer(
        &[Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new_readonly(keypairs[0].pubkey(), false),
                AccountMeta::new_readonly(keypairs[1].pubkey(), false),
                AccountMeta::new_readonly(keypairs[2].pubkey(), false),
            ],
            data: memo.to_vec(),
        }],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    assert_eq!(
        banks_client
            .process_transaction(transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
    );
}
