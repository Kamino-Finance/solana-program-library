use {
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        rent::Rent,
    },
    solana_program_test::*,
    solana_sdk::{account::Account, signature::Signer, transaction::Transaction},
    spl_example_transfer_lamports::processor::process_instruction,
    std::str::FromStr,
};

#[tokio::test]
async fn test_lamport_transfer() {
    let program_id = Pubkey::from_str("TransferLamports111111111111111111111111111").unwrap();
    let source_pubkey = Pubkey::new_unique();
    let destination_pubkey = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "spl_example_transfer_lamports",
        program_id,
        processor!(process_instruction),
    );
    // The minimum balance to make an account with zero byte of data rent exempt
    let minimum_balance = Rent::default().minimum_balance(0);
    program_test.add_account(
        source_pubkey,
        Account {
            lamports: minimum_balance + 200,
            owner: program_id, // Can only withdraw lamports from accounts owned by the program
            ..Account::default()
        },
    );
    program_test.add_account(
        destination_pubkey,
        Account {
            lamports: minimum_balance + 100,
            ..Account::default()
        },
    );
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[Instruction::new_with_bincode(
            program_id,
            &(),
            vec![
                AccountMeta::new(source_pubkey, false),
                AccountMeta::new(destination_pubkey, false),
            ],
        )],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    let source_balance = banks_client.get_balance(source_pubkey).await.unwrap();
    assert_eq!(source_balance, minimum_balance + 195);
    let destination_balance = banks_client.get_balance(destination_pubkey).await.unwrap();
    assert_eq!(destination_balance, minimum_balance + 105);
}
