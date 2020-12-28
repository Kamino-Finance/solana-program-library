#![cfg(feature = "test-bpf")]

mod helpers;

use helpers::*;
use solana_sdk::signature::Signer;
use spl_stake_pool::*;

#[tokio::test]
async fn test_stake_pool_initialize() {
    let (mut banks_client, payer, recent_blockhash) = program_test().start().await;
    let stake_pool_accounts = StakePoolAccounts::new();
    stake_pool_accounts
        .initialize_stake_pool(&mut banks_client, &payer, &recent_blockhash)
        .await;

    // Stake pool now exists
    let stake_pool = banks_client
        .get_account(stake_pool_accounts.stake_pool.pubkey())
        .await
        .expect("get_account")
        .expect("stake pool not none");
    assert_eq!(stake_pool.data.len(), state::State::LEN);
    assert_eq!(stake_pool.owner, id());

    // Validator stake list storage initialized
    let validator_stake_list = banks_client
        .get_account(stake_pool_accounts.validator_stake_list.pubkey())
        .await
        .expect("get_account")
        .expect("validator stake list not none");
    let validator_stake_list =
        state::ValidatorStakeList::deserialize(validator_stake_list.data.as_slice()).unwrap();
    assert_eq!(validator_stake_list.is_initialized, true);
}
