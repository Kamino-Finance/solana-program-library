#![cfg(feature = "test-sbf")]

use solana_program_test::*;

mod program_test;

use program_test::*;
use spl_governance::state::{enums::MintMaxVoterWeightSource, realm::get_realm_address};

use crate::program_test::args::RealmSetupArgs;

#[tokio::test]
async fn test_create_realm() {
    // Arrange
    let mut governance_test = GovernanceProgramTest::start_new().await;

    // Act
    let realm_cookie = governance_test.with_realm().await;

    // Assert
    let realm_account = governance_test
        .get_realm_account(&realm_cookie.address)
        .await;

    assert_eq!(realm_cookie.account, realm_account);
}
