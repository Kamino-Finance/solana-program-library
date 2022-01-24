//! Program state processor

use crate::{
    state::{
        enums::GovernanceAccountType,
        governance::{
            assert_valid_create_governance_args, get_token_governance_address_seeds, Governance,
            GovernanceConfig,
        },
        realm::get_realm_data,
        token_owner_record::get_token_owner_record_data_for_realm,
    },
    tools::spl_token::{assert_spl_token_owner_is_signer, set_spl_token_authority},
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use spl_governance_tools::account::create_and_serialize_account_signed;
use spl_token::{instruction::AuthorityType, state::Account};

/// Processes CreateTokenGovernance instruction
pub fn process_create_token_governance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    config: GovernanceConfig,
    transfer_account_authorities: bool,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let realm_info = next_account_info(account_info_iter)?; // 0
    let token_governance_info = next_account_info(account_info_iter)?; // 1

    let governed_token_info = next_account_info(account_info_iter)?; // 2
    let governed_token_owner_info = next_account_info(account_info_iter)?; // 3

    let token_owner_record_info = next_account_info(account_info_iter)?; // 4

    let payer_info = next_account_info(account_info_iter)?; // 5
    let spl_token_info = next_account_info(account_info_iter)?; // 6

    let system_info = next_account_info(account_info_iter)?; // 7

    let rent_sysvar_info = next_account_info(account_info_iter)?; // 8
    let rent = &Rent::from_account_info(rent_sysvar_info)?;

    let governance_authority_info = next_account_info(account_info_iter)?; // 9

    assert_valid_create_governance_args(program_id, &config, realm_info)?;

    let realm_data = get_realm_data(program_id, realm_info)?;
    let token_owner_record_data =
        get_token_owner_record_data_for_realm(program_id, token_owner_record_info, realm_info.key)?;

    token_owner_record_data.assert_token_owner_or_delegate_is_signer(governance_authority_info)?;

    let voter_weight = token_owner_record_data.resolve_voter_weight(
        program_id,
        account_info_iter,
        realm_info.key,
        &realm_data,
    )?;

    token_owner_record_data.assert_can_create_governance(&realm_data, voter_weight)?;

    let token_governance_data = Governance {
        account_type: GovernanceAccountType::TokenGovernance,
        realm: *realm_info.key,
        governed_account: *governed_token_info.key,
        config,
        proposals_count: 0,
        reserved: [0; 8],
    };

    create_and_serialize_account_signed::<Governance>(
        payer_info,
        token_governance_info,
        &token_governance_data,
        &get_token_governance_address_seeds(realm_info.key, governed_token_info.key),
        program_id,
        system_info,
        rent,
    )?;

    if transfer_account_authorities {
        set_spl_token_authority(
            governed_token_info,
            governed_token_owner_info,
            token_governance_info.key,
            spl_token_info,
            AuthorityType::AccountOwner,
        )?;

        // If the token account has close_authority then transfer it as well
        let token_account_data = Account::unpack(&governed_token_info.data.borrow())?;
        // Note: The code assumes owner==close_authority
        //       If this is not the case then the caller should set close_authority accordingly before making the transfer
        if token_account_data.close_authority.is_some() {
            set_spl_token_authority(
                governed_token_info,
                governed_token_owner_info,
                token_governance_info.key,
                spl_token_info,
                AuthorityType::CloseAccount,
            )?;
        }
    } else {
        assert_spl_token_owner_is_signer(governed_token_info, governed_token_owner_info)?;
    }

    Ok(())
}
