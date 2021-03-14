//! Program state processor

use crate::{error::TimelockError, state::{enums::TimelockType, timelock_config::TimelockConfig, timelock_program::TimelockProgram, timelock_set::{TimelockSet, TIMELOCK_SET_VERSION}, timelock_state::{DESC_SIZE, NAME_SIZE}}, utils::{TokenMintToParams, assert_account_equiv, assert_cheap_mint_initialized, assert_initialized, assert_rent_exempt, assert_token_program_is_correct, assert_uninitialized, get_mint_from_account, spl_token_mint_to}};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_pack::Pack,
    pubkey::Pubkey,
    sysvar::{rent::Rent, Sysvar},
};
use spl_token::state::{Account, Mint};

/// Create a new timelock set
pub fn process_init_timelock_set(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    name: [u8; NAME_SIZE],
    desc_link: [u8; DESC_SIZE],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let timelock_set_account_info = next_account_info(account_info_iter)?;
    let signatory_mint_account_info = next_account_info(account_info_iter)?;
    let admin_mint_account_info = next_account_info(account_info_iter)?;
    let voting_mint_account_info = next_account_info(account_info_iter)?;
    let yes_voting_mint_account_info = next_account_info(account_info_iter)?;
    let no_voting_mint_account_info = next_account_info(account_info_iter)?;
    let signatory_validation_account_info = next_account_info(account_info_iter)?;
    let admin_validation_account_info = next_account_info(account_info_iter)?;
    let voting_validation_account_info = next_account_info(account_info_iter)?;
    let destination_admin_account_info = next_account_info(account_info_iter)?;
    let destination_sig_account_info = next_account_info(account_info_iter)?;
    let yes_voting_dump_account_info = next_account_info(account_info_iter)?;
    let no_voting_dump_account_info = next_account_info(account_info_iter)?;
    let governance_holding_account_info = next_account_info(account_info_iter)?;
    let governance_mint_account_info = next_account_info(account_info_iter)?;
    let timelock_config_account_info = next_account_info(account_info_iter)?;
    let timelock_program_authority_info = next_account_info(account_info_iter)?;
    let timelock_program_info = next_account_info(account_info_iter)?;
    let token_program_info = next_account_info(account_info_iter)?;
    let rent_info = next_account_info(account_info_iter)?;
    let rent = &Rent::from_account_info(rent_info)?;

    let timelock_program: TimelockProgram = assert_initialized(timelock_program_info)?;
    let timelock_config: TimelockConfig = assert_initialized(timelock_config_account_info)?;
    // Using assert_account_equiv not workable here due to cost of stack size on this method.
    if governance_mint_account_info.key != &timelock_config.governance_mint {
        return Err(TimelockError::AccountsShouldMatch.into());
    }

    let mut new_timelock_set: TimelockSet = assert_uninitialized(timelock_set_account_info)?;
    new_timelock_set.version = TIMELOCK_SET_VERSION;
    new_timelock_set.state.desc_link = desc_link;
    new_timelock_set.state.name = name;
    new_timelock_set.state.total_signing_tokens_minted = 1;
    new_timelock_set.config = *timelock_config_account_info.key;

    assert_token_program_is_correct(&timelock_program, token_program_info)?;
    // now create the mints.

    new_timelock_set.admin_mint = *admin_mint_account_info.key;
    new_timelock_set.voting_mint = *voting_mint_account_info.key;
    new_timelock_set.yes_voting_mint = *yes_voting_mint_account_info.key;
    new_timelock_set.no_voting_mint = *no_voting_mint_account_info.key;
    new_timelock_set.signatory_mint = *signatory_mint_account_info.key;

    let _governance_mint: Mint = assert_initialized(governance_mint_account_info)?;
    new_timelock_set.governance_holding = *governance_holding_account_info.key;

    new_timelock_set.admin_validation = *admin_validation_account_info.key;
    new_timelock_set.voting_validation = *voting_validation_account_info.key;
    new_timelock_set.signatory_validation = *signatory_validation_account_info.key;

    // cant use assert_rent_exempt or a loop because will blow out stack size here
    if !rent.is_exempt(timelock_set_account_info.lamports(), timelock_set_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    } 
    if !rent.is_exempt(governance_holding_account_info.lamports(), governance_holding_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    } 
    if !rent.is_exempt(admin_mint_account_info.lamports(), admin_mint_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    } 
    if !rent.is_exempt(voting_mint_account_info.lamports(), voting_mint_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(yes_voting_mint_account_info.lamports(), yes_voting_mint_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(no_voting_mint_account_info.lamports(), no_voting_mint_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(signatory_mint_account_info.lamports(), signatory_mint_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(admin_validation_account_info.lamports(), admin_validation_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(signatory_validation_account_info.lamports(), signatory_validation_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
    if !rent.is_exempt(voting_validation_account_info.lamports(), voting_validation_account_info.data_len()) {
        return Err(TimelockError::NotRentExempt.into())
    }
   
    // Cheap computational and stack-wise calls for initialization checks, no deserialization req'd
    assert_cheap_mint_initialized(admin_mint_account_info)?;
    assert_cheap_mint_initialized(voting_mint_account_info)?;
    assert_cheap_mint_initialized(yes_voting_mint_account_info)?;
    assert_cheap_mint_initialized(no_voting_mint_account_info)?;
    assert_cheap_mint_initialized(signatory_mint_account_info)?;
    let sig_acct_mint: Pubkey = get_mint_from_account(destination_sig_account_info)?;
    let admin_acct_mint: Pubkey = get_mint_from_account(destination_admin_account_info)?;
    let sig_validation_mint: Pubkey = get_mint_from_account(signatory_validation_account_info)?;
    let admin_validation_mint: Pubkey = get_mint_from_account(admin_validation_account_info)?;
    let voting_validation_mint: Pubkey = get_mint_from_account(voting_validation_account_info)?;
    let yes_voting_dump_mint: Pubkey = get_mint_from_account(yes_voting_dump_account_info)?;
    let no_voting_dump_mint: Pubkey = get_mint_from_account(no_voting_dump_account_info)?;
    let governance_holding_mint: Pubkey = get_mint_from_account(governance_holding_account_info)?;

    // Cant use helper or a loop because will blow out stack size with this many uses
    if &sig_acct_mint != signatory_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &admin_acct_mint != admin_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &sig_validation_mint != signatory_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &admin_validation_mint != admin_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &voting_validation_mint != voting_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &yes_voting_dump_mint != yes_voting_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &no_voting_dump_mint != no_voting_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }
    if &governance_holding_mint != governance_mint_account_info.key {
        return Err(TimelockError::MintsShouldMatch.into());
    }

   TimelockSet::pack(
        new_timelock_set,
        &mut timelock_set_account_info.data.borrow_mut(),
    )?;

    let (authority_key, bump_seed) =
        Pubkey::find_program_address(&[timelock_program_info.key.as_ref()], program_id);
    if timelock_program_authority_info.key != &authority_key {
        return Err(TimelockError::InvalidTimelockAuthority.into());
    }
    let authority_signer_seeds = &[timelock_program_info.key.as_ref(), &[bump_seed]];

    spl_token_mint_to(TokenMintToParams {
        mint: admin_mint_account_info.clone(),
        destination: destination_admin_account_info.clone(),
        amount: 1,
        authority: timelock_program_authority_info.clone(),
        authority_signer_seeds: authority_signer_seeds,
        token_program: token_program_info.clone()
    })?;

    spl_token_mint_to(TokenMintToParams {
        mint: signatory_mint_account_info.clone(),
        destination: destination_sig_account_info.clone(),
        amount: 1,
        authority: timelock_program_authority_info.clone(),
        authority_signer_seeds: authority_signer_seeds,
        token_program: token_program_info.clone(),
    })?;
    Ok(())
}
