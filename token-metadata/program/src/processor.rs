use {
    crate::{
        error::MetadataError,
        instruction::MetadataInstruction,
        state::{
            Metadata, Owner, MAX_METADATA_LEN, MAX_NAME_LENGTH, MAX_OWNER_LEN, MAX_SYMBOL_LENGTH,
            MAX_URI_LENGTH, PREFIX,
        },
        utils::{assert_initialized, create_or_allocate_account_raw},
    },
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        borsh::try_from_slice_unchecked,
        entrypoint::ProgramResult,
        msg,
        pubkey::Pubkey,
    },
    spl_token::state::Mint,
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = MetadataInstruction::try_from_slice(input)?;
    match instruction {
        MetadataInstruction::CreateMetadataAccounts(args) => {
            msg!("Instruction: Create Metadata Accounts");
            process_create_metadata_accounts(program_id, accounts, args.name, args.symbol, args.uri)
        }
        MetadataInstruction::UpdateMetadataAccounts(args) => {
            msg!("Instruction: Update Metadata Accounts");
            process_update_metadata_accounts(program_id, accounts, args.uri)
        }
    }
}

/// Create a new account instruction
pub fn process_create_metadata_accounts(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    name: String,
    symbol: String,
    uri: String,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let owner_account_info = next_account_info(account_info_iter)?;
    let metadata_account_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let mint_authority_info = next_account_info(account_info_iter)?;
    let payer_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let system_account_info = next_account_info(account_info_iter)?;
    let rent_info = next_account_info(account_info_iter)?;

    if name.len() > MAX_NAME_LENGTH {
        return Err(MetadataError::NameTooLong.into());
    }

    if symbol.len() > MAX_SYMBOL_LENGTH {
        return Err(MetadataError::SymbolTooLong.into());
    }

    if uri.len() > MAX_URI_LENGTH {
        return Err(MetadataError::UriTooLong.into());
    }

    let mint: Mint = assert_initialized(mint_info)?;
    match mint.mint_authority {
        solana_program::program_option::COption::None => {
            return Err(MetadataError::InvalidMintAuthority.into());
        }
        solana_program::program_option::COption::Some(key) => {
            if *mint_authority_info.key != key {
                return Err(MetadataError::InvalidMintAuthority.into());
            }
        }
    }

    if !mint_authority_info.is_signer {
        return Err(MetadataError::NotMintAuthority.into());
    }

    let metadata_seeds = &[
        PREFIX.as_bytes(),
        program_id.as_ref(),
        mint_info.key.as_ref(),
    ];
    let (metadata_key, metadata_bump_seed) =
        Pubkey::find_program_address(metadata_seeds, program_id);
    let metadata_authority_signer_seeds = &[
        PREFIX.as_bytes(),
        program_id.as_ref(),
        mint_info.key.as_ref(),
        &[metadata_bump_seed],
    ];

    if metadata_account_info.key != &metadata_key {
        return Err(MetadataError::InvalidMetadataKey.into());
    }

    let owner_seeds = &[
        PREFIX.as_bytes(),
        program_id.as_ref(),
        &name.as_bytes(),
        &symbol.as_bytes(),
    ];
    let (owner_key, owner_bump_seed) = Pubkey::find_program_address(owner_seeds, program_id);
    let owner_authority_signer_seeds = &[
        PREFIX.as_bytes(),
        program_id.as_ref(),
        &name.as_bytes(),
        &symbol.as_bytes(),
        &[owner_bump_seed],
    ];

    if owner_account_info.key != &owner_key {
        return Err(MetadataError::InvalidOwnerKey.into());
    }

    create_or_allocate_account_raw(
        *program_id,
        metadata_account_info,
        rent_info,
        system_account_info,
        payer_account_info,
        MAX_METADATA_LEN,
        metadata_authority_signer_seeds,
    )?;
    create_or_allocate_account_raw(
        *program_id,
        owner_account_info,
        rent_info,
        system_account_info,
        payer_account_info,
        MAX_OWNER_LEN,
        owner_authority_signer_seeds,
    )?;

    let mut owner: Owner = try_from_slice_unchecked(&owner_account_info.data.borrow())?;
    let mut metadata: Metadata = try_from_slice_unchecked(&metadata_account_info.data.borrow())?;

    owner.owner = *owner_info.key;
    owner.metadata = *metadata_account_info.key;

    metadata.mint = *mint_info.key;
    metadata.data.name = name;
    metadata.data.symbol = symbol;
    metadata.data.uri = uri;

    owner.serialize(&mut *owner_account_info.data.borrow_mut())?;
    metadata.serialize(&mut *metadata_account_info.data.borrow_mut())?;

    Ok(())
}

/// Update existing account instruction
pub fn process_update_metadata_accounts(
    _: &Pubkey,
    accounts: &[AccountInfo],
    uri: String,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let metadata_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let owner_account_info = next_account_info(account_info_iter)?;

    if uri.len() > MAX_URI_LENGTH {
        return Err(MetadataError::UriTooLong.into());
    }

    let owner: Owner = try_from_slice_unchecked(&owner_account_info.data.borrow())?;
    let mut metadata: Metadata = try_from_slice_unchecked(&metadata_account_info.data.borrow())?;

    if owner.metadata != *metadata_account_info.key {
        return Err(MetadataError::InvalidMetadataForOwner.into());
    }

    if owner.owner != *owner_info.key {
        return Err(MetadataError::OwnerNotOwner.into());
    }

    if !owner_info.is_signer {
        return Err(MetadataError::OwnerIsNotSigner.into());
    }

    metadata.data.uri = uri;

    metadata.serialize(&mut *metadata_account_info.data.borrow_mut())?;
    Ok(())
}
