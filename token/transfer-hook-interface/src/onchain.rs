//! On-chain program invoke helper to perform on-chain `execute` with correct accounts

use {
    crate::{error::TransferHookError, get_extra_account_metas_address, instruction},
    solana_program::{
        account_info::AccountInfo,
        entrypoint::ProgramResult,
        instruction::{AccountMeta, Instruction},
        program::invoke,
        pubkey::Pubkey,
    },
    spl_tlv_account_resolution::state::ExtraAccountMetaList,
};
/// Helper to CPI into a transfer-hook program on-chain, looking through the
/// additional account infos to create the proper instruction
pub fn invoke_execute<'a>(
    program_id: &Pubkey,
    source_info: AccountInfo<'a>,
    mint_info: AccountInfo<'a>,
    destination_info: AccountInfo<'a>,
    authority_info: AccountInfo<'a>,
    additional_accounts: &[AccountInfo<'a>],
    amount: u64,
) -> ProgramResult {
    let validation_pubkey = get_extra_account_metas_address(mint_info.key, program_id);
    let validation_info = additional_accounts
        .iter()
        .find(|&x| *x.key == validation_pubkey)
        .ok_or(TransferHookError::IncorrectAccount)?;
    let mut cpi_instruction = instruction::execute(
        program_id,
        source_info.key,
        mint_info.key,
        destination_info.key,
        authority_info.key,
        &validation_pubkey,
        amount,
    );

    let mut cpi_account_infos = vec![
        source_info,
        mint_info,
        destination_info,
        authority_info,
        validation_info.clone(),
    ];
    ExtraAccountMetaList::add_to_cpi_instruction::<instruction::ExecuteInstruction>(
        &mut cpi_instruction,
        &mut cpi_account_infos,
        &validation_info.try_borrow_data()?,
        additional_accounts,
    )?;
    invoke(&cpi_instruction, &cpi_account_infos)
}

/// Helper to add accounts required for the transfer-hook program on-chain, looking
/// through the additional account infos to add the proper accounts
pub fn add_cpi_accounts_for_execute<'a>(
    cpi_instruction: &mut Instruction,
    cpi_account_infos: &mut Vec<AccountInfo<'a>>,
    mint_pubkey: &Pubkey,
    program_id: &Pubkey,
    additional_accounts: &[AccountInfo<'a>],
) -> ProgramResult {
    let validation_pubkey = get_extra_account_metas_address(mint_pubkey, program_id);
    let validation_info = additional_accounts
        .iter()
        .find(|&x| *x.key == validation_pubkey)
        .ok_or(TransferHookError::IncorrectAccount)?;

    let program_info = additional_accounts
        .iter()
        .find(|&x| x.key == program_id)
        .ok_or(TransferHookError::IncorrectAccount)?;

    // The extra-account metas must be resolved as if for an `Execute` *into the hook program* —
    // seed-derived (PDA) metas are derived against `cpi_instruction.program_id`, so resolving
    // against the (token-program) transfer-checked instruction would derive PDAs against the wrong
    // program. We therefore build a standalone `Execute` instruction (program id = the hook), let
    // `add_to_cpi_instruction` resolve the metas against it, then graft the resolved *extra*
    // accounts (everything past the 5 standard ones) onto the real transfer-checked CPI.
    //
    // The first four accounts of the transfer-checked CPI are, in order, source/mint/destination/
    // authority — the leading accounts of an `Execute`. The transfer amount (needed for any
    // `Seed::InstructionData` metas) is parsed from the transfer-checked instruction data
    // (`[tag, amount: u64, decimals]`).
    let amount = cpi_instruction
        .data
        .get(1..9)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let mut execute_instruction = instruction::execute(
        program_id,
        cpi_account_infos[0].key,
        cpi_account_infos[1].key,
        cpi_account_infos[2].key,
        cpi_account_infos[3].key,
        &validation_pubkey,
        amount,
    );
    let mut execute_account_infos = vec![
        cpi_account_infos[0].clone(),
        cpi_account_infos[1].clone(),
        cpi_account_infos[2].clone(),
        cpi_account_infos[3].clone(),
        validation_info.clone(),
    ];

    ExtraAccountMetaList::add_to_cpi_instruction::<instruction::ExecuteInstruction>(
        &mut execute_instruction,
        &mut execute_account_infos,
        &validation_info.try_borrow_data()?,
        additional_accounts,
    )?;

    // Graft the resolved extra accounts (past source/mint/destination/authority/validation) onto
    // the transfer-checked CPI, then the validation state and the hook program itself.
    cpi_instruction
        .accounts
        .extend_from_slice(&execute_instruction.accounts[5..]);
    cpi_account_infos.extend_from_slice(&execute_account_infos[5..]);

    cpi_account_infos.push(validation_info.clone());
    cpi_account_infos.push(program_info.clone());
    cpi_instruction
        .accounts
        .push(AccountMeta::new_readonly(validation_pubkey, false));
    cpi_instruction
        .accounts
        .push(AccountMeta::new_readonly(*program_id, false));
    Ok(())
}
