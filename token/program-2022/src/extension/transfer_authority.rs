use std::slice::Iter;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

use super::{BaseState, BaseStateWithExtensions};

use {
    crate::{
        extension::{Extension, ExtensionType},
        pod::*,
    },
    bytemuck::{Pod, Zeroable},
};

/// Maximum number of additional accounts for a transfer authority
pub const MAX_ADDITIONAL_ACCOUNTS: usize = 3;

/// Transfer authority extension data for mints.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct TransferAuthorityMint {
    /// Program ID to CPI to on transfer
    pub program_id: OptionalNonZeroPubkey,
    /// Additional accounts required for transfer
    pub additional_accounts: [OptionalNonZeroPubkey; MAX_ADDITIONAL_ACCOUNTS],
}
impl Extension for TransferAuthorityMint {
    const TYPE: ExtensionType = ExtensionType::TransferAuthorityMint;
}

/// Transfer authority extension data for mints.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct TransferAuthorityAccount {
    /// Boolean for whether this account is for a mint that requires transfer authority cpi
    pub require_transfer_authority: PodBool,
}
impl Extension for TransferAuthorityAccount {
    const TYPE: ExtensionType = ExtensionType::TransferAuthorityAccount;
}

/// Call CPI to transfer authority to check if transfer is valid
pub fn transfer_authority_check<'info, S: BaseState, BSE: BaseStateWithExtensions<S>>(
    mint_state: &BSE,
    mint_info: &AccountInfo<'info>,
    source_account_info: &AccountInfo<'info>,
    destination_account_info: &AccountInfo<'info>,
    _amount: u64,
    account_info_iter: &mut Iter<AccountInfo<'info>>,
) -> ProgramResult {
    if let Some(transfer_authority_mint) = mint_state.get_extension::<TransferAuthorityMint>().ok()
    {
        if let Some(program_id) = Option::<Pubkey>::from(transfer_authority_mint.program_id) {
            let mut account_metas = Vec::new();
            account_metas.push(AccountMeta::new(*mint_info.key, false));
            account_metas.push(AccountMeta::new(*source_account_info.key, false));
            account_metas.push(AccountMeta::new(*destination_account_info.key, false));

            let mut acount_infos = Vec::new();
            acount_infos.push(mint_info.clone());
            acount_infos.push(source_account_info.clone());
            acount_infos.push(destination_account_info.clone());

            for additional_account in transfer_authority_mint.additional_accounts.iter() {
                if let Some(pubkey) = Option::<Pubkey>::from(*additional_account) {
                    account_metas.push(AccountMeta::new(pubkey, false));
                    acount_infos.push(next_account_info(account_info_iter)?.clone());
                }
            }
            invoke(
                &Instruction {
                    program_id,
                    data: [].to_vec(),
                    accounts: account_metas,
                },
                &acount_infos,
            )?;
        }
    }
    Ok(())
}
