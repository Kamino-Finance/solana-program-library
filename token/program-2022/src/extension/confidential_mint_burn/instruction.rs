#[cfg(not(target_os = "solana"))]
use crate::{
    error::TokenError,
    extension::confidential_transfer::processor::verify_and_split_deposit_amount,
    proof::ProofLocation,
};
#[cfg(feature = "serde-traits")]
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "solana"))]
use solana_zk_token_sdk::instruction::{
    BatchedGroupedCiphertext2HandlesValidityProofData, BatchedRangeProofU64Data,
};
#[cfg(not(target_os = "solana"))]
use solana_zk_token_sdk::{
    encryption::{elgamal::ElGamalPubkey, pedersen::PedersenOpening},
    zk_token_proof_instruction::{verify_batched_verify_range_proof_u64, ProofInstruction},
};
use {
    crate::extension::confidential_transfer::DecryptableBalance,
    bytemuck::{Pod, Zeroable},
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_program::pubkey::Pubkey,
    solana_zk_token_sdk::zk_token_elgamal::pod::ElGamalCiphertext,
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        check_program_account,
        extension::confidential_transfer::instruction::TransferSplitContextStateAccounts,
        instruction::{encode_instruction, TokenInstruction},
    },
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        sysvar,
    },
};

/// Confidential Transfer extension instructions
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum ConfidentialMintBurnInstruction {
    /// Initializes confidential mints and burns for a mint.
    ///
    /// The `ConfidentialMintBurnInstruction::InitializeMint` instruction
    /// requires no signers and MUST be included within the same Transaction
    /// as `TokenInstruction::InitializeMint`. Otherwise another party can
    /// initialize the configuration.
    ///
    /// The instruction fails if the `TokenInstruction::InitializeMint`
    /// instruction has already executed for the mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The SPL Token mint.
    ///
    /// Data expected by this instruction:
    ///   `InitializeMintData`
    InitializeMint,
    /// Updates mint-authority for confidential-mint-burn mint.
    UpdateMint,
    /// Mints confidential tokens to
    ConfidentialMint,
    /// Removes whitelist designation for specific address
    ConfidentialBurn,
}

/// Data expected by `WhitelistedTransferInstruction::InitializeMint`
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeMintData {
    /// Authority to modify the `WhitelistTransferMint` configuration and to
    /// approve new accounts.
    pub authority: Pubkey,
}

/// Data expected by `ConfidentialTransferInstruction::UpdateMint`
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct UpdateMintData {
    /// Determines if newly configured accounts must be approved by the
    /// `authority` before they may be used by the user.
    pub new_authority: Pubkey,
}

/// Data expected by `ConfidentialMintBurnInstruction::ConfidentialMint`
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct MintInstructionData {
    /// low 16 bits of encrypted amount to be minted, exposes mint amounts
    /// to the auditor through the data received via `get_transaction`
    pub audit_amount_lo: ElGamalCiphertext,
    /// high 48 bits of encrypted amount to be minted, exposes mint amounts
    /// to the auditor through the data received via `get_transaction`
    pub audit_amount_hi: ElGamalCiphertext,
    /// Relative location of the `ProofInstruction::VerifyBatchedRangeProofU64`
    /// instruction to the `ConfidentialMint` instruction in the
    /// transaction. The
    /// `ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity`
    /// has to always be at the instruction directly after the range proof one.
    pub proof_instruction_offset: i8,
}

/// Data expected by `ConfidentialMintBurnInstruction::ConfidentialBurn`
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct BurnInstructionData {
    /// The new source decryptable balance if the transfer succeeds
    #[cfg_attr(feature = "serde-traits", serde(with = "aeciphertext_fromstr"))]
    pub new_decryptable_available_balance: DecryptableBalance,
    /// low 16 bits of encrypted amount to be minted
    pub auditor_lo: ElGamalCiphertext,
    /// high 48 bits of encrypted amount to be minted
    pub auditor_hi: ElGamalCiphertext,
    /// Relative location of the
    /// `ProofInstruction::VerifyCiphertextCommitmentEquality` instruction
    /// to the `ConfidentialBurn` instruction in the transaction. The
    /// `ProofInstruction::VerifyBatchedRangeProofU128` has to always be at
    /// the instruction directly after the equality proof one,
    /// with the `ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity`
    /// following after that.
    pub proof_instruction_offset: i8,
}

/// Create a `InitializeMint` instruction
#[cfg(not(target_os = "solana"))]
pub fn initialize_mint(
    token_program_id: &Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let accounts = vec![AccountMeta::new(*mint, false)];

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialMintBurnExtension,
        ConfidentialMintBurnInstruction::InitializeMint,
        &InitializeMintData { authority },
    ))
}

/// Create a `UpdateMint` instruction
#[cfg(not(target_os = "solana"))]
pub fn update_mint(
    token_program_id: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    multisig_signers: &[&Pubkey],
    new_authority: Pubkey,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new_readonly(*authority, multisig_signers.is_empty()),
    ];
    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }
    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialMintBurnExtension,
        ConfidentialMintBurnInstruction::UpdateMint,
        &UpdateMintData { new_authority },
    ))
}

/// Create a `ConfidentialMint` instruction
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "solana"))]
pub fn confidential_mint(
    token_program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    auditor_elgamal_pubkey: Option<ElGamalPubkey>,
    authority: &Pubkey,
    multisig_signers: &[&Pubkey],
    range_proof_location: ProofLocation<'_, BatchedRangeProofU64Data>,
    ciphertext_validity_proof_location: ProofLocation<
        '_,
        BatchedGroupedCiphertext2HandlesValidityProofData,
    >,
    pedersen_openings: &(PedersenOpening, PedersenOpening),
) -> Result<Vec<Instruction>, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(*authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    let (amount_lo, amount_hi) = verify_and_split_deposit_amount(amount)?;
    let auditor_elgamal_pubkey = auditor_elgamal_pubkey.unwrap_or_default();
    let audit_amount_lo = auditor_elgamal_pubkey.encrypt_with(amount_lo, &pedersen_openings.0);
    let audit_amount_hi = auditor_elgamal_pubkey.encrypt_with(amount_hi, &pedersen_openings.1);

    let proof_instruction_offset = match range_proof_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };
    match ciphertext_validity_proof_location {
        ProofLocation::InstructionOffset(_, _) => {
            // already pushed instruction introspection sysvar previously
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
        }
    }

    let mut instrs = vec![encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialMintBurnExtension,
        ConfidentialMintBurnInstruction::ConfidentialMint,
        &MintInstructionData {
            audit_amount_lo: audit_amount_lo.into(),
            audit_amount_hi: audit_amount_hi.into(),
            proof_instruction_offset,
        },
    )];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, range_proof_data) =
        range_proof_location
    {
        if let ProofLocation::InstructionOffset(_, ciphertext_validity_proof_data) =
            ciphertext_validity_proof_location
        {
            // This constructor appends the proof instruction right after the
            // `ConfidentialMint` instruction. This means that the proof instruction
            // offset must be always be 1.
            let proof_instruction_offset: i8 = proof_instruction_offset.into();
            if proof_instruction_offset != 1 {
                return Err(TokenError::InvalidProofInstructionOffset.into());
            }
            instrs.push(verify_batched_verify_range_proof_u64(
                None,
                range_proof_data,
            ));
            instrs.push(
                ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
                    .encode_verify_proof(None, ciphertext_validity_proof_data),
            );
        } else {
            // both proofs have to either be context state or instruction offset
            return Err(ProgramError::InvalidArgument);
        }
    };

    Ok(instrs)
}

/// Create a `ConfidentialBurn` instruction
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "solana"))]
pub fn confidential_burn_with_split_proofs(
    token_program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    auditor_pubkey: Option<ElGamalPubkey>,
    burn_amount: u64,
    new_decryptable_available_balance: DecryptableBalance,
    context_accounts: TransferSplitContextStateAccounts,
    authority: &Pubkey,
    multisig_signers: &[&Pubkey],
    pedersen_openings: &(PedersenOpening, PedersenOpening),
) -> Result<Vec<Instruction>, ProgramError> {
    Ok(vec![inner_confidential_burn_with_split_proofs(
        token_program_id,
        token_account,
        mint,
        auditor_pubkey,
        burn_amount,
        new_decryptable_available_balance,
        context_accounts,
        authority,
        multisig_signers,
        pedersen_openings,
    )?])
}

/// Create a inner `ConfidentialBurn` instruction
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "solana"))]
pub fn inner_confidential_burn_with_split_proofs(
    token_program_id: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    auditor_pubkey: Option<ElGamalPubkey>,
    burn_amount: u64,
    new_decryptable_available_balance: DecryptableBalance,
    context_accounts: TransferSplitContextStateAccounts,
    authority: &Pubkey,
    multisig_signers: &[&Pubkey],
    pedersen_openings: &(PedersenOpening, PedersenOpening),
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
    ];

    if context_accounts
        .close_split_context_state_accounts
        .is_some()
    {
        println!("close split context accounts on execution not implemented for confidential burn");
        return Err(ProgramError::InvalidInstructionData);
    }

    accounts.push(AccountMeta::new_readonly(
        *context_accounts.equality_proof,
        false,
    ));
    accounts.push(AccountMeta::new_readonly(
        *context_accounts.ciphertext_validity_proof,
        false,
    ));
    accounts.push(AccountMeta::new_readonly(
        *context_accounts.range_proof,
        false,
    ));

    accounts.push(AccountMeta::new_readonly(
        *authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    let (burn_hi, burn_lo) = if let Some(apk) = auditor_pubkey {
        let (opening_hi, opening_lo) = pedersen_openings;
        let (amount_lo, amount_hi) = verify_and_split_deposit_amount(burn_amount)?;
        let burn_hi = apk.encrypt_with(amount_hi, opening_hi);
        let burn_lo = apk.encrypt_with(amount_lo, opening_lo);
        (burn_hi.into(), burn_lo.into())
    } else {
        (ElGamalCiphertext::zeroed(), ElGamalCiphertext::zeroed())
    };

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialMintBurnExtension,
        ConfidentialMintBurnInstruction::ConfidentialBurn,
        &BurnInstructionData {
            new_decryptable_available_balance,
            auditor_hi: burn_hi,
            auditor_lo: burn_lo,
            proof_instruction_offset: 0,
        },
    ))
}
