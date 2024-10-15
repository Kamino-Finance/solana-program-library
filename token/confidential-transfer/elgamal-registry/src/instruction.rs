use {
    crate::id,
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::{Pubkey, PUBKEY_BYTES},
        sysvar,
    },
    solana_zk_sdk::zk_elgamal_proof_program::{
        instruction::ProofInstruction, proof_data::PubkeyValidityProofData,
    },
    spl_token_confidential_transfer_proof_extraction::{ProofData, ProofLocation},
};

#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum RegistryInstruction {
    /// Initialize an ElGamal public key registry.
    ///
    /// 0. `[writable]` The account to initialize
    /// 1. `[]` Instructions sysvar if `VerifyPubkeyValidity` is included in the
    ///    same transaction or context state account if `VerifyPubkeyValidity`
    ///    is pre-verified into a context state account.
    /// 2. `[]` (Optional) Record account if the accompanying proof is to be
    ///    read from a record account.
    CreateRegistry {
        /// The owner of the ElGamal registry account
        owner: Pubkey,
        /// Relative location of the `ProofInstruction::PubkeyValidityProof`
        /// instruction to the `CreateElGamalRegistry` instruction in the
        /// transaction. If the offset is `0`, then use a context state account
        /// for the proof.
        proof_instruction_offset: i8,
    },
    /// Update an ElGamal public key registry with a new ElGamal public key.
    ///
    /// 0. `[writable]` The account to initialize
    /// 1. `[signer]` The owner of the ElGamal public key registry
    /// 2. `[]` Instructions sysvar if `VerifyPubkeyValidity` is included in the
    ///    same transaction or context state account if `VerifyPubkeyValidity`
    ///    is pre-verified into a context state account.
    /// 3. `[]` (Optional) Record account if the accompanying proof is to be
    ///    read from a record account.
    UpdateRegistry {
        /// Relative location of the `ProofInstruction::PubkeyValidityProof`
        /// instruction to the `UpdateElGamalRegistry` instruction in the
        /// transaction. If the offset is `0`, then use a context state account
        /// for the proof.
        proof_instruction_offset: i8,
    },
}

impl RegistryInstruction {
    /// Unpacks a byte buffer into a `RegistryInstruction`
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        Ok(match tag {
            0 => {
                let owner = rest
                    .get(..PUBKEY_BYTES)
                    .and_then(|x| Pubkey::try_from(x).ok())
                    .ok_or(ProgramError::InvalidInstructionData)?;
                let proof_instruction_offset =
                    *rest.first().ok_or(ProgramError::InvalidInstructionData)?;
                Self::CreateRegistry {
                    owner,
                    proof_instruction_offset: proof_instruction_offset as i8,
                }
            }
            2 => {
                let proof_instruction_offset =
                    *rest.first().ok_or(ProgramError::InvalidInstructionData)?;
                Self::UpdateRegistry {
                    proof_instruction_offset: proof_instruction_offset as i8,
                }
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }

    /// Packs a `RegistryInstruction` into a byte buffer.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = vec![];
        match self {
            Self::CreateRegistry {
                owner,
                proof_instruction_offset,
            } => {
                buf.push(0);
                buf.extend_from_slice(owner.as_ref());
                buf.extend_from_slice(&proof_instruction_offset.to_le_bytes());
            }
            Self::UpdateRegistry {
                proof_instruction_offset,
            } => {
                buf.push(1);
                buf.extend_from_slice(&proof_instruction_offset.to_le_bytes());
            }
        };
        buf
    }
}

/// Create a `RegistryInstruction::CreateRegistry` instruction
pub fn create_registry(
    registry_account: &Pubkey,
    owner: &Pubkey,
    proof_location: ProofLocation<PubkeyValidityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut accounts = vec![AccountMeta::new(*registry_account, false)];
    let proof_instruction_offset = proof_instruction_offset(&mut accounts, proof_location);

    let registry_instruction = Instruction {
        program_id: id(),
        accounts,
        data: RegistryInstruction::CreateRegistry {
            owner: *owner,
            proof_instruction_offset,
        }
        .pack(),
    };
    append_zk_elgamal_proof(registry_instruction, proof_location)
}

/// Create a `RegistryInstruction::UpdateRegistry` instruction
pub fn update_registry(
    registry_account: &Pubkey,
    owner: &Pubkey,
    proof_location: ProofLocation<PubkeyValidityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut accounts = vec![
        AccountMeta::new(*registry_account, false),
        AccountMeta::new_readonly(*owner, true),
    ];
    let proof_instruction_offset = proof_instruction_offset(&mut accounts, proof_location);

    let registry_instruction = Instruction {
        program_id: id(),
        accounts,
        data: RegistryInstruction::UpdateRegistry {
            proof_instruction_offset,
        }
        .pack(),
    };
    append_zk_elgamal_proof(registry_instruction, proof_location)
}

/// Takes a `ProofLocation`, updates the list of accounts, and returns a
/// suitable proof location
fn proof_instruction_offset(
    accounts: &mut Vec<AccountMeta>,
    proof_location: ProofLocation<PubkeyValidityProofData>,
) -> i8 {
    match proof_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            if let ProofData::RecordAccount(record_address, _) = proof_data {
                accounts.push(AccountMeta::new_readonly(*record_address, false));
            }
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    }
}

/// Takes a `RegistryInstruction` and appends the pubkey validity proof
/// instruction
fn append_zk_elgamal_proof(
    registry_instruction: Instruction,
    proof_data_location: ProofLocation<PubkeyValidityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![registry_instruction];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(ProgramError::InvalidArgument);
        }
        match proof_data {
            ProofData::InstructionData(data) => instructions
                .push(ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, data)),
            ProofData::RecordAccount(address, offset) => instructions.push(
                ProofInstruction::VerifyPubkeyValidity
                    .encode_verify_proof_from_account(None, address, offset),
            ),
        }
    }
    Ok(instructions)
}
