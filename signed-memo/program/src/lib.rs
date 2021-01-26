#![deny(missing_docs)]

//! A program that accepts a string of encoded characters and verifies that it parses,
//! while verifying and logging signers. Currently handles UTF-8 characters.

mod entrypoint;
pub mod processor;

// Export current sdk types for downstream users building with a different sdk version
pub use solana_program;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

solana_program::declare_id!("MemoS11111111111111111111111111111111111111");

/// Submit a signed memo
///
/// Accounts expected by this instruction:
///
///   0. ..0+N. `[signer]` Expected signers; if zero provided, instruction will be processed as a
///     normal, unsigned spl-memo
///
pub fn signed_memo(memo: &[u8], signer_pubkeys: &[&Pubkey]) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: signer_pubkeys
            .iter()
            .map(|&pubkey| AccountMeta::new_readonly(*pubkey, true))
            .collect(),
        data: memo.to_vec(),
    }
}
