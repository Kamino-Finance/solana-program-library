//! Program entrypoint

// `entrypoint` (the macro) is only used by the `entrypoint!` invocation below, which is compiled
// out under `no-entrypoint`; `entrypoint::ProgramResult` is always used.
#[allow(unused_imports)]
use {
    crate::{error::TokenError, processor::Processor},
    solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult,
        program_error::PrintProgramError, pubkey::Pubkey,
    },
};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Entrypoint of the token program.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if let Err(error) = Processor::process(program_id, accounts, instruction_data) {
        // catch the error so we can print it
        error.print::<TokenError>();
        return Err(error);
    }
    Ok(())
}
