//! Program state processor

use crate::{
    error::MarginPoolError,
    instruction::MarginPoolInstruction,
    state::{MarginPool, Position},
    swap::spl_token_swap_withdraw_single,
};
use num_traits::FromPrimitive;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    decode_error::DecodeError,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::{PrintProgramError, ProgramError},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
};
use spl_token_swap::state::SwapInfo;
use std::collections::HashSet;

/// Program state handler.
pub struct Processor {}
impl Processor {
    /// Unpacks a spl_token `Account`.
    pub fn unpack_uninitialized(_data: &[u8]) -> Result<MarginPool, MarginPoolError> {
        unimplemented!();
    }

    /// Unpacks a spl_token `Account`.
    pub fn unpack_token_swap(data: &[u8]) -> Result<SwapInfo, MarginPoolError> {
        SwapInfo::unpack(data).map_err(|_| MarginPoolError::ExpectedAccount)
    }

    /// Unpacks a spl_token `Account`.
    pub fn unpack_token_account(data: &[u8]) -> Result<spl_token::state::Account, MarginPoolError> {
        spl_token::state::Account::unpack(data).map_err(|_| MarginPoolError::ExpectedAccount)
    }

    /// Unpacks a spl_token `Mint`.
    pub fn unpack_mint(data: &[u8]) -> Result<spl_token::state::Mint, MarginPoolError> {
        spl_token::state::Mint::unpack(data).map_err(|_| MarginPoolError::ExpectedMint)
    }

    /// Calculates the authority id by generating a program address.
    pub fn authority_id(
        program_id: &Pubkey,
        my_info: &Pubkey,
        nonce: u8,
    ) -> Result<Pubkey, MarginPoolError> {
        Pubkey::create_program_address(&[&my_info.to_bytes()[..32], &[nonce]], program_id)
            .or(Err(MarginPoolError::InvalidProgramAddress))
    }

    /// Check if the authority id matches the key
    pub fn check_authority_id(
        key: &Pubkey,
        program_id: &Pubkey,
        my_info: &Pubkey,
        nonce: u8,
    ) -> Result<(), MarginPoolError> {
        if *key != Self::authority_id(program_id, my_info, nonce)? {
            return Err(MarginPoolError::InvalidProgramAddress.into());
        }
        Ok(())
    }

    /// Issue a spl_token `Burn` instruction.
    pub fn token_burn<'a>(
        me: &Pubkey,
        token_program: AccountInfo<'a>,
        burn_account: AccountInfo<'a>,
        mint: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        nonce: u8,
        amount: u64,
    ) -> Result<(), ProgramError> {
        let swap_bytes = me.to_bytes();
        let authority_signature_seeds = [&swap_bytes[..32], &[nonce]];
        let signers = &[&authority_signature_seeds[..]];

        let ix = spl_token::instruction::burn(
            token_program.key,
            burn_account.key,
            mint.key,
            authority.key,
            &[],
            amount,
        )?;

        invoke_signed(
            &ix,
            &[burn_account, mint, authority, token_program],
            signers,
        )
    }

    /// Issue a spl_token `MintTo` instruction.
    pub fn token_mint_to<'a>(
        me: &Pubkey,
        token_program: AccountInfo<'a>,
        mint: AccountInfo<'a>,
        destination: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        nonce: u8,
        amount: u64,
    ) -> Result<(), ProgramError> {
        let swap_bytes = me.to_bytes();
        let authority_signature_seeds = [&swap_bytes[..32], &[nonce]];
        let signers = &[&authority_signature_seeds[..]];
        let ix = spl_token::instruction::mint_to(
            token_program.key,
            mint.key,
            destination.key,
            authority.key,
            &[],
            amount,
        )?;

        invoke_signed(&ix, &[mint, destination, authority, token_program], signers)
    }

    /// Issue a spl_token `Transfer` instruction.
    pub fn token_transfer<'a>(
        me: &Pubkey,
        token_program: AccountInfo<'a>,
        source: AccountInfo<'a>,
        destination: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        nonce: u8,
        amount: u64,
    ) -> Result<(), ProgramError> {
        let swap_bytes = me.to_bytes();
        let authority_signature_seeds = [&swap_bytes[..32], &[nonce]];
        let signers = &[&authority_signature_seeds[..]];
        let ix = spl_token::instruction::transfer(
            token_program.key,
            source.key,
            destination.key,
            authority.key,
            &[],
            amount,
        )?;
        invoke_signed(
            &ix,
            &[source, destination, authority, token_program],
            signers,
        )
    }

    /// Issue a spl_token `Transfer` instruction.
    pub fn token_swap_withdraw<'a>(
        me: &Pubkey,
        token_swap_program: AccountInfo<'a>,
        token_swap_info: AccountInfo<'a>,
        token_swap_pool_info: AccountInfo<'a>,
        lp_source: AccountInfo<'a>,
        token_swap_a_source: AccountInfo<'a>,
        token_swap_b_source: AccountInfo<'a>,
        token_destination_a: AccountInfo<'a>,
        token_destination_b: AccountInfo<'a>,
        nonce: u8,
        num_pool: u64,
        min_a: u64,
        min_b: u64,
    ) -> Result<(), ProgramError> {
        unimplemented!();
    }

    /// TODO:
    /// 1. Add fees to parameters
    /// 2.
    /// Processes an [Initialize](enum.Instruction.html).
    pub fn process_initialize(
        program_id: &Pubkey,
        nonce: u8,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let margin_pool_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let token_swap_info = next_account_info(account_info_iter)?;
        let token_lp_info = next_account_info(account_info_iter)?;
        let token_a_info = next_account_info(account_info_iter)?;
        let token_b_info = next_account_info(account_info_iter)?;
        let pool_mint_info = next_account_info(account_info_iter)?;
        let token_program_info = next_account_info(account_info_iter)?;
        let token_swap_program_info = next_account_info(account_info_iter)?;

        let _margin_pool = Self::unpack_uninitialized(&margin_pool_info.data.borrow())?;
        Self::check_authority_id(authority_info.key, program_id, margin_pool_info.key, nonce)?;

        let token_swap = Self::unpack_token_swap(&token_swap_info.data.borrow())?;
        let token_lp = Self::unpack_token_account(&token_lp_info.data.borrow())?;
        let token_a = Self::unpack_token_account(&token_a_info.data.borrow())?;
        let token_b = Self::unpack_token_account(&token_b_info.data.borrow())?;
        let pool_mint = Self::unpack_mint(&pool_mint_info.data.borrow())?;

        if *authority_info.key != token_a.owner {
            return Err(MarginPoolError::InvalidOwner.into());
        }
        if *authority_info.key != token_b.owner {
            return Err(MarginPoolError::InvalidOwner.into());
        }
        if COption::Some(*authority_info.key) != pool_mint.mint_authority {
            return Err(MarginPoolError::InvalidOwner.into());
        }
        let mints: HashSet<Pubkey> = [
            token_a.mint,
            token_b.mint,
            token_lp.mint,
            *pool_mint_info.key,
        ]
        .iter()
        .cloned()
        .collect();
        if mints.len() != 4 {
            return Err(MarginPoolError::RepeatedMint.into());
        }
        if token_b.amount != 0 {
            return Err(MarginPoolError::InvalidSupply.into());
        }
        if token_a.amount != 0 {
            return Err(MarginPoolError::InvalidSupply.into());
        }
        if token_a.delegate.is_some() {
            return Err(MarginPoolError::InvalidDelegate.into());
        }
        if token_b.delegate.is_some() {
            return Err(MarginPoolError::InvalidDelegate.into());
        }
        if token_a.close_authority.is_some() {
            return Err(MarginPoolError::InvalidCloseAuthority.into());
        }
        if token_b.close_authority.is_some() {
            return Err(MarginPoolError::InvalidCloseAuthority.into());
        }
        if token_swap.pool_mint != *pool_mint_info.key {
            return Err(MarginPoolError::InvalidMint.into());
        }

        if pool_mint.supply != 0 {
            return Err(MarginPoolError::InvalidSupply.into());
        }
        if pool_mint.freeze_authority.is_some() {
            return Err(MarginPoolError::InvalidFreezeAuthority.into());
        }

        let obj = MarginPool {
            version: 1,
            nonce,
            token_swap: *token_swap_info.key,
            token_program_id: *token_program_info.key,
            token_swap_program_id: *token_swap_program_info.key,
            token_lp: *token_lp_info.key,
            token_a: *token_a_info.key,
            token_b: *token_b_info.key,
            pool_mint: *pool_mint_info.key,
            token_a_mint: token_a.mint,
            token_b_mint: token_b.mint,
            token_lp_mint: token_lp.mint,

            /// fees
            /// TODO: initalize
            position_fee_numerator: 0,
            position_fee_denominator: 0,
            owner_withdraw_fee_numerator: 0,
            owner_withdraw_fee_denominator: 0,
            owner_position_fee_numerator: 0,
            owner_position_fee_denominator: 0,
            host_position_fee_numerator: 0,
            host_position_fee_denominator: 0,
        };
        MarginPool::pack(obj, &mut margin_pool_info.data.borrow_mut())?;
        Ok(())
    }
    fn token_swap_price(swap_info: &SwapInfo, source: &Pubkey) {
        unimplemented!();
    }
    /// Processes an [Swap](enum.Instruction.html).
    pub fn process_fund_position(
        program_id: &Pubkey,
        amount_in: u64,
        min_amount_out: u64,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();

        let margin_pool_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let user_transfer_info = next_account_info(account_info_iter)?;
        let token_swap_info = next_account_info(account_info_iter)?;
        let position_info = next_account_info(account_info_iter)?;
        let position_mint_info = next_account_info(account_info_iter)?;
        let token_source_info = next_account_info(account_info_iter)?;
        let token_lp_info = next_account_info(account_info_iter)?;
        let token_dest_info = next_account_info(account_info_iter)?;
        let token_program_info = next_account_info(account_info_iter)?;
        let token_swap_program_info = next_account_info(account_info_iter)?;

        let margin_pool = MarginPool::unpack(&margin_pool_info.data.borrow())?;
        let mut position = Position::unpack(&position_info.data.borrow())?;
        Self::check_authority_id(
            authority_info.key,
            program_id,
            margin_pool_info.key,
            margin_pool.nonce,
        )?;
        let checks = [
            margin_pool.token_swap != *token_swap_info.key,
            margin_pool.token_program_id != *token_program_info.key,
            margin_pool.token_swap_program_id != *token_swap_program_info.key,
            margin_pool.token_a != *token_source_info.key
                || margin_pool.token_b != *token_source_info.key,
            margin_pool.token_a != *token_dest_info.key
                || margin_pool.token_b != *token_dest_info.key,
            *token_source_info.key != *token_dest_info.key,
            margin_pool.token_lp != *token_lp_info.key,
            position.mint == Pubkey::default() || position.mint == *position_mint_info.key,
        ];

        if !checks.all() {
            return Err(MarginPoolError::InvalidInput.into());
        }

        if position.mint == Pubkey::default() {
            position.mint = *position_mint_info.key;
            let mint = Self::unpack_mint(&position_mint_info.data.borrow())?;
            if COption::Some(*authority_info.key) != mint.mint_authority {
                return Err(MarginPoolError::InvalidOwner.into());
            }
            if mint.supply != 0 {
                return Err(MarginPoolError::InvalidSupply.into());
            }
        }

        let source_account = Self::unpack_token_account(&token_source_info.data.borrow())?;
        let swap_info = Self::unpack_token_swap(&token_swap_info.data.borrow())?;
        let p1 = Self::token_swap_price(&swap_info, &source_account.mint);
        let (a_out, b_out) = if source_account.mint == swap_info.token_a_mint {
            (min_amount_out, min_amount_out.checked_mul(p1)?)
        } else {
            (min_amount_out.checked_div(p1)?, min_amount_out)
        };

        // Token swap program implements now withdraw and swap as atomic operation
        spl_token_swap_withdraw_single(
            token_swap_program_info.key,
            token_program_info.key,
            token_swap_info.key,
            authority_info.key,
            user_transfer_info.key,
            token_source_info.key,
            token_source_info.key,
            token_dest_info.key,
        );

        let swap_info = Self::unpack_token_swap(token_swap_info.data.borrow())?;
        let p2 = Self::token_swap_price(&swap_info, source_account.mint);

        let needed: u64 = u128::try_from(min_amount_out)
            .unwrap()
            .checked_mul(u128::try_from(p1).unwrap())?
            .checked_div(u128::try_from(p2).unwrap())?
            .to_u64()?;

        if amount_in < needed {
            msg!("Insuficient funds");
            return Err(MarginPoolError::InsufficeintFunds.into());
        }
        position.charge_yield();
        position.colleteral_amount += amount_in;
        position.size += min_amount_out;

        Self::token_transfer(
            margin_pool_info.key,
            token_program_info.clone(),
            position_mint_info.clone(),
            swap_source_info.clone(),
            authority_info.clone(),
            token_swap.nonce,
            min_amount_out,
        )?;

        Position::pack(position, &mut position_info.data.borrow_mut())?;
        Ok(())
    }

    // /// Processes an [Deposit](enum.Instruction.html).
    // pub fn process_deposit(
    //     program_id: &Pubkey,
    //     pool_token_amount: u64,
    //     maximum_token_a_amount: u64,
    //     maximum_token_b_amount: u64,
    //     accounts: &[AccountInfo],
    // ) -> ProgramResult {
    //     let account_info_iter = &mut accounts.iter();
    //     let margin_pool_info = next_account_info(account_info_iter)?;
    //     let authority_info = next_account_info(account_info_iter)?;
    //     let source_a_info = next_account_info(account_info_iter)?;
    //     let source_b_info = next_account_info(account_info_iter)?;
    //     let token_a_info = next_account_info(account_info_iter)?;
    //     let token_b_info = next_account_info(account_info_iter)?;
    //     let pool_mint_info = next_account_info(account_info_iter)?;
    //     let dest_info = next_account_info(account_info_iter)?;
    //     let token_program_info = next_account_info(account_info_iter)?;

    //     let token_swap = MarginPool::unpack(&margin_pool_info.data.borrow())?;
    //     if *authority_info.key != Self::authority_id(program_id, margin_pool_info.key, token_swap.nonce)? {
    //         return Err(MarginPoolError::InvalidProgramAddress.into());
    //     }
    //     if *token_a_info.key != token_swap.token_a {
    //         return Err(MarginPoolError::IncorrectSwapAccount.into());
    //     }
    //     if *token_b_info.key != token_swap.token_b {
    //         return Err(MarginPoolError::IncorrectSwapAccount.into());
    //     }
    //     if *pool_mint_info.key != token_swap.pool_mint {
    //         return Err(MarginPoolError::IncorrectPoolMint.into());
    //     }
    //     if token_a_info.key == source_a_info.key {
    //         return Err(MarginPoolError::InvalidInput.into());
    //     }
    //     if token_b_info.key == source_b_info.key {
    //         return Err(MarginPoolError::InvalidInput.into());
    //     }

    //     let token_a = Self::unpack_token_account(&token_a_info.data.borrow())?;
    //     let token_b = Self::unpack_token_account(&token_b_info.data.borrow())?;
    //     let pool_mint = Self::unpack_mint(&pool_mint_info.data.borrow())?;
    //     let pool_token_amount = to_u128(pool_token_amount)?;
    //     let pool_mint_supply = to_u128(pool_mint.supply)?;

    //     let calculator = token_swap.swap_curve.calculator;

    //     let a_amount = calculator
    //         .pool_tokens_to_trading_tokens(
    //             pool_token_amount,
    //             pool_mint_supply,
    //             to_u128(token_a.amount)?,
    //         )
    //         .ok_or(MarginPoolError::ZeroTradingTokens)?;
    //     if a_amount > to_u128(maximum_token_a_amount)? {
    //         return Err(MarginPoolError::ExceededSlippage.into());
    //     }
    //     let b_amount = calculator
    //         .pool_tokens_to_trading_tokens(
    //             pool_token_amount,
    //             pool_mint_supply,
    //             to_u128(token_b.amount)?,
    //         )
    //         .ok_or(MarginPoolError::ZeroTradingTokens)?;
    //     if b_amount > to_u128(maximum_token_b_amount)? {
    //         return Err(MarginPoolError::ExceededSlippage.into());
    //     }

    //     Self::token_transfer(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         source_a_info.clone(),
    //         token_a_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         to_u64(a_amount)?,
    //     )?;
    //     Self::token_transfer(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         source_b_info.clone(),
    //         token_b_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         to_u64(b_amount)?,
    //     )?;
    //     Self::token_mint_to(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         pool_mint_info.clone(),
    //         dest_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         to_u64(pool_token_amount)?,
    //     )?;

    //     Ok(())
    // }

    // /// Processes an [Withdraw](enum.Instruction.html).
    // pub fn process_withdraw(
    //     program_id: &Pubkey,
    //     pool_token_amount: u64,
    //     minimum_token_a_amount: u64,
    //     minimum_token_b_amount: u64,
    //     accounts: &[AccountInfo],
    // ) -> ProgramResult {
    //     let account_info_iter = &mut accounts.iter();
    //     let margin_pool_info = next_account_info(account_info_iter)?;
    //     let authority_info = next_account_info(account_info_iter)?;
    //     let pool_mint_info = next_account_info(account_info_iter)?;
    //     let source_info = next_account_info(account_info_iter)?;
    //     let token_a_info = next_account_info(account_info_iter)?;
    //     let token_b_info = next_account_info(account_info_iter)?;
    //     let dest_token_a_info = next_account_info(account_info_iter)?;
    //     let dest_token_b_info = next_account_info(account_info_iter)?;
    //     let pool_fee_account_info = next_account_info(account_info_iter)?;
    //     let token_program_info = next_account_info(account_info_iter)?;

    //     let token_swap = MarginPool::unpack(&margin_pool_info.data.borrow())?;
    //     if *authority_info.key != Self::authority_id(program_id, margin_pool_info.key, token_swap.nonce)? {
    //         return Err(MarginPoolError::InvalidProgramAddress.into());
    //     }
    //     if *token_a_info.key != token_swap.token_a {
    //         return Err(MarginPoolError::IncorrectSwapAccount.into());
    //     }
    //     if *token_b_info.key != token_swap.token_b {
    //         return Err(MarginPoolError::IncorrectSwapAccount.into());
    //     }
    //     if *pool_mint_info.key != token_swap.pool_mint {
    //         return Err(MarginPoolError::IncorrectPoolMint.into());
    //     }
    //     if *pool_fee_account_info.key != token_swap.pool_fee_account {
    //         return Err(MarginPoolError::IncorrectFeeAccount.into());
    //     }
    //     if token_a_info.key == dest_token_a_info.key {
    //         return Err(MarginPoolError::InvalidInput.into());
    //     }
    //     if token_b_info.key == dest_token_b_info.key {
    //         return Err(MarginPoolError::InvalidInput.into());
    //     }

    //     let token_a = Self::unpack_token_account(&token_a_info.data.borrow())?;
    //     let token_b = Self::unpack_token_account(&token_b_info.data.borrow())?;
    //     let pool_mint = Self::unpack_mint(&pool_mint_info.data.borrow())?;

    //     let calculator = token_swap.swap_curve.calculator;

    //     let withdraw_fee: u128 = if *pool_fee_account_info.key == *source_info.key {
    //         // withdrawing from the fee account, don't assess withdraw fee
    //         0
    //     } else {
    //         calculator
    //             .owner_withdraw_fee(to_u128(pool_token_amount)?)
    //             .ok_or(MarginPoolError::FeeCalculationFailure)?
    //     };
    //     let pool_token_amount = to_u128(pool_token_amount)?
    //         .checked_sub(withdraw_fee)
    //         .ok_or(MarginPoolError::CalculationFailure)?;

    //     let a_amount = calculator
    //         .pool_tokens_to_trading_tokens(
    //             pool_token_amount,
    //             to_u128(pool_mint.supply)?,
    //             to_u128(token_a.amount)?,
    //         )
    //         .ok_or(MarginPoolError::ZeroTradingTokens)?;
    //     if a_amount < to_u128(minimum_token_a_amount)? {
    //         return Err(MarginPoolError::ExceededSlippage.into());
    //     }
    //     let b_amount = calculator
    //         .pool_tokens_to_trading_tokens(
    //             pool_token_amount,
    //             to_u128(pool_mint.supply)?,
    //             to_u128(token_b.amount)?,
    //         )
    //         .ok_or(MarginPoolError::ZeroTradingTokens)?;
    //     let b_amount = to_u64(b_amount)?;
    //     if b_amount < minimum_token_b_amount {
    //         return Err(MarginPoolError::ExceededSlippage.into());
    //     }

    //     Self::token_transfer(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         token_a_info.clone(),
    //         dest_token_a_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         to_u64(a_amount)?,
    //     )?;
    //     Self::token_transfer(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         token_b_info.clone(),
    //         dest_token_b_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         b_amount,
    //     )?;
    //     if withdraw_fee > 0 {
    //         Self::token_transfer(
    //             margin_pool_info.key,
    //             token_program_info.clone(),
    //             source_info.clone(),
    //             pool_fee_account_info.clone(),
    //             authority_info.clone(),
    //             token_swap.nonce,
    //             to_u64(withdraw_fee)?,
    //         )?;
    //     }
    //     Self::token_burn(
    //         margin_pool_info.key,
    //         token_program_info.clone(),
    //         source_info.clone(),
    //         pool_mint_info.clone(),
    //         authority_info.clone(),
    //         token_swap.nonce,
    //         to_u64(pool_token_amount)?,
    //     )?;
    //     Ok(())
    // }

    /// Processes an [Instruction](enum.Instruction.html).
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
        let instruction = MarginPoolInstruction::unpack(input)?;
        match instruction {
            MarginPoolInstruction::Initialize { nonce } => {
                msg!("Instruction: Init");
                Self::process_initialize(program_id, nonce, accounts)
            }
            MarginPoolInstruction::FundPosition {
                amount_in,
                minimum_amount_out,
            } => {
                msg!("Instruction: Fund Position");
                Self::process_fund_position(program_id, amount_in, minimum_amount_out, accounts)
            }
            MarginPoolInstruction::ReducePosition { .. } => unimplemented!(),
            MarginPoolInstruction::Deposit { .. } => unimplemented!(),
            MarginPoolInstruction::Withdraw { .. } => unimplemented!(),
            MarginPoolInstruction::Liquidate => unimplemented!(),
        }
    }
}

impl PrintProgramError for MarginPoolError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        match self {
            MarginPoolError::AlreadyInUse => msg!("Error: Swap account already in use"),
            MarginPoolError::InvalidProgramAddress => {
                msg!("Error: Invalid program address generated from nonce and key")
            }
            MarginPoolError::InvalidOwner => {
                msg!("Error: The input account owner is not the program address")
            }
            MarginPoolError::InvalidOutputOwner => {
                msg!("Error: Output pool account owner cannot be the program address")
            }
            MarginPoolError::ExpectedMint => {
                msg!("Error: Deserialized account is not an SPL Token mint")
            }
            MarginPoolError::ExpectedAccount => {
                msg!("Error: Deserialized account is not an SPL Token account")
            }
            MarginPoolError::EmptySupply => msg!("Error: Input token account empty"),
            MarginPoolError::InvalidSupply => msg!("Error: Pool token mint has a non-zero supply"),
            MarginPoolError::RepeatedMint => {
                msg!("Error: Swap input token accounts have the same mint")
            }
            MarginPoolError::InvalidDelegate => msg!("Error: Token account has a delegate"),
            MarginPoolError::InvalidInput => msg!("Error: InvalidInput"),
            MarginPoolError::IncorrectSwapAccount => {
                msg!("Error: Address of the provided swap token account is incorrect")
            }
            MarginPoolError::IncorrectPoolMint => {
                msg!("Error: Address of the provided pool token mint is incorrect")
            }
            MarginPoolError::InvalidOutput => msg!("Error: InvalidOutput"),
            MarginPoolError::CalculationFailure => msg!("Error: CalculationFailure"),
            MarginPoolError::InvalidInstruction => msg!("Error: InvalidInstruction"),
            MarginPoolError::ExceededSlippage => {
                msg!("Error: Swap instruction exceeds desired slippage limit")
            }
            MarginPoolError::InvalidCloseAuthority => {
                msg!("Error: Token account has a close authority")
            }
            MarginPoolError::InvalidFreezeAuthority => {
                msg!("Error: Pool token mint has a freeze authority")
            }
            MarginPoolError::IncorrectFeeAccount => msg!("Error: Pool fee token account incorrect"),
            MarginPoolError::ZeroTradingTokens => {
                msg!("Error: Given pool token amount results in zero trading tokens")
            }
            MarginPoolError::FeeCalculationFailure => msg!(
                "Error: The fee calculation failed due to overflow, underflow, or unexpected 0"
            ),
            MarginPoolError::ConversionFailure => msg!("Error: Conversion to or from u64 failed."),
            MarginPoolError::InvalidFee => {
                msg!("Error: The provided fee does not match the program owner's constraints")
            }
            MarginPoolError::InvalidMint => {
                msg!("Error: Swap input token accounts have the same mint")
            }
            MarginPoolError::InsufficeintFunds => msg!("Error: Margin Pool insufficient funds"),
            MarginPoolError::SwapFaild => msg!("Error: Margin Pool swap faild"),
        }
    }
}
