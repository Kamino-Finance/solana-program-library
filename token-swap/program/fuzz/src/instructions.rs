use spl_token_swap_fuzz::{
    native_account_data::NativeAccountData, native_token::get_token_balance,
    native_token_swap::NativeTokenSwap,
};

use spl_token_swap::{
    curve::{
        base::{CurveType, SwapCurve},
        constant_product::ConstantProductCurve,
        fees::Fees,
    },
    error::SwapError,
    instruction::{DepositAllTokenTypes, Swap, WithdrawAllTokenTypes},
};

use spl_token::error::TokenError;

use honggfuzz::fuzz;

use arbitrary::Arbitrary;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Arbitrary, Clone)]
enum FuzzInstruction {
    Swap {
        token_a_id: AccountId,
        token_b_id: AccountId,
        trade_direction: TradeDirection,
        instruction: Swap,
    },
    DepositAllTokenTypes {
        token_a_id: AccountId,
        token_b_id: AccountId,
        pool_token_id: AccountId,
        instruction: DepositAllTokenTypes,
    },
    WithdrawAllTokenTypes {
        token_a_id: AccountId,
        token_b_id: AccountId,
        pool_token_id: AccountId,
        instruction: WithdrawAllTokenTypes,
    },
}

/// Helper enum to tell which direction a swap is meant to go.
#[derive(Debug, Arbitrary, Clone)]
enum TradeDirection {
    AtoB,
    BtoA,
}

/// Use u8 as an account id to simplify the address space and re-use accounts
/// more often.
type AccountId = u8;

const INITIAL_SWAP_TOKEN_A_AMOUNT: u64 = 100_000_000_000;
const INITIAL_SWAP_TOKEN_B_AMOUNT: u64 = 300_000_000_000;

const INITIAL_USER_TOKEN_A_AMOUNT: u64 = 1_000_000_000;
const INITIAL_USER_TOKEN_B_AMOUNT: u64 = 3_000_000_000;

fn main() {
    loop {
        fuzz!(|fuzz_instructions: Vec<FuzzInstruction>| {
            run_fuzz_instructions(fuzz_instructions)
        });
    }
}

fn run_fuzz_instructions(fuzz_instructions: Vec<FuzzInstruction>) {
    let trade_fee_numerator = 25;
    let trade_fee_denominator = 10000;
    let owner_trade_fee_numerator = 5;
    let owner_trade_fee_denominator = 10000;
    let owner_withdraw_fee_numerator = 30;
    let owner_withdraw_fee_denominator = 10000;
    let host_fee_numerator = 1;
    let host_fee_denominator = 5;
    let fees = Fees {
        trade_fee_numerator,
        trade_fee_denominator,
        owner_trade_fee_numerator,
        owner_trade_fee_denominator,
        owner_withdraw_fee_numerator,
        owner_withdraw_fee_denominator,
        host_fee_numerator,
        host_fee_denominator,
    };
    let swap_curve = SwapCurve {
        curve_type: CurveType::ConstantProduct,
        calculator: Box::new(ConstantProductCurve {}),
    };
    let mut token_swap = NativeTokenSwap::new(
        fees,
        swap_curve,
        INITIAL_SWAP_TOKEN_A_AMOUNT,
        INITIAL_SWAP_TOKEN_B_AMOUNT,
    );

    // keep track of all accounts, including swap accounts
    let mut token_a_accounts: HashMap<AccountId, NativeAccountData> = HashMap::new();
    let mut token_b_accounts: HashMap<AccountId, NativeAccountData> = HashMap::new();
    let mut pool_accounts: HashMap<AccountId, NativeAccountData> = HashMap::new();

    // add all the pool and token accounts that will be needed
    for fuzz_instruction in &fuzz_instructions {
        let (token_a_id, token_b_id, pool_token_id) = match fuzz_instruction.clone() {
            FuzzInstruction::Swap {
                token_a_id,
                token_b_id,
                ..
            } => (token_a_id, token_b_id, None),

            FuzzInstruction::DepositAllTokenTypes {
                token_a_id,
                token_b_id,
                pool_token_id,
                ..
            } => (token_a_id, token_b_id, Some(pool_token_id)),

            FuzzInstruction::WithdrawAllTokenTypes {
                token_a_id,
                token_b_id,
                pool_token_id,
                ..
            } => (token_a_id, token_b_id, Some(pool_token_id)),
        };
        token_a_accounts
            .entry(token_a_id)
            .or_insert_with(|| token_swap.create_token_a_account(INITIAL_USER_TOKEN_A_AMOUNT));
        token_b_accounts
            .entry(token_b_id)
            .or_insert_with(|| token_swap.create_token_b_account(INITIAL_USER_TOKEN_B_AMOUNT));
        if let Some(pool_token_id) = pool_token_id {
            pool_accounts
                .entry(pool_token_id)
                .or_insert_with(|| token_swap.create_pool_account());
        }
    }

    let pool_tokens = [&token_swap.pool_token_account, &token_swap.pool_fee_account]
        .iter()
        .map(|&x| get_token_balance(x))
        .sum::<u64>() as u128;
    let initial_pool_token_amount =
        pool_tokens + pool_accounts.values().map(get_token_balance).sum::<u64>() as u128;
    let initial_swap_token_a_amount = get_token_balance(&token_swap.token_a_account) as u128;
    let initial_swap_token_b_amount = get_token_balance(&token_swap.token_b_account) as u128;

    // to ensure that we never create or remove base tokens
    let before_total_token_a =
        INITIAL_SWAP_TOKEN_A_AMOUNT + get_total_token_a_amount(&fuzz_instructions);
    let before_total_token_b =
        INITIAL_SWAP_TOKEN_B_AMOUNT + get_total_token_b_amount(&fuzz_instructions);

    for fuzz_instruction in fuzz_instructions {
        run_fuzz_instruction(
            fuzz_instruction,
            &mut token_swap,
            &mut token_a_accounts,
            &mut token_b_accounts,
            &mut pool_accounts,
        );
    }

    let pool_tokens = [&token_swap.pool_token_account, &token_swap.pool_fee_account]
        .iter()
        .map(|&x| get_token_balance(x))
        .sum::<u64>() as u128;
    let pool_token_amount = pool_tokens + pool_accounts.values().map(get_token_balance).sum::<u64>() as u128;
    let swap_token_a_amount = get_token_balance(&token_swap.token_a_account) as u128;
    let swap_token_b_amount = get_token_balance(&token_swap.token_b_account) as u128;

    let lost_a_value = initial_swap_token_a_amount * pool_token_amount > swap_token_a_amount * initial_pool_token_amount;
    let lost_b_value = initial_swap_token_b_amount * pool_token_amount > swap_token_b_amount * initial_pool_token_amount;
    assert!(!(lost_a_value && lost_b_value));

    // check total token a and b amounts
    let after_total_token_a = token_a_accounts
        .values()
        .map(get_token_balance)
        .sum::<u64>()
        + get_token_balance(&token_swap.token_a_account);
    assert_eq!(before_total_token_a, after_total_token_a);
    let after_total_token_b = token_b_accounts
        .values()
        .map(get_token_balance)
        .sum::<u64>()
        + get_token_balance(&token_swap.token_b_account);
    assert_eq!(before_total_token_b, after_total_token_b);

    // final check to make sure that withdrawing everything works
    let mut withdrawn_token_a_account = token_swap.create_token_a_account(0);
    let mut withdrawn_token_b_account = token_swap.create_token_b_account(0);
    for mut pool_account in pool_accounts.values_mut() {
        token_swap
            .withdraw_all(
                &mut pool_account,
                &mut withdrawn_token_a_account,
                &mut withdrawn_token_b_account,
            )
            .unwrap();
    }
    let mut pool_account = token_swap.pool_token_account.clone();
    token_swap
        .withdraw_all(
            &mut pool_account,
            &mut withdrawn_token_a_account,
            &mut withdrawn_token_b_account,
        )
        .unwrap();
    let mut fee_account = token_swap.pool_fee_account.clone();
    token_swap
        .withdraw_all(
            &mut fee_account,
            &mut withdrawn_token_a_account,
            &mut withdrawn_token_b_account,
        )
        .unwrap();

    let after_total_token_a = token_a_accounts
        .values()
        .map(get_token_balance)
        .sum::<u64>()
        + get_token_balance(&withdrawn_token_a_account)
        + get_token_balance(&token_swap.token_a_account);
    assert_eq!(before_total_token_a, after_total_token_a);
    let after_total_token_b = token_b_accounts
        .values()
        .map(get_token_balance)
        .sum::<u64>()
        + get_token_balance(&withdrawn_token_b_account)
        + get_token_balance(&token_swap.token_b_account);
    assert_eq!(before_total_token_b, after_total_token_b);
}

fn run_fuzz_instruction(
    fuzz_instruction: FuzzInstruction,
    token_swap: &mut NativeTokenSwap,
    token_a_accounts: &mut HashMap<AccountId, NativeAccountData>,
    token_b_accounts: &mut HashMap<AccountId, NativeAccountData>,
    pool_accounts: &mut HashMap<AccountId, NativeAccountData>,
) {
    let result = match fuzz_instruction {
        FuzzInstruction::Swap {
            token_a_id,
            token_b_id,
            trade_direction,
            instruction,
        } => {
            let mut token_a_account = token_a_accounts.get_mut(&token_a_id).unwrap();
            let mut token_b_account = token_b_accounts.get_mut(&token_b_id).unwrap();
            match trade_direction {
                TradeDirection::AtoB => {
                    token_swap.swap_a_to_b(&mut token_a_account, &mut token_b_account, instruction)
                }
                TradeDirection::BtoA => {
                    token_swap.swap_b_to_a(&mut token_b_account, &mut token_a_account, instruction)
                }
            }
        }
        FuzzInstruction::DepositAllTokenTypes {
            token_a_id,
            token_b_id,
            pool_token_id,
            instruction,
        } => {
            let mut token_a_account = token_a_accounts.get_mut(&token_a_id).unwrap();
            let mut token_b_account = token_b_accounts.get_mut(&token_b_id).unwrap();
            let mut pool_account = pool_accounts.get_mut(&pool_token_id).unwrap();
            token_swap.deposit(
                &mut token_a_account,
                &mut token_b_account,
                &mut pool_account,
                instruction,
            )
        }
        FuzzInstruction::WithdrawAllTokenTypes {
            token_a_id,
            token_b_id,
            pool_token_id,
            instruction,
        } => {
            let mut token_a_account = token_a_accounts.get_mut(&token_a_id).unwrap();
            let mut token_b_account = token_b_accounts.get_mut(&token_b_id).unwrap();
            let mut pool_account = pool_accounts.get_mut(&pool_token_id).unwrap();
            token_swap.withdraw(
                &mut pool_account,
                &mut token_a_account,
                &mut token_b_account,
                instruction,
            )
        }
    };
    result
        .map_err(|e| {
            if !(e == SwapError::CalculationFailure.into()
                || e == SwapError::ConversionFailure.into()
                || e == SwapError::FeeCalculationFailure.into()
                || e == SwapError::ExceededSlippage.into()
                || e == SwapError::ZeroTradingTokens.into()
                || e == TokenError::InsufficientFunds.into())
            {
                Err(e).unwrap()
            }
        })
        .ok();
}

fn get_total_token_a_amount(fuzz_instructions: &[FuzzInstruction]) -> u64 {
    let mut token_a_ids = HashSet::new();
    for fuzz_instruction in fuzz_instructions.iter() {
        match fuzz_instruction {
            FuzzInstruction::Swap { token_a_id, .. } => token_a_ids.insert(token_a_id),
            FuzzInstruction::DepositAllTokenTypes { token_a_id, .. } => {
                token_a_ids.insert(token_a_id)
            }
            FuzzInstruction::WithdrawAllTokenTypes { token_a_id, .. } => {
                token_a_ids.insert(token_a_id)
            }
        };
    }
    (token_a_ids.len() as u64) * INITIAL_USER_TOKEN_A_AMOUNT
}

fn get_total_token_b_amount(fuzz_instructions: &[FuzzInstruction]) -> u64 {
    let mut token_b_ids = HashSet::new();
    for fuzz_instruction in fuzz_instructions.iter() {
        match fuzz_instruction {
            FuzzInstruction::Swap { token_b_id, .. } => token_b_ids.insert(token_b_id),
            FuzzInstruction::DepositAllTokenTypes { token_b_id, .. } => {
                token_b_ids.insert(token_b_id)
            }
            FuzzInstruction::WithdrawAllTokenTypes { token_b_id, .. } => {
                token_b_ids.insert(token_b_id)
            }
        };
    }
    (token_b_ids.len() as u64) * INITIAL_USER_TOKEN_B_AMOUNT
}
