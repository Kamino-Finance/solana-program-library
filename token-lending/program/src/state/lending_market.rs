use super::*;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::{
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack, Sealed},
    pubkey::{Pubkey, PUBKEY_BYTES},
};

/// Lending market state
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LendingMarket {
    /// Version of lending market
    pub version: u8,
    /// Bump seed for derived authority address
    pub bump_seed: u8,
    /// Token program id
    pub token_program_id: Pubkey,
    /// Quote currency token mint
    pub quote_token_mint: Pubkey,
    /// The target ratio of an obligation's borrows to deposits as a percent
    pub loan_to_value_ratio: u8,
    /// The percent at which an obligation is considered unhealthy
    pub liquidation_threshold: u8,
    /// Owner authority which can add new reserves
    pub owner: Pubkey,
}

/// Initialize a lending market
pub struct InitLendingMarketParams {
    /// Bump seed for derived authority address
    pub bump_seed: u8,
    /// Token program id
    pub token_program_id: Pubkey,
    /// Quote currency token mint
    pub quote_token_mint: Pubkey,
    /// The target ratio of an obligation's borrows to deposits as a percent
    pub loan_to_value_ratio: u8,
    /// The percent at which an obligation is considered unhealthy
    pub liquidation_threshold: u8,
    /// Owner authority which can add new reserves
    pub owner: Pubkey,
}

impl LendingMarket {
    /// Create a new lending market
    pub fn new(params: InitLendingMarketParams) -> Self {
        let mut lending_market = Self::default();
        Self::init(&mut lending_market, params);
        lending_market
    }

    /// Initialize a lending market
    pub fn init(&mut self, params: InitLendingMarketParams) {
        self.version = PROGRAM_VERSION;
        self.bump_seed = params.bump_seed;
        self.owner = params.owner;
        self.quote_token_mint = params.quote_token_mint;
        self.token_program_id = params.token_program_id;
        self.loan_to_value_ratio = params.loan_to_value_ratio;
        self.liquidation_threshold = params.liquidation_threshold;
    }
}

impl Sealed for LendingMarket {}
impl IsInitialized for LendingMarket {
    fn is_initialized(&self) -> bool {
        self.version != UNINITIALIZED_VERSION
    }
}

// @TODO: adjust padding. what's a reasonable number?
const LENDING_MARKET_LEN: usize = 160; // 1 + 1 + 32 + 32 + 1 + 1 + 32 + 60
impl Pack for LendingMarket {
    const LEN: usize = LENDING_MARKET_LEN;

    fn pack_into_slice(&self, output: &mut [u8]) {
        let output = array_mut_ref![output, 0, LENDING_MARKET_LEN];
        #[allow(clippy::ptr_offset_with_cast)]
        let (
            version,
            bump_seed,
            token_program_id,
            quote_token_mint,
            loan_to_value_ratio,
            liquidation_threshold,
            owner,
            _padding,
        ) = mut_array_refs![
            output,
            1,
            1,
            PUBKEY_BYTES,
            PUBKEY_BYTES,
            1,
            1,
            PUBKEY_BYTES,
            60
        ];
        *version = self.version.to_le_bytes();
        *bump_seed = self.bump_seed.to_le_bytes();
        token_program_id.copy_from_slice(self.token_program_id.as_ref());
        quote_token_mint.copy_from_slice(self.quote_token_mint.as_ref());
        *loan_to_value_ratio = self.loan_to_value_ratio.to_le_bytes();
        *liquidation_threshold = self.liquidation_threshold.to_le_bytes();
        owner.copy_from_slice(self.owner.as_ref());
    }

    /// Unpacks a byte buffer into a [LendingMarketInfo](struct.LendingMarketInfo.html).
    fn unpack_from_slice(input: &[u8]) -> Result<Self, ProgramError> {
        let input = array_ref![input, 0, LENDING_MARKET_LEN];
        #[allow(clippy::ptr_offset_with_cast)]
        let (
            version,
            bump_seed,
            quote_token_mint,
            token_program_id,
            loan_to_value_ratio,
            liquidation_threshold,
            owner,
            _padding,
        ) = array_refs![
            input,
            1,
            1,
            PUBKEY_BYTES,
            PUBKEY_BYTES,
            1,
            1,
            PUBKEY_BYTES,
            60
        ];
        let version = u8::from_le_bytes(*version);
        if version > PROGRAM_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(Self {
            version,
            bump_seed: u8::from_le_bytes(*bump_seed),
            token_program_id: Pubkey::new_from_array(*token_program_id),
            quote_token_mint: Pubkey::new_from_array(*quote_token_mint),
            loan_to_value_ratio: u8::from_le_bytes(*loan_to_value_ratio),
            liquidation_threshold: u8::from_le_bytes(*liquidation_threshold),
            owner: Pubkey::new_from_array(*owner),
        })
    }
}
