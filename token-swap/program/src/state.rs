//! State transition types

use crate::curve::SwapCurveWrapper;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_sdk::{
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack, Sealed},
    pubkey::Pubkey,
};

/// Program states.
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct SwapInfo {
    /// Initialized state.
    pub is_initialized: bool,
    /// Nonce used in program address.
    /// The program address is created deterministically with the nonce,
    /// swap program id, and swap account pubkey.  This program address has
    /// authority over the swap's token A account, token B account, and pool
    /// token mint.
    pub nonce: u8,

    /// Program ID of the tokens being exchanged.
    pub token_program_id: Pubkey,

    /// Token A
    /// The Liquidity token is issued against this value.
    pub token_a: Pubkey,
    /// Token B
    pub token_b: Pubkey,
    /// Pool tokens are issued when A or B tokens are deposited.
    /// Pool tokens can be withdrawn back to the original A or B token.
    pub pool_mint: Pubkey,

    /// Swap curve parameters, to be unpacked and used by the SwapCurve, which
    /// calculates swaps, deposits, and withdrawals
    pub swap_curve: SwapCurveWrapper,
}

impl Sealed for SwapInfo {}
impl IsInitialized for SwapInfo {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Pack for SwapInfo {
    const LEN: usize = 195;

    /// Unpacks a byte buffer into a [SwapInfo](struct.SwapInfo.html).
    fn unpack_from_slice(input: &[u8]) -> Result<Self, ProgramError> {
        let input = array_ref![input, 0, 195];
        #[allow(clippy::ptr_offset_with_cast)]
        let (
            is_initialized,
            nonce,
            token_program_id,
            token_a,
            token_b,
            pool_mint,
            swap_curve,
        ) = array_refs![input, 1, 1, 32, 32, 32, 32, 65];
        Ok(Self {
            is_initialized: match is_initialized {
                [0] => false,
                [1] => true,
                _ => return Err(ProgramError::InvalidAccountData),
            },
            nonce: nonce[0],
            token_program_id: Pubkey::new_from_array(*token_program_id),
            token_a: Pubkey::new_from_array(*token_a),
            token_b: Pubkey::new_from_array(*token_b),
            pool_mint: Pubkey::new_from_array(*pool_mint),
            swap_curve: SwapCurveWrapper::unpack_from_slice(swap_curve)?,
        })
    }

    fn pack_into_slice(&self, output: &mut [u8]) {
        let output = array_mut_ref![output, 0, 195];
        let (
            is_initialized,
            nonce,
            token_program_id,
            token_a,
            token_b,
            pool_mint,
            swap_curve,
        ) = mut_array_refs![output, 1, 1, 32, 32, 32, 32, 65];
        is_initialized[0] = self.is_initialized as u8;
        nonce[0] = self.nonce;
        token_program_id.copy_from_slice(self.token_program_id.as_ref());
        token_a.copy_from_slice(self.token_a.as_ref());
        token_b.copy_from_slice(self.token_b.as_ref());
        pool_mint.copy_from_slice(self.pool_mint.as_ref());
        self.swap_curve.pack_into_slice(&mut swap_curve[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::FlatCurve;

    use std::convert::TryInto;

    #[test]
    fn test_swap_info_packing() {
        let nonce = 255;
        let curve_type_raw: u8 = 1;
        let curve_type = curve_type_raw.try_into().unwrap();
        let token_program_id_raw = [1u8; 32];
        let token_a_raw = [1u8; 32];
        let token_b_raw = [2u8; 32];
        let pool_mint_raw = [3u8; 32];
        let token_program_id = Pubkey::new_from_array(token_program_id_raw);
        let token_a = Pubkey::new_from_array(token_a_raw);
        let token_b = Pubkey::new_from_array(token_b_raw);
        let pool_mint = Pubkey::new_from_array(pool_mint_raw);
        let fee_numerator = 1;
        let fee_denominator = 4;
        let calculator = Box::new(FlatCurve { fee_numerator, fee_denominator });
        let swap_curve = SwapCurveWrapper {
            curve_type,
            calculator,
        };
        let is_initialized = true;
        let swap_info = SwapInfo {
            is_initialized,
            nonce,
            token_program_id,
            token_a,
            token_b,
            pool_mint,
            swap_curve,
        };

        let mut packed = [0u8; SwapInfo::LEN];
        SwapInfo::pack_into_slice(&swap_info, &mut packed);
        let unpacked = SwapInfo::unpack(&packed).unwrap();
        assert_eq!(swap_info, unpacked);

        let mut packed = vec![];
        packed.push(1 as u8);
        packed.push(nonce);
        packed.extend_from_slice(&token_program_id_raw);
        packed.extend_from_slice(&token_a_raw);
        packed.extend_from_slice(&token_b_raw);
        packed.extend_from_slice(&pool_mint_raw);
        packed.push(curve_type_raw);
        packed.push(fee_numerator as u8);
        packed.extend_from_slice(&[0u8; 7]); // padding
        packed.push(fee_denominator as u8);
        packed.extend_from_slice(&[0u8; 7]); // padding
        packed.extend_from_slice(&[0u8; 48]); // padding
        let unpacked = SwapInfo::unpack(&packed).unwrap();
        assert_eq!(swap_info, unpacked);

        let packed = [0u8; SwapInfo::LEN];
        let swap_info: SwapInfo = Default::default();
        let unpack_unchecked = SwapInfo::unpack_unchecked(&packed).unwrap();
        assert_eq!(unpack_unchecked, swap_info);
        let err = SwapInfo::unpack(&packed).unwrap_err();
        assert_eq!(err, ProgramError::UninitializedAccount);
    }
}
