use solana_program::pubkey::Pubkey;

#[derive(Debug)]
pub struct TokenAccountCookie {
    pub address: Pubkey,
}

#[derive(Debug)]
pub struct WalletCookie {
    pub address: Pubkey,
}
