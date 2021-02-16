//! Program state
use {
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{program_pack::IsInitialized, pubkey::Pubkey},
};

/// Struct wrapping data and providing metadata
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub struct AccountData {
    /// Struct version, allows for upgrades to the program
    pub version: u8,

    /// The account allowed to update the data
    pub authority: Pubkey,

    /// The data contained by the account, could be anything serializable
    pub data: Data,
}

/// Struct just for data
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub struct Data {
    /// The data contained by the account, could be anything or serializable
    pub bytes: [u8; Self::DATA_SIZE],
}

impl Data {
    /// very small data for easy testing
    pub const DATA_SIZE: usize = 8;
}

impl AccountData {
    /// Version to fill in on new created accounts
    pub const CURRENT_VERSION: u8 = 1;

    /// Start of writable account data, after version and authority
    pub const WRITABLE_START_INDEX: usize = 33;
}

impl IsInitialized for AccountData {
    /// Is initialized
    fn is_initialized(&self) -> bool {
        self.version != 0
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use solana_program::program_error::ProgramError;

    /// Version for tests
    pub const TEST_VERSION: u8 = 1;
    /// Pubkey for tests
    pub const TEST_PUBKEY: Pubkey = Pubkey::new_from_array([100; 32]);
    /// Bytes for tests
    pub const TEST_BYTES: [u8; Data::DATA_SIZE] = [42; Data::DATA_SIZE];
    /// Data for tests
    pub const TEST_DATA: Data = Data { bytes: TEST_BYTES };
    /// AccountData for tests
    pub const TEST_ACCOUNT_DATA: AccountData = AccountData {
        version: TEST_VERSION,
        authority: TEST_PUBKEY,
        data: TEST_DATA,
    };

    #[test]
    fn serialize_document() {
        let mut expected = vec![];
        expected.push(TEST_VERSION);
        expected.extend_from_slice(&TEST_PUBKEY.to_bytes());
        expected.extend_from_slice(&TEST_DATA.bytes);
        assert_eq!(TEST_ACCOUNT_DATA.try_to_vec().unwrap(), expected);
        assert_eq!(
            AccountData::try_from_slice(&expected).unwrap(),
            TEST_ACCOUNT_DATA
        );
    }

    #[test]
    fn deserialize_invalid_slice() {
        let data = [200; Data::DATA_SIZE - 1];
        let mut expected = vec![];
        expected.push(TEST_VERSION);
        expected.extend_from_slice(&TEST_PUBKEY.to_bytes());
        expected.extend_from_slice(&data);
        let err: ProgramError = AccountData::try_from_slice(&expected).unwrap_err().into();
        assert!(matches!(err, ProgramError::IOError(_)));
    }
}
