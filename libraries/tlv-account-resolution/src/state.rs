//! State transition types

use {
    crate::{account::ExtraAccountMeta, error::AccountResolutionError},
    solana_program::{
        account_info::AccountInfo,
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
    },
    spl_discriminator::SplDiscriminate,
    spl_type_length_value::{
        pod::{PodSlice, PodSliceMut},
        state::{TlvState, TlvStateBorrowed, TlvStateMut},
    },
    std::future::Future,
};

/// Type representing the output of an account fetching function, for easy
/// chaining between APIs
pub type AccountDataResult = Result<Option<Vec<u8>>, AccountFetchError>;
/// Generic error type that can come out of any client while fetching account
/// data
pub type AccountFetchError = Box<dyn std::error::Error + Send + Sync>;

/// De-escalate an account meta if necessary
fn de_escalate_account_meta(account_meta: &mut AccountMeta, account_metas: &[AccountMeta]) {
    // This is a little tricky to read, but the idea is to see if
    // this account is marked as writable or signer anywhere in
    // the instruction at the start. If so, DON'T escalate it to
    // be a writer or signer in the CPI
    let maybe_highest_privileges = account_metas
        .iter()
        .filter(|&x| x.pubkey == account_meta.pubkey)
        .map(|x| (x.is_signer, x.is_writable))
        .reduce(|acc, x| (acc.0 || x.0, acc.1 || x.1));
    // If `Some`, then the account was found somewhere in the instruction
    if let Some((is_signer, is_writable)) = maybe_highest_privileges {
        if !is_signer && is_signer != account_meta.is_signer {
            // Existing account is *NOT* a signer already, but the CPI
            // wants it to be, so de-escalate to not be a signer
            account_meta.is_signer = false;
        }
        if !is_writable && is_writable != account_meta.is_writable {
            // Existing account is *NOT* writable already, but the CPI
            // wants it to be, so de-escalate to not be writable
            account_meta.is_writable = false;
        }
    }
}

/// Stateless helper for storing additional accounts required for an
/// instruction.
///
/// This struct works with any `SplDiscriminate`, and stores the extra accounts
/// needed for that specific instruction, using the given `ArrayDiscriminator`
/// as the type-length-value `ArrayDiscriminator`, and then storing all of the
/// given `AccountMeta`s as a zero-copy slice.
///
/// Sample usage:
///
/// ```ignore
/// use {
///     solana_program::{
///         account_info::AccountInfo, instruction::{AccountMeta, Instruction},
///         pubkey::Pubkey
///     },
///     spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
///     spl_tlv_account_resolution::state::ExtraAccountMetaList,
/// };
///
/// struct MyInstruction;
/// impl SplDiscriminate for MyInstruction {
///     // Give it a unique discriminator, can also be generated using a hash function
///     const SPL_DISCRIMINATOR: ArrayDiscriminator = ArrayDiscriminator::new([1; ArrayDiscriminator::LENGTH]);
/// }
///
/// // actually put it in the additional required account keys and signer / writable
/// let extra_metas = [
///     AccountMeta::new(Pubkey::new_unique(), false).into(),
///     AccountMeta::new(Pubkey::new_unique(), true).into(),
///     AccountMeta::new_readonly(Pubkey::new_unique(), true).into(),
///     AccountMeta::new_readonly(Pubkey::new_unique(), false).into(),
/// ];
///
/// // assume that this buffer is actually account data, already allocated to `account_size`
/// let account_size = ExtraAccountMetaList::size_of(extra_metas.len()).unwrap();
/// let mut buffer = vec![0; account_size];
///
/// // Initialize the structure for your instruction
/// ExtraAccountMetaList::init::<MyInstruction>(&mut buffer, &extra_metas).unwrap();
///
/// // Off-chain, you can add the additional accounts directly from the account data
/// let program_id = Pubkey::new_unique();
/// let mut instruction = Instruction::new_with_bytes(program_id, &[], vec![]);
/// ExtraAccountMetaList::add_to_instruction::<MyInstruction>(&mut instruction, &buffer).unwrap();
///
/// // On-chain, you can add the additional accounts *and* account infos
/// let mut cpi_instruction = Instruction::new_with_bytes(program_id, &[], vec![]);
/// let mut cpi_account_infos = vec![]; // assume the other required account infos are already included
/// let remaining_account_infos: &[AccountInfo<'_>] = &[]; // these are the account infos provided to the instruction that are *not* part of any other known interface
/// ExtraAccountMetaList::add_to_cpi_instruction::<MyInstruction>(
///     &mut cpi_instruction,
///     &mut cpi_account_infos,
///     &buffer,
///     &remaining_account_infos,
/// );
/// ```
pub struct ExtraAccountMetaList;
impl ExtraAccountMetaList {
    /// Initialize pod slice data for the given instruction and its required
    /// list of `ExtraAccountMeta`s
    pub fn init<T: SplDiscriminate>(
        data: &mut [u8],
        extra_account_metas: &[ExtraAccountMeta],
    ) -> Result<(), ProgramError> {
        let mut state = TlvStateMut::unpack(data).unwrap();
        let tlv_size = PodSlice::<ExtraAccountMeta>::size_of(extra_account_metas.len())?;
        let (bytes, _) = state.alloc::<T>(tlv_size, false)?;
        let mut validation_data = PodSliceMut::init(bytes)?;
        for meta in extra_account_metas {
            validation_data.push(*meta)?;
        }
        Ok(())
    }

    /// Get the underlying `PodSlice<ExtraAccountMeta>` from an unpacked TLV
    ///
    /// Due to lifetime annoyances, this function can't just take in the bytes,
    /// since then we would be returning a reference to a locally created
    /// `TlvStateBorrowed`. I hope there's a better way to do this!
    pub fn unpack_with_tlv_state<'a, T: SplDiscriminate>(
        tlv_state: &'a TlvStateBorrowed,
    ) -> Result<PodSlice<'a, ExtraAccountMeta>, ProgramError> {
        let bytes = tlv_state.get_first_bytes::<T>()?;
        PodSlice::<ExtraAccountMeta>::unpack(bytes)
    }

    /// Get the byte size required to hold `num_items` items
    pub fn size_of(num_items: usize) -> Result<usize, ProgramError> {
        Ok(TlvStateBorrowed::get_base_len()
            .saturating_add(PodSlice::<ExtraAccountMeta>::size_of(num_items)?))
    }

    /// Checks provided account infos against validation data, using
    /// instruction data and program ID to resolve any dynamic PDAs
    /// if necessary.
    ///
    /// Note: this function will also verify all extra required accounts
    /// have been provided in the correct order
    pub fn check_account_infos<T: SplDiscriminate>(
        account_infos: &[AccountInfo],
        instruction_data: &[u8],
        program_id: &Pubkey,
        data: &[u8],
    ) -> Result<(), ProgramError> {
        let state = TlvStateBorrowed::unpack(data).unwrap();
        let extra_meta_list = ExtraAccountMetaList::unpack_with_tlv_state::<T>(&state)?;
        let extra_account_metas = extra_meta_list.data();

        let initial_accounts_len = account_infos.len() - extra_account_metas.len();

        // TODO: Try to find a way to store references to the
        // `Rc<RefCell<&mut [u8]>>` instead of copying
        let mut account_data_list: Vec<Option<Vec<u8>>> = vec![];
        for info in account_infos.iter() {
            account_data_list.push(Some(info.try_borrow_data()?.to_vec()));
        }

        for (i, config) in extra_account_metas.iter().enumerate() {
            let meta = config.resolve(
                &account_data_list,
                account_infos,
                instruction_data,
                program_id,
            )?;
            let expected_index = i
                .checked_add(initial_accounts_len)
                .ok_or::<ProgramError>(AccountResolutionError::CalculationFailure.into())?;
            if let Some(info) = account_infos.get(expected_index) {
                if !(info.key == &meta.pubkey
                    && info.is_signer == meta.is_signer
                    && info.is_writable == meta.is_writable)
                {
                    return Err(AccountResolutionError::IncorrectAccount.into());
                } else {
                    account_data_list.push(Some(info.try_borrow_data()?.to_vec()));
                }
            } else {
                return Err(AccountResolutionError::IncorrectAccount.into());
            }
        }

        Ok(())
    }

    /// Add the additional account metas to an existing instruction
    pub async fn add_to_instruction<F, Fut, T>(
        instruction: &mut Instruction,
        get_account_data_fn: F,
        data: &[u8],
    ) -> Result<(), ProgramError>
    where
        F: Fn(Pubkey) -> Fut,
        Fut: Future<Output = AccountDataResult>,
        T: SplDiscriminate,
    {
        let state = TlvStateBorrowed::unpack(data)?;
        let bytes = state.get_first_bytes::<T>()?;
        let extra_account_metas = PodSlice::<ExtraAccountMeta>::unpack(bytes)?;

        // TODO: Here we aren't copying, but if the list turns into type
        // `Vec<&[u8]>`, we can store the fetched vectors separately and pass
        // a list of references to conform with the API
        let mut account_data_list: Vec<Option<Vec<u8>>> = vec![];
        for meta in instruction.accounts.iter() {
            let account_data = get_account_data_fn(meta.pubkey).await.unwrap_or(None);
            account_data_list.push(account_data);
        }

        for extra_meta in extra_account_metas.data().iter() {
            let mut meta = extra_meta.resolve(
                &account_data_list,
                &instruction.accounts,
                &instruction.data,
                &instruction.program_id,
            )?;
            de_escalate_account_meta(&mut meta, &instruction.accounts);
            let account_data = get_account_data_fn(meta.pubkey).await.unwrap_or(None);
            account_data_list.push(account_data);
            instruction.accounts.push(meta);
        }
        Ok(())
    }

    /// Add the additional account metas and account infos for a CPI
    pub fn add_to_cpi_instruction<'a, T: SplDiscriminate>(
        cpi_instruction: &mut Instruction,
        cpi_account_infos: &mut Vec<AccountInfo<'a>>,
        data: &[u8],
        account_infos: &[AccountInfo<'a>],
    ) -> Result<(), ProgramError> {
        let state = TlvStateBorrowed::unpack(data)?;
        let bytes = state.get_first_bytes::<T>()?;
        let extra_account_metas = PodSlice::<ExtraAccountMeta>::unpack(bytes)?;

        // TODO: Try to find a way to store references to the
        // `Rc<RefCell<&mut [u8]>>` instead of copying
        let mut account_data_list: Vec<Option<Vec<u8>>> = vec![];
        for info in cpi_account_infos.iter() {
            account_data_list.push(Some(info.try_borrow_data()?.to_vec()));
        }

        for extra_meta in extra_account_metas.data().iter() {
            let mut meta = extra_meta.resolve(
                &account_data_list,
                cpi_account_infos,
                &cpi_instruction.data,
                &cpi_instruction.program_id,
            )?;
            de_escalate_account_meta(&mut meta, &cpi_instruction.accounts);

            let account_info = account_infos
                .iter()
                .find(|&x| *x.key == meta.pubkey)
                .ok_or(AccountResolutionError::IncorrectAccount)?
                .clone();

            account_data_list.push(Some(account_info.try_borrow_data()?.to_vec()));
            cpi_instruction.accounts.push(meta);
            cpi_account_infos.push(account_info);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::seeds::Seed,
        solana_program::{clock::Epoch, instruction::AccountMeta, pubkey::Pubkey},
        solana_program_test::tokio,
        spl_discriminator::{ArrayDiscriminator, SplDiscriminate},
        std::collections::HashMap,
    };

    pub struct TestInstruction;
    impl SplDiscriminate for TestInstruction {
        const SPL_DISCRIMINATOR: ArrayDiscriminator =
            ArrayDiscriminator::new([1; ArrayDiscriminator::LENGTH]);
    }

    pub struct TestOtherInstruction;
    impl SplDiscriminate for TestOtherInstruction {
        const SPL_DISCRIMINATOR: ArrayDiscriminator =
            ArrayDiscriminator::new([2; ArrayDiscriminator::LENGTH]);
    }

    pub struct MockRpc<'a> {
        cache: HashMap<Pubkey, &'a AccountInfo<'a>>,
    }
    impl<'a> MockRpc<'a> {
        pub fn setup(account_infos: &'a [AccountInfo<'a>]) -> Self {
            let mut cache = HashMap::new();
            for info in account_infos {
                cache.insert(*info.key, info);
            }
            Self { cache }
        }

        pub async fn get_account_data(&self, pubkey: Pubkey) -> AccountDataResult {
            Ok(self
                .cache
                .get(&pubkey)
                .map(|account| account.try_borrow_data().unwrap().to_vec()))
        }
    }

    fn account_info_to_meta(account_info: &AccountInfo) -> AccountMeta {
        AccountMeta {
            pubkey: *account_info.key,
            is_signer: account_info.is_signer,
            is_writable: account_info.is_writable,
        }
    }

    #[tokio::test]
    async fn init_with_metas() {
        let metas = [
            AccountMeta::new(Pubkey::new_unique(), false).into(),
            AccountMeta::new(Pubkey::new_unique(), true).into(),
            AccountMeta::new_readonly(Pubkey::new_unique(), true).into(),
            AccountMeta::new_readonly(Pubkey::new_unique(), false).into(),
        ];
        let account_size = ExtraAccountMetaList::size_of(metas.len()).unwrap();
        let mut buffer = vec![0; account_size];

        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &metas).unwrap();

        let mock_rpc = MockRpc::setup(&[]);

        let mut instruction = Instruction::new_with_bytes(Pubkey::new_unique(), &[], vec![]);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let check_metas = metas
            .iter()
            .map(|e| AccountMeta::try_from(e).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(instruction.accounts, check_metas,);
    }

    #[tokio::test]
    async fn init_with_infos() {
        let program_id = Pubkey::new_unique();

        let pubkey1 = Pubkey::new_unique();
        let mut lamports1 = 0;
        let mut data1 = [];
        let pubkey2 = Pubkey::new_unique();
        let mut lamports2 = 0;
        let mut data2 = [4, 4, 4, 6, 6, 6, 8, 8];
        let pubkey3 = Pubkey::new_unique();
        let mut lamports3 = 0;
        let mut data3 = [];
        let owner = Pubkey::new_unique();
        let account_infos = [
            AccountInfo::new(
                &pubkey1,
                false,
                true,
                &mut lamports1,
                &mut data1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey2,
                true,
                false,
                &mut lamports2,
                &mut data2,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey3,
                false,
                false,
                &mut lamports3,
                &mut data3,
                &owner,
                false,
                Epoch::default(),
            ),
        ];

        let required_pda = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::AccountKey { index: 0 },
                Seed::AccountData {
                    account_index: 1,
                    data_index: 2,
                    length: 4,
                },
            ],
            false,
            true,
        )
        .unwrap();

        // Convert to `ExtraAccountMeta`
        let required_extra_accounts = [
            ExtraAccountMeta::from(&account_infos[0]),
            ExtraAccountMeta::from(&account_infos[1]),
            ExtraAccountMeta::from(&account_infos[2]),
            required_pda,
        ];

        let account_size = ExtraAccountMetaList::size_of(required_extra_accounts.len()).unwrap();
        let mut buffer = vec![0; account_size];

        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &required_extra_accounts)
            .unwrap();

        let mock_rpc = MockRpc::setup(&account_infos);

        let mut instruction = Instruction::new_with_bytes(program_id, &[], vec![]);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let (check_required_pda, _) = Pubkey::find_program_address(
            &[
                account_infos[0].key.as_ref(), // Account key
                &[4, 6, 6, 6],                 // Account data
            ],
            &program_id,
        );

        // Convert to `AccountMeta` to check instruction
        let check_metas = [
            account_info_to_meta(&account_infos[0]),
            account_info_to_meta(&account_infos[1]),
            account_info_to_meta(&account_infos[2]),
            AccountMeta::new(check_required_pda, false),
        ];

        assert_eq!(instruction.accounts, check_metas,);

        assert_eq!(
            instruction.accounts.get(3).unwrap().pubkey,
            check_required_pda
        );
    }

    #[tokio::test]
    async fn init_with_extra_account_metas() {
        let program_id = Pubkey::new_unique();

        let extra_meta3_literal_str = "seed_prefix";

        let ix_account1 = AccountMeta::new(Pubkey::new_unique(), false);
        let ix_account2 = AccountMeta::new(Pubkey::new_unique(), true);

        let extra_meta1 = AccountMeta::new(Pubkey::new_unique(), false);
        let extra_meta2 = AccountMeta::new(Pubkey::new_unique(), true);
        let extra_meta3 = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::Literal {
                    bytes: extra_meta3_literal_str.as_bytes().to_vec(),
                },
                Seed::InstructionData {
                    index: 1,
                    length: 1, // u8
                },
                Seed::AccountKey { index: 0 },
                Seed::AccountKey { index: 2 },
            ],
            false,
            true,
        )
        .unwrap();

        let metas = [
            ExtraAccountMeta::from(&extra_meta1),
            ExtraAccountMeta::from(&extra_meta2),
            extra_meta3,
        ];

        let ix_data = vec![1, 2, 3, 4];
        let ix_accounts = vec![ix_account1.clone(), ix_account2.clone()];
        let mut instruction = Instruction::new_with_bytes(program_id, &ix_data, ix_accounts);

        let account_size = ExtraAccountMetaList::size_of(metas.len()).unwrap();
        let mut buffer = vec![0; account_size];

        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &metas).unwrap();

        let mock_rpc = MockRpc::setup(&[]);

        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let check_extra_meta3_u8_arg = ix_data[1];
        let check_extra_meta3_pubkey = Pubkey::find_program_address(
            &[
                extra_meta3_literal_str.as_bytes(),
                &[check_extra_meta3_u8_arg],
                ix_account1.pubkey.as_ref(),
                extra_meta1.pubkey.as_ref(),
            ],
            &program_id,
        )
        .0;
        let check_metas = [
            ix_account1,
            ix_account2,
            extra_meta1,
            extra_meta2,
            AccountMeta::new(check_extra_meta3_pubkey, false),
        ];

        assert_eq!(
            instruction.accounts.get(4).unwrap().pubkey,
            check_extra_meta3_pubkey,
        );
        assert_eq!(instruction.accounts, check_metas,);
    }

    #[tokio::test]
    async fn init_multiple() {
        let extra_meta5_literal_str = "seed_prefix";
        let extra_meta5_literal_u32 = 4u32;
        let other_meta2_literal_str = "other_seed_prefix";

        let extra_meta1 = AccountMeta::new(Pubkey::new_unique(), false);
        let extra_meta2 = AccountMeta::new(Pubkey::new_unique(), true);
        let extra_meta3 = AccountMeta::new_readonly(Pubkey::new_unique(), true);
        let extra_meta4 = AccountMeta::new_readonly(Pubkey::new_unique(), false);
        let extra_meta5 = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::Literal {
                    bytes: extra_meta5_literal_str.as_bytes().to_vec(),
                },
                Seed::Literal {
                    bytes: extra_meta5_literal_u32.to_le_bytes().to_vec(),
                },
                Seed::InstructionData {
                    index: 5,
                    length: 1, // u8
                },
                Seed::AccountKey { index: 2 },
            ],
            false,
            true,
        )
        .unwrap();

        let other_meta1 = AccountMeta::new(Pubkey::new_unique(), false);
        let other_meta2 = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::Literal {
                    bytes: other_meta2_literal_str.as_bytes().to_vec(),
                },
                Seed::InstructionData {
                    index: 1,
                    length: 4, // u32
                },
                Seed::AccountKey { index: 0 },
            ],
            false,
            true,
        )
        .unwrap();

        let metas = [
            ExtraAccountMeta::from(&extra_meta1),
            ExtraAccountMeta::from(&extra_meta2),
            ExtraAccountMeta::from(&extra_meta3),
            ExtraAccountMeta::from(&extra_meta4),
            extra_meta5,
        ];
        let other_metas = [ExtraAccountMeta::from(&other_meta1), other_meta2];

        let account_size = ExtraAccountMetaList::size_of(metas.len()).unwrap()
            + ExtraAccountMetaList::size_of(other_metas.len()).unwrap();
        let mut buffer = vec![0; account_size];

        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &metas).unwrap();
        ExtraAccountMetaList::init::<TestOtherInstruction>(&mut buffer, &other_metas).unwrap();

        let mock_rpc = MockRpc::setup(&[]);

        let program_id = Pubkey::new_unique();
        let ix_data = vec![0, 0, 0, 0, 0, 7, 0, 0];
        let ix_accounts = vec![];
        let mut instruction = Instruction::new_with_bytes(program_id, &ix_data, ix_accounts);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let check_extra_meta5_u8_arg = ix_data[5];
        let check_extra_meta5_pubkey = Pubkey::find_program_address(
            &[
                extra_meta5_literal_str.as_bytes(),
                extra_meta5_literal_u32.to_le_bytes().as_ref(),
                &[check_extra_meta5_u8_arg],
                extra_meta3.pubkey.as_ref(),
            ],
            &program_id,
        )
        .0;
        let check_metas = [
            extra_meta1,
            extra_meta2,
            extra_meta3,
            extra_meta4,
            AccountMeta::new(check_extra_meta5_pubkey, false),
        ];

        assert_eq!(
            instruction.accounts.get(4).unwrap().pubkey,
            check_extra_meta5_pubkey,
        );
        assert_eq!(instruction.accounts, check_metas,);

        let program_id = Pubkey::new_unique();
        let ix_account1 = AccountMeta::new(Pubkey::new_unique(), false);
        let ix_account2 = AccountMeta::new(Pubkey::new_unique(), true);
        let ix_accounts = vec![ix_account1.clone(), ix_account2.clone()];
        let ix_data = vec![0, 26, 0, 0, 0, 0, 0];
        let mut instruction = Instruction::new_with_bytes(program_id, &ix_data, ix_accounts);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestOtherInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let check_other_meta2_u32_arg = u32::from_le_bytes(ix_data[1..5].try_into().unwrap());
        let check_other_meta2_pubkey = Pubkey::find_program_address(
            &[
                other_meta2_literal_str.as_bytes(),
                check_other_meta2_u32_arg.to_le_bytes().as_ref(),
                ix_account1.pubkey.as_ref(),
            ],
            &program_id,
        )
        .0;
        let check_other_metas = [
            ix_account1,
            ix_account2,
            other_meta1,
            AccountMeta::new(check_other_meta2_pubkey, false),
        ];

        assert_eq!(
            instruction.accounts.get(3).unwrap().pubkey,
            check_other_meta2_pubkey,
        );
        assert_eq!(instruction.accounts, check_other_metas,);
    }

    #[tokio::test]
    async fn init_mixed() {
        let extra_meta5_literal_str = "seed_prefix";
        let extra_meta6_literal_u64 = 28u64;

        let pubkey1 = Pubkey::new_unique();
        let mut lamports1 = 0;
        let mut data1 = [];
        let pubkey2 = Pubkey::new_unique();
        let mut lamports2 = 0;
        let mut data2 = [];
        let pubkey3 = Pubkey::new_unique();
        let mut lamports3 = 0;
        let mut data3 = [];
        let owner = Pubkey::new_unique();
        let account_infos = [
            AccountInfo::new(
                &pubkey1,
                false,
                true,
                &mut lamports1,
                &mut data1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey2,
                true,
                false,
                &mut lamports2,
                &mut data2,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey3,
                false,
                false,
                &mut lamports3,
                &mut data3,
                &owner,
                false,
                Epoch::default(),
            ),
        ];

        let extra_meta1 = AccountMeta::new(Pubkey::new_unique(), false);
        let extra_meta2 = AccountMeta::new(Pubkey::new_unique(), true);
        let extra_meta3 = AccountMeta::new_readonly(Pubkey::new_unique(), true);
        let extra_meta4 = AccountMeta::new_readonly(Pubkey::new_unique(), false);
        let extra_meta5 = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::Literal {
                    bytes: extra_meta5_literal_str.as_bytes().to_vec(),
                },
                Seed::InstructionData {
                    index: 1,
                    length: 8, // [u8; 8]
                },
                Seed::InstructionData {
                    index: 9,
                    length: 32, // Pubkey
                },
                Seed::AccountKey { index: 2 },
            ],
            false,
            true,
        )
        .unwrap();
        let extra_meta6 = ExtraAccountMeta::new_with_seeds(
            &[
                Seed::Literal {
                    bytes: extra_meta6_literal_u64.to_le_bytes().to_vec(),
                },
                Seed::AccountKey { index: 1 },
                Seed::AccountKey { index: 4 },
            ],
            false,
            true,
        )
        .unwrap();

        let test_ix_required_extra_accounts = account_infos
            .iter()
            .map(ExtraAccountMeta::from)
            .collect::<Vec<_>>();
        let test_other_ix_required_extra_accounts = [
            ExtraAccountMeta::from(&extra_meta1),
            ExtraAccountMeta::from(&extra_meta2),
            ExtraAccountMeta::from(&extra_meta3),
            ExtraAccountMeta::from(&extra_meta4),
            extra_meta5,
            extra_meta6,
        ];

        let account_size = ExtraAccountMetaList::size_of(test_ix_required_extra_accounts.len())
            .unwrap()
            + ExtraAccountMetaList::size_of(test_other_ix_required_extra_accounts.len()).unwrap();
        let mut buffer = vec![0; account_size];

        ExtraAccountMetaList::init::<TestInstruction>(
            &mut buffer,
            &test_ix_required_extra_accounts,
        )
        .unwrap();
        ExtraAccountMetaList::init::<TestOtherInstruction>(
            &mut buffer,
            &test_other_ix_required_extra_accounts,
        )
        .unwrap();

        let mock_rpc = MockRpc::setup(&account_infos);

        let program_id = Pubkey::new_unique();
        let mut instruction = Instruction::new_with_bytes(program_id, &[], vec![]);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let test_ix_check_metas = account_infos
            .iter()
            .map(account_info_to_meta)
            .collect::<Vec<_>>();
        assert_eq!(instruction.accounts, test_ix_check_metas,);

        let program_id = Pubkey::new_unique();
        let instruction_u8array_arg = [1, 2, 3, 4, 5, 6, 7, 8];
        let instruction_pubkey_arg = Pubkey::new_unique();
        let mut instruction_data = vec![0];
        instruction_data.extend_from_slice(&instruction_u8array_arg);
        instruction_data.extend_from_slice(instruction_pubkey_arg.as_ref());
        let mut instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);
        ExtraAccountMetaList::add_to_instruction::<_, _, TestOtherInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        let check_extra_meta5_pubkey = Pubkey::find_program_address(
            &[
                extra_meta5_literal_str.as_bytes(),
                &instruction_u8array_arg,
                instruction_pubkey_arg.as_ref(),
                extra_meta3.pubkey.as_ref(),
            ],
            &program_id,
        )
        .0;

        let check_extra_meta6_pubkey = Pubkey::find_program_address(
            &[
                extra_meta6_literal_u64.to_le_bytes().as_ref(),
                extra_meta2.pubkey.as_ref(),
                check_extra_meta5_pubkey.as_ref(), // The first PDA should be at index 4
            ],
            &program_id,
        )
        .0;

        let test_other_ix_check_metas = vec![
            extra_meta1,
            extra_meta2,
            extra_meta3,
            extra_meta4,
            AccountMeta::new(check_extra_meta5_pubkey, false),
            AccountMeta::new(check_extra_meta6_pubkey, false),
        ];

        assert_eq!(
            instruction.accounts.get(4).unwrap().pubkey,
            check_extra_meta5_pubkey,
        );
        assert_eq!(
            instruction.accounts.get(5).unwrap().pubkey,
            check_extra_meta6_pubkey,
        );
        assert_eq!(instruction.accounts, test_other_ix_check_metas,);
    }

    #[tokio::test]
    async fn cpi_instruction() {
        // Say we have a program that CPIs to another program.
        //
        // Say that _other_ program will need extra account infos.

        // This will be our program
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        // Some seeds used by the program for PDAs
        let required_pda1_literal_string = "required_pda1";
        let required_pda2_literal_u32 = 4u32;

        // Define instruction data
        //  - 0: u8
        //  - 1-8: [u8; 8]
        //  - 9-16: u64
        let instruction_u8array_arg = [1, 2, 3, 4, 5, 6, 7, 8];
        let instruction_u64_arg = 208u64;
        let mut instruction_data = vec![0];
        instruction_data.extend_from_slice(&instruction_u8array_arg);
        instruction_data.extend_from_slice(instruction_u64_arg.to_le_bytes().as_ref());

        // Define known instruction accounts
        let ix_accounts = vec![
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ];

        // Define extra account metas required by the program we will CPI to
        let extra_meta1 = AccountMeta::new(Pubkey::new_unique(), false);
        let extra_meta2 = AccountMeta::new(Pubkey::new_unique(), true);
        let extra_meta3 = AccountMeta::new_readonly(Pubkey::new_unique(), false);
        let required_accounts = [
            ExtraAccountMeta::from(&extra_meta1),
            ExtraAccountMeta::from(&extra_meta2),
            ExtraAccountMeta::from(&extra_meta3),
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: required_pda1_literal_string.as_bytes().to_vec(),
                    },
                    Seed::InstructionData {
                        index: 1,
                        length: 8, // [u8; 8]
                    },
                    Seed::AccountKey { index: 1 },
                ],
                false,
                true,
            )
            .unwrap(),
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: required_pda2_literal_u32.to_le_bytes().to_vec(),
                    },
                    Seed::InstructionData {
                        index: 9,
                        length: 8, // u64
                    },
                    Seed::AccountKey { index: 5 },
                ],
                false,
                true,
            )
            .unwrap(),
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::InstructionData {
                        index: 0,
                        length: 1, // u8
                    },
                    Seed::AccountData {
                        account_index: 2,
                        data_index: 0,
                        length: 8,
                    },
                ],
                false,
                true,
            )
            .unwrap(),
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::AccountData {
                        account_index: 5,
                        data_index: 4,
                        length: 4,
                    }, // This one is a PDA!
                ],
                false,
                true,
            )
            .unwrap(),
        ];

        // Now here we're going to build the list of account infos
        // We'll need to include:
        //  - The instruction account infos for the program to CPI to
        //  - The extra account infos for the program to CPI to
        //  - Some other arbitrary account infos our program may use

        // First we need to manually derive each PDA
        let check_required_pda1_pubkey = Pubkey::find_program_address(
            &[
                required_pda1_literal_string.as_bytes(),
                &instruction_u8array_arg,
                ix_accounts.get(1).unwrap().pubkey.as_ref(), // The second account
            ],
            &program_id,
        )
        .0;
        let check_required_pda2_pubkey = Pubkey::find_program_address(
            &[
                required_pda2_literal_u32.to_le_bytes().as_ref(),
                instruction_u64_arg.to_le_bytes().as_ref(),
                check_required_pda1_pubkey.as_ref(), // The first PDA should be at index 5
            ],
            &program_id,
        )
        .0;
        let check_required_pda3_pubkey = Pubkey::find_program_address(
            &[
                &[0],    // Instruction "discriminator" (u8)
                &[8; 8], // The first 8 bytes of the data for account at index 2 (extra account 1)
            ],
            &program_id,
        )
        .0;
        let check_required_pda4_pubkey = Pubkey::find_program_address(
            &[
                &[7; 4], /* 4 bytes starting at index 4 of the data for account at index 5 (extra
                         * pda 1) */
            ],
            &program_id,
        )
        .0;

        // The instruction account infos for the program to CPI to
        let pubkey_ix_1 = ix_accounts.get(0).unwrap().pubkey;
        let mut lamports_ix_1 = 0;
        let mut data_ix_1 = [];
        let pubkey_ix_2 = ix_accounts.get(1).unwrap().pubkey;
        let mut lamports_ix_2 = 0;
        let mut data_ix_2 = [];

        // The extra account infos for the program to CPI to
        let mut lamports1 = 0;
        let mut data1 = [8; 12];
        let mut lamports2 = 0;
        let mut data2 = [];
        let mut lamports3 = 0;
        let mut data3 = [];
        let mut lamports_pda1 = 0;
        let mut data_pda1 = [7; 12];
        let mut lamports_pda2 = 0;
        let mut data_pda2 = [];
        let mut lamports_pda3 = 0;
        let mut data_pda3 = [];
        let mut lamports_pda4 = 0;
        let mut data_pda4 = [];

        // Some other arbitrary account infos our program may use
        let pubkey_arb_1 = Pubkey::new_unique();
        let mut lamports_arb_1 = 0;
        let mut data_arb_1 = [];
        let pubkey_arb_2 = Pubkey::new_unique();
        let mut lamports_arb_2 = 0;
        let mut data_arb_2 = [];

        let all_account_infos = [
            AccountInfo::new(
                &pubkey_ix_1,
                ix_accounts.get(0).unwrap().is_signer,
                ix_accounts.get(0).unwrap().is_writable,
                &mut lamports_ix_1,
                &mut data_ix_1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey_ix_2,
                ix_accounts.get(1).unwrap().is_signer,
                ix_accounts.get(1).unwrap().is_writable,
                &mut lamports_ix_2,
                &mut data_ix_2,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &extra_meta1.pubkey,
                required_accounts.get(0).unwrap().is_signer.into(),
                required_accounts.get(0).unwrap().is_writable.into(),
                &mut lamports1,
                &mut data1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &extra_meta2.pubkey,
                required_accounts.get(1).unwrap().is_signer.into(),
                required_accounts.get(1).unwrap().is_writable.into(),
                &mut lamports2,
                &mut data2,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &extra_meta3.pubkey,
                required_accounts.get(2).unwrap().is_signer.into(),
                required_accounts.get(2).unwrap().is_writable.into(),
                &mut lamports3,
                &mut data3,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &check_required_pda1_pubkey,
                required_accounts.get(3).unwrap().is_signer.into(),
                required_accounts.get(3).unwrap().is_writable.into(),
                &mut lamports_pda1,
                &mut data_pda1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &check_required_pda2_pubkey,
                required_accounts.get(4).unwrap().is_signer.into(),
                required_accounts.get(4).unwrap().is_writable.into(),
                &mut lamports_pda2,
                &mut data_pda2,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &check_required_pda3_pubkey,
                required_accounts.get(5).unwrap().is_signer.into(),
                required_accounts.get(5).unwrap().is_writable.into(),
                &mut lamports_pda3,
                &mut data_pda3,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &check_required_pda4_pubkey,
                required_accounts.get(6).unwrap().is_signer.into(),
                required_accounts.get(6).unwrap().is_writable.into(),
                &mut lamports_pda4,
                &mut data_pda4,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey_arb_1,
                false,
                true,
                &mut lamports_arb_1,
                &mut data_arb_1,
                &owner,
                false,
                Epoch::default(),
            ),
            AccountInfo::new(
                &pubkey_arb_2,
                false,
                true,
                &mut lamports_arb_2,
                &mut data_arb_2,
                &owner,
                false,
                Epoch::default(),
            ),
        ];

        // Let's use a mock RPC and set up a test instruction to check the CPI
        // instruction against later
        let rpc_account_infos = all_account_infos.clone();
        let mock_rpc = MockRpc::setup(&rpc_account_infos);

        let account_size = ExtraAccountMetaList::size_of(required_accounts.len()).unwrap();
        let mut buffer = vec![0; account_size];
        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &required_accounts).unwrap();

        let mut instruction =
            Instruction::new_with_bytes(program_id, &instruction_data, ix_accounts.clone());
        ExtraAccountMetaList::add_to_instruction::<_, _, TestInstruction>(
            &mut instruction,
            |pubkey| mock_rpc.get_account_data(pubkey),
            &buffer,
        )
        .await
        .unwrap();

        // Perform the account resolution for the CPI instruction

        // Create the instruction itself
        let mut cpi_instruction =
            Instruction::new_with_bytes(program_id, &instruction_data, ix_accounts);

        // Start with the known account infos
        let mut cpi_account_infos =
            vec![all_account_infos[0].clone(), all_account_infos[1].clone()];

        // Mess up the ordering of the account infos to make it harder!
        let mut messed_account_infos = all_account_infos.clone();
        messed_account_infos.swap(0, 4);
        messed_account_infos.swap(1, 2);
        messed_account_infos.swap(3, 4);
        messed_account_infos.swap(5, 6);
        messed_account_infos.swap(8, 7);

        // Resolve the rest!
        ExtraAccountMetaList::add_to_cpi_instruction::<TestInstruction>(
            &mut cpi_instruction,
            &mut cpi_account_infos,
            &buffer,
            &messed_account_infos,
        )
        .unwrap();

        // Our CPI instruction should match the check instruction.
        assert_eq!(cpi_instruction, instruction);

        // CPI account infos should have the instruction account infos
        // and the extra required account infos from the validation account,
        // and they should be in the correct order.
        let check_account_infos = &all_account_infos[..9];
        assert_eq!(cpi_account_infos.len(), check_account_infos.len());
        for (a, b) in std::iter::zip(cpi_account_infos, check_account_infos) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.is_signer, b.is_signer);
            assert_eq!(a.is_writable, b.is_writable);
        }
    }

    #[test]
    fn check_account_infos_test() {
        let program_id = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        // Create a list of required account metas
        let pubkey1 = Pubkey::new_unique();
        let pubkey2 = Pubkey::new_unique();
        let required_accounts = [
            ExtraAccountMeta::new_with_pubkey(&pubkey1, false, true).unwrap(),
            ExtraAccountMeta::new_with_pubkey(&pubkey2, false, false).unwrap(),
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: b"lit_seed".to_vec(),
                    },
                    Seed::InstructionData {
                        index: 0,
                        length: 4,
                    },
                    Seed::AccountKey { index: 0 },
                ],
                false,
                true,
            )
            .unwrap(),
        ];

        // Create the validation data
        let account_size = ExtraAccountMetaList::size_of(required_accounts.len()).unwrap();
        let mut buffer = vec![0; account_size];
        ExtraAccountMetaList::init::<TestInstruction>(&mut buffer, &required_accounts).unwrap();

        // Create the instruction data
        let instruction_data = vec![0, 1, 2, 3, 4, 5, 6, 7];

        // Set up a list of the required accounts as account infos,
        // with two instruction accounts
        let pubkey_ix_1 = Pubkey::new_unique();
        let mut lamports_ix_1 = 0;
        let mut data_ix_1 = [];
        let pubkey_ix_2 = Pubkey::new_unique();
        let mut lamports_ix_2 = 0;
        let mut data_ix_2 = [];
        let mut lamports1 = 0;
        let mut data1 = [];
        let mut lamports2 = 0;
        let mut data2 = [];
        let mut lamports3 = 0;
        let mut data3 = [];
        let pda = Pubkey::find_program_address(
            &[b"lit_seed", &instruction_data[..4], pubkey_ix_1.as_ref()],
            &program_id,
        )
        .0;
        let account_infos = [
            // Instruction account 1
            AccountInfo::new(
                &pubkey_ix_1,
                false,
                true,
                &mut lamports_ix_1,
                &mut data_ix_1,
                &owner,
                false,
                Epoch::default(),
            ),
            // Instruction account 2
            AccountInfo::new(
                &pubkey_ix_2,
                false,
                true,
                &mut lamports_ix_2,
                &mut data_ix_2,
                &owner,
                false,
                Epoch::default(),
            ),
            // Required account 1
            AccountInfo::new(
                &pubkey1,
                false,
                true,
                &mut lamports1,
                &mut data1,
                &owner,
                false,
                Epoch::default(),
            ),
            // Required account 2
            AccountInfo::new(
                &pubkey2,
                false,
                false,
                &mut lamports2,
                &mut data2,
                &owner,
                false,
                Epoch::default(),
            ),
            // Required account 3 (PDA)
            AccountInfo::new(
                &pda,
                false,
                true,
                &mut lamports3,
                &mut data3,
                &owner,
                false,
                Epoch::default(),
            ),
        ];

        // Create another list of account infos to intentionally mess up
        let mut messed_account_infos = account_infos.clone().to_vec();
        messed_account_infos.swap(0, 2);
        messed_account_infos.swap(1, 4);
        messed_account_infos.swap(3, 2);

        // Account info check should fail for the messed list
        assert_eq!(
            ExtraAccountMetaList::check_account_infos::<TestInstruction>(
                &messed_account_infos,
                &instruction_data,
                &program_id,
                &buffer,
            )
            .unwrap_err(),
            AccountResolutionError::IncorrectAccount.into(),
        );

        // Account info check should pass for the correct list
        assert_eq!(
            ExtraAccountMetaList::check_account_infos::<TestInstruction>(
                &account_infos,
                &instruction_data,
                &program_id,
                &buffer,
            ),
            Ok(()),
        );
    }
}
