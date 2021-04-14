//! Error types

use {
    num_derive::FromPrimitive,
    solana_program::{
        decode_error::DecodeError,
        msg,
        program_error::{PrintProgramError, ProgramError},
    },
    thiserror::Error,
};

/// Errors that may be returned by the Metadata program.
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum MetadataError {
    /// Invalid instruction data passed in.
    #[error("Failed to unpack instruction data")]
    InstructionUnpackError,

    /// Lamport balance below rent-exempt threshold.
    #[error("Lamport balance below rent-exempt threshold")]
    NotRentExempt,

    /// Already initialized
    #[error("Already initialized")]
    AlreadyInitialized,

    /// Uninitialized
    #[error("Uninitialized")]
    Uninitialized,

    ///  Metadata's key must match seed of ['metadata', program id, mint] provided
    #[error(" Metadata's key must match seed of ['metadata', program id, mint] provided")]
    InvalidMetadataKey,

    ///  NameSymbolTuple's key must match seed of ['metadata', program id, name, symbol] provided
    #[error(
        "NameSymbolTuple's key must match seed of ['metadata', program id, name, symbol] provided"
    )]
    InvalidNameSymbolKey,

    ///  Edition's key must match seed of ['metadata', program id, name, 'edition'] provided
    #[error("Edition's key must match seed of ['metadata', program id, name, 'edition'] provided")]
    InvalidEditionKey,

    /// This NameSymbol does not own this metadata
    #[error("This NameSymbol does not own this metadata")]
    InvalidMetadataForNameSymbolTuple,

    /// Update Authority given does not match
    #[error("Update Authority given does not match")]
    UpdateAuthorityIncorrect,

    /// Update Authority needs to be signer to update  metadata
    #[error("Update Authority needs to be signer to update metadata")]
    UpdateAuthorityIsNotSigner,

    /// You must be the mint authority and signer on this transaction
    #[error("You must be the mint authority and signer on this transaction")]
    NotMintAuthority,

    /// Mint authority provided does not match the authority on the mint
    #[error("Mint authority provided does not match the authority on the mint")]
    InvalidMintAuthority,

    /// Name too long
    #[error("Name too long")]
    NameTooLong,

    /// Symbol too long
    #[error("Symbol too long")]
    SymbolTooLong,

    /// URI too long
    #[error("URI too long")]
    UriTooLong,

    /// Update authority must be equivalent to the name symbol tuple's authority and also signer of this transaction
    #[error("Update authority must be equivalent to the name symbol tuple's authority and also signer of this transaction")]
    UpdateAuthorityMustBeEqualToNameSymbolAuthorityAndSigner,

    /// Update authority must be equivalent to the metadata's authority and also signer of this transaction
    #[error("Update authority must be equivalent to the metadata's authority and also signer of this transaction")]
    UpdateAuthorityMustBeEqualToMetadataAuthorityAndSigner,

    /// Mint given does not match mint on Metadata
    #[error("Mint given does not match mint on Metadata")]
    MintMismatch,

    /// Master Records must have exactly one token
    #[error("Master Records must have exactly one token")]
    MasterRecordsMustHaveExactlyOneToken,

    /// Maximum editions printed already
    #[error("Maximum editions printed already")]
    MaxEditionsMintedAlready,

    /// Newly minted editions must have zero tokens
    #[error("Newly minted editions must have zero tokens")]
    NewlyMintedEditionsMustHaveZeroTokens,

    /// Token mint to failed
    #[error("Token mint to failed")]
    TokenMintToFailed,

    /// The master edition record passed must match the master record on the edition given
    #[error("The master edition record passed must match the master record on the edition given")]
    MasterRecordMismatch,

    /// The destination account for your new edition token does not have the right mint
    #[error("The destination account for your new edition token does not have the right mint")]
    DestinationMintMismatch,

    /// An edition can only mint one of its kind!
    #[error("An edition can only mint one of its kind!")]
    EditionAlreadyMinted,
}

impl PrintProgramError for MetadataError {
    fn print<E>(&self) {
        msg!(&self.to_string());
    }
}

impl From<MetadataError> for ProgramError {
    fn from(e: MetadataError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl<T> DecodeError<T> for MetadataError {
    fn type_of() -> &'static str {
        "Metadata Error"
    }
}
