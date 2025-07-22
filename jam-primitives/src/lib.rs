pub mod block;
pub mod crypto;
pub mod header;
pub mod types;
pub mod utils;

// Re-export commonly used types and traits
pub use types::*;
pub use utils::codec::{Decode, Encode};

/// Common result type for primitive operations
pub type PrimitiveResult<T> = Result<T, PrimitiveError>;

/// Error types for primitive operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    /// Invalid data format
    InvalidFormat,
    /// Validation failed
    ValidationFailed(String),
    /// Encoding/decoding error
    CodecError(String),
    /// Cryptographic operation failed
    CryptoError(String),
    /// Invalid block structure or content
    InvalidBlock(String),
    /// Size limit exceeded
    SizeLimit(String),
    /// Invalid transaction
    InvalidTransaction(String),
    /// Invalid header
    InvalidHeader(String),
}

impl std::fmt::Display for PrimitiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrimitiveError::InvalidFormat => write!(f, "Invalid data format"),
            PrimitiveError::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
            PrimitiveError::CodecError(msg) => write!(f, "Codec error: {}", msg),
            PrimitiveError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            PrimitiveError::InvalidBlock(msg) => write!(f, "Invalid block: {}", msg),
            PrimitiveError::SizeLimit(msg) => write!(f, "Size limit exceeded: {}", msg),
            PrimitiveError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            PrimitiveError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
        }
    }
}

impl std::error::Error for PrimitiveError {}

/// Trait for types that can be hashed
pub trait Hashable {
    fn hash(&self) -> Hash;
}

/// Trait for types that can be validated
pub trait Validate {
    fn validate(&self) -> PrimitiveResult<()>;
}

/// Constants for the JAM protocol
pub mod constants {
    /// Maximum block size in bytes
    pub const MAX_BLOCK_SIZE: u32 = 4 * 1024 * 1024; // 4MB

    /// Maximum number of cores
    pub const MAX_CORES: u32 = 1023;

    /// Maximum accumulation size
    pub const MAX_ACCUMULATION_SIZE: u32 = 1024 * 1024; // 1MB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_error_display() {
        let err = PrimitiveError::ValidationFailed("test error".to_string());
        assert_eq!(format!("{}", err), "Validation failed: test error");
    }
}
