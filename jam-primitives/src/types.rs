use crate::utils::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Represents public key bytes as unique account identifier
#[derive(Serialize, Deserialize, Decode, Encode)]
pub struct AccountId(pub [u8; 32]);

/// Blake 3 hash as bytes
#[derive(Serialize, Deserialize, Decode, Encode)]
pub struct Hash(pub [u8; 32]);

/// All supported signatures types generic enum
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Signature {
    /// Ed25519 signature (64 bytes)
    Ed25519([u8; 64]),
    /// ECDSA signature (65 bytes with recovery)
    Ecdsa([u8; 65]),
    /// Bandersnatch signature (for VRF operations)
    Bandersnatch([u8; 64]),
}
