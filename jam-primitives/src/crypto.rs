//! # Cryptographic Primitives for JAM Protocol
//!
//! This module provides cryptographic types and operations used throughout the JAM protocol.

use crate::types::Hash;
use crate::utils::codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl From<[u8; 32]> for Ed25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Ed25519Signature(pub [u8; 64]);

impl From<[u8; 64]> for Ed25519Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl serde::Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

/// Bandersnatch cryptographic operations module
pub mod bandersnatch {
    use super::*;

    /// Bandersnatch public key (32 bytes)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
    pub struct PublicKey(pub [u8; 32]);

    impl From<[u8; 32]> for PublicKey {
        fn from(bytes: [u8; 32]) -> Self {
            Self(bytes)
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    /// Bandersnatch signature (64 bytes)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
    pub struct Signature(pub [u8; 64]);

    impl From<[u8; 64]> for Signature {
        fn from(bytes: [u8; 64]) -> Self {
            Self(bytes)
        }
    }

    impl serde::Serialize for Signature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serde_bytes::serialize(&self.0, serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for Signature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("Invalid signature length"));
            }
            let mut array = [0u8; 64];
            array.copy_from_slice(&bytes);
            Ok(Self(array))
        }
    }
}

/// Hashing operations module
pub mod hashing {
    use super::*;

    /// Trait for cryptographic hashers
    pub trait Hasher {
        fn new() -> Self;
        fn hash(&self, data: &[u8]) -> Hash;
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> Hash;
    }

    /// Blake3 hasher implementation
    pub struct Blake3Hasher {
        hasher: blake3::Hasher,
    }

    impl Hasher for Blake3Hasher {
        fn new() -> Self {
            Self {
                hasher: blake3::Hasher::new(),
            }
        }

        fn hash(&self, data: &[u8]) -> Hash {
            let hash = blake3::hash(data);
            Hash(*hash.as_bytes())
        }

        fn update(&mut self, data: &[u8]) {
            self.hasher.update(data);
        }

        fn finalize(self) -> Hash {
            let hash = self.hasher.finalize();
            Hash(*hash.as_bytes())
        }
    }

    impl Default for Blake3Hasher {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Signature verification operations
pub mod signature {
    use super::*;

    /// Trait for signature verification
    pub trait Verify {
        type PublicKey;
        type Signature;

        fn verify(
            public_key: &Self::PublicKey,
            signature: &Self::Signature,
            message: &[u8],
        ) -> bool;
    }

    /// Ed25519 signature verification
    pub struct Ed25519Verifier;

    impl Verify for Ed25519Verifier {
        type PublicKey = Ed25519PublicKey;
        type Signature = Ed25519Signature;

        fn verify(
            _public_key: &Self::PublicKey,
            _signature: &Self::Signature,
            _message: &[u8],
        ) -> bool {
            // TODO: Implement actual Ed25519 signature verification
            // For now, return false as a placeholder
            // This should be implemented properly with the correct ed25519-dalek API
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashing::*;

    #[test]
    fn test_blake3_hasher() {
        let hasher = Blake3Hasher::new();
        let data = b"hello world";
        let hash1 = hasher.hash(data);
        let hash2 = hasher.hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_ed25519_public_key() {
        let bytes = [1u8; 32];
        let key = Ed25519PublicKey::from(bytes);
        assert_eq!(key.as_ref(), &bytes);
    }

    #[test]
    fn test_bandersnatch_public_key() {
        let bytes = [2u8; 32];
        let key = bandersnatch::PublicKey::from(bytes);
        assert_eq!(key.as_ref(), &bytes);
    }
}
