//! # Core Types for JAM Protocol
//!
//! This module defines the fundamental types used throughout the JAM protocol.

use crate::utils::codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Represents public key bytes as unique account identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Decode, Encode)]
pub struct AccountId(pub [u8; 32]);

impl From<[u8; 32]> for AccountId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AccountId {
    /// Create a new AccountId from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get account ID as bytes slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Blake 3 hash as bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Decode, Encode)]
pub struct Hash(pub [u8; 32]);

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Hash {
    /// Create a zero hash (all bytes are zero)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Check if hash is all zeros
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

/// Block number in the chain
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct BlockNumber(pub u32);

impl From<u32> for BlockNumber {
    fn from(number: u32) -> Self {
        Self(number)
    }
}

impl From<BlockNumber> for u32 {
    fn from(block_number: BlockNumber) -> Self {
        block_number.0
    }
}

impl std::ops::Add<u32> for BlockNumber {
    type Output = Self;

    fn add(self, other: u32) -> Self {
        Self(self.0 + other)
    }
}

/// Unix timestamp in milliseconds
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct Timestamp(pub u64);

impl From<u64> for Timestamp {
    fn from(timestamp: u64) -> Self {
        Self(timestamp)
    }
}

impl From<Timestamp> for u64 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

impl Timestamp {
    /// Saturating subtraction
    pub fn saturating_sub(self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }
}

/// Weight represents computational cost
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct Weight(pub u64);

impl From<u64> for Weight {
    fn from(weight: u64) -> Self {
        Self(weight)
    }
}

impl From<Weight> for u64 {
    fn from(weight: Weight) -> Self {
        weight.0
    }
}

impl std::ops::Add for Weight {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Mul<u64> for Weight {
    type Output = Self;

    fn mul(self, other: u64) -> Self {
        Self(self.0 * other)
    }
}

impl std::iter::Sum for Weight {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(0), |acc, x| acc + x)
    }
}

impl std::iter::Sum<u64> for Weight {
    fn sum<I: Iterator<Item = u64>>(iter: I) -> Self {
        Self(iter.sum())
    }
}

/// Gas amount for computation
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct Gas(pub u64);

impl From<u64> for Gas {
    fn from(gas: u64) -> Self {
        Self(gas)
    }
}

impl From<Gas> for u64 {
    fn from(gas: Gas) -> Self {
        gas.0
    }
}

impl Gas {
    /// Saturating multiplication with u64
    pub fn saturating_mul(self, other: u64) -> Balance {
        Balance(self.0 as u128 * other as u128)
    }

    /// Convert to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// Balance type for token amounts
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct Balance(pub u128);

impl From<u128> for Balance {
    fn from(balance: u128) -> Self {
        Self(balance)
    }
}

impl From<Balance> for u128 {
    fn from(balance: Balance) -> Self {
        balance.0
    }
}

impl Balance {
    /// Zero balance
    pub const ZERO: Self = Self(0);

    /// Maximum balance
    pub const MAX: Self = Self(u128::MAX);

    /// Saturating multiplication
    pub fn saturating_mul(self, other: u64) -> Self {
        Self(self.0.saturating_mul(other as u128))
    }

    /// Saturating addition
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// Service identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Decode, Encode)]
pub struct ServiceId(pub u32);

impl ServiceId {
    /// Create a new ServiceId
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<u32> for ServiceId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<ServiceId> for u32 {
    fn from(service_id: ServiceId) -> Self {
        service_id.0
    }
}

/// Time slot in the JAM protocol
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Decode, Encode,
)]
pub struct TimeSlot(pub u32);

impl From<u32> for TimeSlot {
    fn from(slot: u32) -> Self {
        Self(slot)
    }
}

impl From<TimeSlot> for u32 {
    fn from(time_slot: TimeSlot) -> Self {
        time_slot.0
    }
}

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

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Signature::Ed25519(bytes) => {
                serializer.serialize_newtype_variant("Signature", 0, "Ed25519", &bytes.as_slice())
            }
            Signature::Ecdsa(bytes) => {
                serializer.serialize_newtype_variant("Signature", 1, "Ecdsa", &bytes.as_slice())
            }
            Signature::Bandersnatch(bytes) => serializer.serialize_newtype_variant(
                "Signature",
                2,
                "Bandersnatch",
                &bytes.as_slice(),
            ),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Error, Visitor};

        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a signature variant")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;

                let (variant, variant_access): (String, _) = data.variant()?;
                match variant.as_str() {
                    "Ed25519" => {
                        let bytes: Vec<u8> = variant_access.newtype_variant()?;
                        if bytes.len() != 64 {
                            return Err(Error::custom("Invalid Ed25519 signature length"));
                        }
                        let mut array = [0u8; 64];
                        array.copy_from_slice(&bytes);
                        Ok(Signature::Ed25519(array))
                    }
                    "Ecdsa" => {
                        let bytes: Vec<u8> = variant_access.newtype_variant()?;
                        if bytes.len() != 65 {
                            return Err(Error::custom("Invalid ECDSA signature length"));
                        }
                        let mut array = [0u8; 65];
                        array.copy_from_slice(&bytes);
                        Ok(Signature::Ecdsa(array))
                    }
                    "Bandersnatch" => {
                        let bytes: Vec<u8> = variant_access.newtype_variant()?;
                        if bytes.len() != 64 {
                            return Err(Error::custom("Invalid Bandersnatch signature length"));
                        }
                        let mut array = [0u8; 64];
                        array.copy_from_slice(&bytes);
                        Ok(Signature::Bandersnatch(array))
                    }
                    _ => Err(Error::unknown_variant(
                        &variant,
                        &["Ed25519", "Ecdsa", "Bandersnatch"],
                    )),
                }
            }
        }

        deserializer.deserialize_enum(
            "Signature",
            &["Ed25519", "Ecdsa", "Bandersnatch"],
            SignatureVisitor,
        )
    }
}

impl Signature {
    /// Create an Ed25519 signature
    pub fn ed25519(bytes: [u8; 64]) -> Self {
        Self::Ed25519(bytes)
    }

    /// Create an ECDSA signature
    pub fn ecdsa(bytes: [u8; 65]) -> Self {
        Self::Ecdsa(bytes)
    }

    /// Create a Bandersnatch signature
    pub fn bandersnatch(bytes: [u8; 64]) -> Self {
        Self::Bandersnatch(bytes)
    }

    /// Get the signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(bytes) => bytes,
            Self::Ecdsa(bytes) => bytes,
            Self::Bandersnatch(bytes) => bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id() {
        let bytes = [1u8; 32];
        let account_id = AccountId::from(bytes);
        assert_eq!(account_id.as_ref(), &bytes);
    }

    #[test]
    fn test_hash() {
        let bytes = [2u8; 32];
        let hash = Hash::from(bytes);
        assert_eq!(hash.as_ref(), &bytes);
    }

    #[test]
    fn test_block_number() {
        let number = 42u32;
        let block_number = BlockNumber::from(number);
        assert_eq!(u32::from(block_number), number);
    }

    #[test]
    fn test_timestamp() {
        let time = 1234567890u64;
        let timestamp = Timestamp::from(time);
        assert_eq!(u64::from(timestamp), time);
    }

    #[test]
    fn test_signature_types() {
        let ed25519_sig = Signature::ed25519([1u8; 64]);
        let ecdsa_sig = Signature::ecdsa([2u8; 65]);
        let bandersnatch_sig = Signature::bandersnatch([3u8; 64]);

        assert_eq!(ed25519_sig.as_bytes(), &[1u8; 64]);
        assert_eq!(ecdsa_sig.as_bytes(), &[2u8; 65]);
        assert_eq!(bandersnatch_sig.as_bytes(), &[3u8; 64]);
    }
}
