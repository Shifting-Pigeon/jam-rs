//! # JAM Protocol Header Structures
//!
//! Block header definitions for the JAM protocol.
//! Based on the Gray Paper specification for JAM block headers.

use crate::utils::codec::{Decode, Encode};
use crate::{
    Hashable, PrimitiveError, PrimitiveResult, Validate,
    types::{AccountId, BlockNumber, Hash, Timestamp},
};
use serde::{Deserialize, Serialize};

/// JAM block header
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct Header {
    /// Hash of the parent block
    pub parent_hash: Hash,
    /// Block number (height in the chain)
    pub number: BlockNumber,
    /// Block timestamp (milliseconds since Unix epoch)
    pub timestamp: Timestamp,
    /// State root hash after applying this block
    pub state_root: Hash,
    /// Hash of extrinsics/transactions root
    pub extrinsics_root: Hash,
    /// Additional header data and proofs
    pub digest: Vec<Vec<u8>>,
    /// Block author
    pub author: AccountId,
    /// Current epoch
    pub epoch: u32,
    /// Slot within epoch
    pub slot: u32,
}

impl Header {
    /// Create a new header
    pub fn new(
        parent_hash: Hash,
        number: BlockNumber,
        timestamp: Timestamp,
        state_root: Hash,
        extrinsics_root: Hash,
        author: AccountId,
        epoch: u32,
        slot: u32,
    ) -> Self {
        Self {
            parent_hash,
            number,
            timestamp,
            state_root,
            extrinsics_root,
            digest: Vec::new(),
            author,
            epoch,
            slot,
        }
    }

    /// Check if this is a genesis block header
    pub fn is_genesis(&self) -> bool {
        self.number == BlockNumber(0)
    }

    /// Get encoded size of the header
    pub fn encoded_size(&self) -> usize {
        self.encode().len()
    }

    /// Verify the header is well-formed
    pub fn verify_basic(&self) -> PrimitiveResult<()> {
        // Genesis block should have zero parent hash
        if self.is_genesis() && !self.parent_hash.is_zero() {
            return Err(PrimitiveError::InvalidHeader(
                "Genesis block must have zero parent hash".to_string(),
            ));
        }

        // Non-genesis blocks should have non-zero parent hash
        if !self.is_genesis() && self.parent_hash.is_zero() {
            return Err(PrimitiveError::InvalidHeader(
                "Non-genesis block cannot have zero parent hash".to_string(),
            ));
        }

        // Validate timestamp (should be reasonable)
        if self.timestamp == Timestamp(0) {
            return Err(PrimitiveError::InvalidHeader(
                "Header timestamp cannot be zero".to_string(),
            ));
        }

        // Basic digest validation
        if self.digest.len() > 100 {
            return Err(PrimitiveError::InvalidHeader(
                "Too many digest items".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify header against parent
    pub fn verify_against_parent(&self, parent: &Header) -> PrimitiveResult<()> {
        // Check parent hash matches
        if self.parent_hash != parent.hash() {
            return Err(PrimitiveError::InvalidHeader(
                "Parent hash mismatch".to_string(),
            ));
        }

        // Check block number is sequential
        if self.number != parent.number + 1 {
            return Err(PrimitiveError::InvalidHeader(
                "Block number is not sequential".to_string(),
            ));
        }

        // Check timestamp is advancing
        if self.timestamp <= parent.timestamp {
            return Err(PrimitiveError::InvalidHeader(
                "Block timestamp must advance".to_string(),
            ));
        }

        // Check timestamp is not too far in the future (basic sanity check)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if self.timestamp > Timestamp(now + 60_000) {
            // 1 minute in the future
            return Err(PrimitiveError::InvalidHeader(
                "Block timestamp too far in the future".to_string(),
            ));
        }

        Ok(())
    }
}

impl Validate for Header {
    fn validate(&self) -> PrimitiveResult<()> {
        self.verify_basic()
    }
}

impl Hashable for Header {
    fn hash(&self) -> Hash {
        use crate::crypto::hashing::{Blake3Hasher, Hasher};
        let hasher = Blake3Hasher::new();
        hasher.hash(&self.encode())
    }
}

/// Header digest item
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct HeaderDigest {
    /// Engine identifier
    pub engine_id: [u8; 4],
    /// Digest data
    pub data: Vec<u8>,
}

impl HeaderDigest {
    /// Create new digest item
    pub fn new(engine_id: [u8; 4], data: Vec<u8>) -> Self {
        Self { engine_id, data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_account() -> AccountId {
        AccountId::new([1u8; 32])
    }

    #[test]
    fn test_header_creation() {
        let header = Header::new(
            Hash::zero(),
            BlockNumber(1),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert_eq!(header.number, BlockNumber(1));
        assert_eq!(header.timestamp, Timestamp(1000));
        assert!(!header.is_genesis());
    }

    #[test]
    fn test_genesis_header() {
        let genesis = Header::new(
            Hash::zero(),
            BlockNumber(0),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            0,
        );

        assert!(genesis.is_genesis());
        assert!(genesis.verify_basic().is_ok());
    }

    #[test]
    fn test_header_validation() {
        // Valid non-genesis header
        let parent_hash = Hash::from([1u8; 32]);
        let header = Header::new(
            parent_hash,
            BlockNumber(1),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert!(header.verify_basic().is_ok());

        // Invalid: non-genesis with zero parent hash
        let invalid_header = Header::new(
            Hash::zero(),
            BlockNumber(1),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert!(invalid_header.verify_basic().is_err());

        // Invalid: zero timestamp
        let zero_time_header = Header::new(
            parent_hash,
            BlockNumber(1),
            Timestamp(0),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            0,
        );
        assert!(zero_time_header.verify_basic().is_err());
    }

    #[test]
    fn test_header_parent_verification() {
        let parent = Header::new(
            Hash::zero(),
            BlockNumber(0),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            0,
        );

        let child = Header::new(
            parent.hash(),
            BlockNumber(1),
            Timestamp(2000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert!(child.verify_against_parent(&parent).is_ok());

        // Invalid: wrong parent hash
        let wrong_parent = Header::new(
            Hash::from([1u8; 32]),
            BlockNumber(1),
            Timestamp(2000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert!(wrong_parent.verify_against_parent(&parent).is_err());

        // Invalid: wrong block number
        let wrong_number = Header::new(
            parent.hash(),
            BlockNumber(3),
            Timestamp(2000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            3,
        );

        assert!(wrong_number.verify_against_parent(&parent).is_err());

        // Invalid: timestamp not advancing
        let same_time = Header::new(
            parent.hash(),
            BlockNumber(1),
            Timestamp(1000),
            Hash::zero(),
            Hash::zero(),
            dummy_account(),
            0,
            1,
        );

        assert!(same_time.verify_against_parent(&parent).is_err());
    }

    #[test]
    fn test_header_digest() {
        let digest = HeaderDigest::new(*b"TEST", vec![1, 2, 3]);
        assert_eq!(digest.engine_id, *b"TEST");
        assert_eq!(digest.data, vec![1, 2, 3]);
    }
}
