//! # JAM Protocol Block Structures
//!
//! Block and block body definitions for the JAM protocol.
//! Based on the Gray Paper specification for JAM block structure.

use crate::utils::codec::{Decode, Encode};
use crate::{
    Hashable, PrimitiveError, PrimitiveResult, Validate,
    crypto::hashing::{Blake3Hasher, Hasher},
    header::Header,
    transaction::Transaction,
    types::{AccountId, BlockNumber, Gas, Hash, ServiceId, Signature, TimeSlot, Timestamp, Weight},
};
use serde::{Deserialize, Serialize};

/// A complete JAM block containing header and body
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct Block {
    /// Block header containing metadata
    pub header: Header,
    /// Block body containing transactions and other data
    pub body: BlockBody,
}

impl Block {
    /// Create a new block
    pub fn new(header: Header, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Get block number
    pub fn number(&self) -> BlockNumber {
        self.header.number
    }

    /// Get block hash (header hash)
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get parent hash
    pub fn parent_hash(&self) -> Hash {
        self.header.parent_hash
    }

    /// Get block timestamp
    pub fn timestamp(&self) -> Timestamp {
        self.header.timestamp
    }

    /// Get block weight
    pub fn weight(&self) -> Weight {
        self.body.weight()
    }

    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.number == BlockNumber(0)
    }

    /// Get all transactions in the block
    pub fn transactions(&self) -> &[Transaction] {
        &self.body.transactions
    }

    /// Get block size in bytes
    pub fn size(&self) -> usize {
        self.header.encoded_size() + self.body.encoded_size()
    }
}

impl Validate for Block {
    fn validate(&self) -> PrimitiveResult<()> {
        // Validate header
        self.header.validate()?;

        // Validate body
        self.body.validate()?;

        // Validate header-body consistency
        if self.header.extrinsics_root != self.body.hash() {
            return Err(PrimitiveError::InvalidBlock(
                "Header extrinsics root doesn't match computed body hash".to_string(),
            ));
        }

        // Validate block size
        if self.size() > crate::constants::MAX_BLOCK_SIZE as usize {
            return Err(PrimitiveError::SizeLimit(
                "Block exceeds maximum size limit".to_string(),
            ));
        }

        Ok(())
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// Block body containing the actual block data
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockBody {
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
    /// Availability data for erasure coding
    pub availability: AvailabilityData,
    /// Work reports from cores
    pub work_reports: Vec<WorkReport>,
    /// Guarantees for parachain blocks
    pub guarantees: Vec<Guarantee>,
    /// Preimages for services
    pub preimages: Vec<Preimage>,
}

impl BlockBody {
    /// Create a new empty block body
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            availability: AvailabilityData::new(),
            work_reports: Vec::new(),
            guarantees: Vec::new(),
            preimages: Vec::new(),
        }
    }

    /// Create a block body with transactions
    pub fn with_transactions(transactions: Vec<Transaction>) -> Self {
        Self {
            transactions,
            availability: AvailabilityData::new(),
            work_reports: Vec::new(),
            guarantees: Vec::new(),
            preimages: Vec::new(),
        }
    }

    /// Add a transaction to the block body
    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push(transaction);
    }

    /// Get total weight of all items in the body
    pub fn weight(&self) -> Weight {
        self.transactions
            .iter()
            .map(|tx| tx.weight())
            .sum::<Weight>()
            + Weight(self.work_reports.len() as u64) * 1000
            + Weight(self.guarantees.len() as u64) * 500
            + self
                .preimages
                .iter()
                .map(|p| Weight(p.data.len() as u64))
                .sum::<Weight>()
    }

    /// Get number of transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if body is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
            && self.work_reports.is_empty()
            && self.guarantees.is_empty()
            && self.preimages.is_empty()
    }

    /// Get encoded size
    pub fn encoded_size(&self) -> usize {
        self.encode().len()
    }
}

impl Default for BlockBody {
    fn default() -> Self {
        Self::new()
    }
}

impl Validate for BlockBody {
    fn validate(&self) -> PrimitiveResult<()> {
        // Validate all transactions
        for (i, tx) in self.transactions.iter().enumerate() {
            tx.validate().map_err(|e| {
                PrimitiveError::InvalidBlock(format!("Invalid transaction at index {}: {}", i, e))
            })?;
        }

        // Validate work reports
        for (i, report) in self.work_reports.iter().enumerate() {
            report.validate().map_err(|e| {
                PrimitiveError::InvalidBlock(format!("Invalid work report at index {}: {}", i, e))
            })?;
        }

        // Validate guarantees
        for (i, guarantee) in self.guarantees.iter().enumerate() {
            guarantee.validate().map_err(|e| {
                PrimitiveError::InvalidBlock(format!("Invalid guarantee at index {}: {}", i, e))
            })?;
        }

        Ok(())
    }
}

impl Hashable for BlockBody {
    fn hash(&self) -> Hash {
        let hasher = Blake3Hasher::new();
        hasher.hash(&self.encode())
    }
}

/// Availability data for erasure coding
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AvailabilityData {
    /// Erasure coded chunks
    pub chunks: Vec<AvailabilityChunk>,
}

impl AvailabilityData {
    /// Create new empty availability data
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }
}

impl Default for AvailabilityData {
    fn default() -> Self {
        Self::new()
    }
}

/// A single chunk of availability data
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AvailabilityChunk {
    /// Chunk index
    pub index: u32,
    /// Chunk data
    pub data: Vec<u8>,
    /// Proof for this chunk
    pub proof: Vec<u8>,
}

/// Work report from a core
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct WorkReport {
    /// Core index that produced this report
    pub core_index: u16,
    /// Work package hash
    pub package_hash: Hash,
    /// Result of work execution
    pub result: WorkResult,
    /// Context for work execution
    pub context: WorkContext,
    /// Authorizer signature
    pub authorizer_signature: Signature,
}

impl WorkReport {
    /// Create a new work report
    pub fn new(
        core_index: u16,
        package_hash: Hash,
        result: WorkResult,
        context: WorkContext,
        authorizer_signature: Signature,
    ) -> Self {
        Self {
            core_index,
            package_hash,
            result,
            context,
            authorizer_signature,
        }
    }
}

impl Validate for WorkReport {
    fn validate(&self) -> PrimitiveResult<()> {
        // Validate core index is within bounds
        if self.core_index >= crate::constants::MAX_CORES as u16 {
            return Err(PrimitiveError::InvalidBlock(
                "Core index exceeds maximum".to_string(),
            ));
        }

        // Validate result
        self.result.validate()?;

        Ok(())
    }
}

/// Result of work execution
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct WorkResult {
    /// Service that executed the work
    pub service_id: ServiceId,
    /// Payload hash
    pub payload_hash: Hash,
    /// Gas used
    pub gas_used: Gas,
    /// Result data
    pub result_data: Vec<u8>,
}

impl Validate for WorkResult {
    fn validate(&self) -> PrimitiveResult<()> {
        // Check result data size
        if self.result_data.len() > crate::constants::MAX_ACCUMULATION_SIZE as usize {
            return Err(PrimitiveError::SizeLimit(
                "Work result data exceeds maximum size".to_string(),
            ));
        }

        Ok(())
    }
}

/// Context for work execution
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct WorkContext {
    /// Anchor block hash
    pub anchor: Hash,
    /// State root at execution
    pub state_root: Hash,
    /// Lookup anchor
    pub lookup_anchor: Hash,
    /// Prerequisite work package
    pub prerequisite: Option<Hash>,
}

/// Guarantee for parachain block
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct Guarantee {
    /// Work report being guaranteed
    pub work_report: Hash,
    /// Timeslot
    pub timeslot: TimeSlot,
    /// Guarantor signatures
    pub signatures: Vec<(AccountId, Signature)>,
}

impl Validate for Guarantee {
    fn validate(&self) -> PrimitiveResult<()> {
        // Check minimum number of signatures
        if self.signatures.is_empty() {
            return Err(PrimitiveError::InvalidBlock(
                "Guarantee must have at least one signature".to_string(),
            ));
        }

        // Check for duplicate signers
        let mut signers = std::collections::HashSet::new();
        for (signer, _) in &self.signatures {
            if !signers.insert(signer) {
                return Err(PrimitiveError::InvalidBlock(
                    "Duplicate signer in guarantee".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Preimage data for services
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct Preimage {
    /// Hash of the preimage
    pub hash: Hash,
    /// Preimage data
    pub data: Vec<u8>,
}

impl Preimage {
    /// Create a new preimage
    pub fn new(data: Vec<u8>) -> Self {
        let hasher = Blake3Hasher::new();
        let hash = hasher.hash(&data);

        Self { hash, data }
    }

    /// Verify that the hash matches the data
    pub fn verify(&self) -> bool {
        let hasher = Blake3Hasher::new();
        hasher.hash(&self.data) == self.hash
    }
}
