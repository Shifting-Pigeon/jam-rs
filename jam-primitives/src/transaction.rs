//! # JAM Protocol Transaction Types
//!
//! Transaction types and structures for the JAM protocol as defined in the Gray Paper.
//! This module contains all transaction-related data structures and their validation logic.

use crate::utils::codec::{Decode, Encode};
use crate::{
    Hash, PrimitiveError, PrimitiveResult, Validate,
    types::{AccountId, Balance, Gas, ServiceId, Signature, Timestamp, Weight},
};
use serde::{Deserialize, Serialize};

/// Transaction nonce type
pub type Nonce = u64;

/// Transaction type identifier
pub type TransactionType = u8;

/// Gas price type (in smallest unit)
pub type GasPrice = u64;

/// Transaction kinds supported by JAM
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Transfer tokens between accounts
    Transfer {
        /// Destination account
        to: AccountId,
        /// Amount to transfer
        amount: Balance,
    },
    /// Call a service method
    ServiceCall {
        /// Target service
        service: ServiceId,
        /// Method identifier
        method: u32,
        /// Call data
        data: Vec<u8>,
    },
    /// Deploy a new service
    ServiceDeploy {
        /// Service code (WebAssembly)
        code: Vec<u8>,
        /// Initial service state
        initial_state: Vec<u8>,
    },
    /// Update service code
    ServiceUpdate {
        /// Service to update
        service: ServiceId,
        /// New service code
        code: Vec<u8>,
    },
    /// Register as a validator
    ValidatorRegister {
        /// Validator public keys
        keys: ValidatorKeys,
        /// Stake amount
        stake: Balance,
    },
    /// Unregister as a validator
    ValidatorUnregister,
    /// Delegate stake to a validator
    Delegate {
        /// Target validator
        validator: AccountId,
        /// Amount to delegate
        amount: Balance,
    },
    /// Undelegate stake from a validator
    Undelegate {
        /// Target validator
        validator: AccountId,
        /// Amount to undelegate
        amount: Balance,
    },
    /// Core assignment transaction
    CoreAssign {
        /// Core index to assign
        core: u16,
        /// Service to assign to core
        service: ServiceId,
        /// Assignment duration
        duration: u64,
    },
    /// Availability report
    AvailabilityReport {
        /// Core index
        core: u16,
        /// Availability data hash
        data_hash: Hash,
        /// Erasure coded chunks
        chunks: Vec<Vec<u8>>,
    },
    /// Dispute initiation
    DisputeInitiate {
        /// Disputed core
        core: u16,
        /// Block number being disputed
        block_number: u32,
        /// Dispute evidence
        evidence: Vec<u8>,
    },
    /// Dispute vote
    DisputeVote {
        /// Dispute ID
        dispute_id: Hash,
        /// Vote (true = valid, false = invalid)
        vote: bool,
        /// Justification
        justification: Vec<u8>,
    },
}

impl TransactionKind {
    /// Get the transaction type identifier
    pub fn transaction_type(&self) -> TransactionType {
        match self {
            TransactionKind::Transfer { .. } => 0,
            TransactionKind::ServiceCall { .. } => 1,
            TransactionKind::ServiceDeploy { .. } => 2,
            TransactionKind::ServiceUpdate { .. } => 3,
            TransactionKind::ValidatorRegister { .. } => 4,
            TransactionKind::ValidatorUnregister => 5,
            TransactionKind::Delegate { .. } => 6,
            TransactionKind::Undelegate { .. } => 7,
            TransactionKind::CoreAssign { .. } => 8,
            TransactionKind::AvailabilityReport { .. } => 9,
            TransactionKind::DisputeInitiate { .. } => 10,
            TransactionKind::DisputeVote { .. } => 11,
        }
    }

    /// Get human-readable transaction type name
    pub fn type_name(&self) -> &'static str {
        match self {
            TransactionKind::Transfer { .. } => "Transfer",
            TransactionKind::ServiceCall { .. } => "ServiceCall",
            TransactionKind::ServiceDeploy { .. } => "ServiceDeploy",
            TransactionKind::ServiceUpdate { .. } => "ServiceUpdate",
            TransactionKind::ValidatorRegister { .. } => "ValidatorRegister",
            TransactionKind::ValidatorUnregister => "ValidatorUnregister",
            TransactionKind::Delegate { .. } => "Delegate",
            TransactionKind::Undelegate { .. } => "Undelegate",
            TransactionKind::CoreAssign { .. } => "CoreAssign",
            TransactionKind::AvailabilityReport { .. } => "AvailabilityReport",
            TransactionKind::DisputeInitiate { .. } => "DisputeInitiate",
            TransactionKind::DisputeVote { .. } => "DisputeVote",
        }
    }

    /// Check if this transaction requires stake
    pub fn requires_stake(&self) -> bool {
        matches!(
            self,
            TransactionKind::ValidatorRegister { .. } | TransactionKind::Delegate { .. }
        )
    }

    /// Get the target service ID if applicable
    pub fn target_service(&self) -> Option<ServiceId> {
        match self {
            TransactionKind::ServiceCall { service, .. }
            | TransactionKind::ServiceUpdate { service, .. }
            | TransactionKind::CoreAssign { service, .. } => Some(*service),
            _ => None,
        }
    }

    /// Get the core index if applicable
    pub fn target_core(&self) -> Option<u16> {
        match self {
            TransactionKind::CoreAssign { core, .. }
            | TransactionKind::AvailabilityReport { core, .. }
            | TransactionKind::DisputeInitiate { core, .. } => Some(*core),
            _ => None,
        }
    }
}

/// Validator keys for registration
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ValidatorKeys {
    /// GRANDPA key for finality voting
    pub grandpa: crate::crypto::Ed25519PublicKey,
    /// BABE key for block production
    pub babe: crate::crypto::bandersnatch::PublicKey,
    /// Session key for networking
    pub session: crate::crypto::Ed25519PublicKey,
    /// Authority discovery key
    pub authority_discovery: crate::crypto::Ed25519PublicKey,
}

impl ValidatorKeys {
    /// Create new validator keys
    pub fn new(
        grandpa: crate::crypto::Ed25519PublicKey,
        babe: crate::crypto::bandersnatch::PublicKey,
        session: crate::crypto::Ed25519PublicKey,
        authority_discovery: crate::crypto::Ed25519PublicKey,
    ) -> Self {
        Self {
            grandpa,
            babe,
            session,
            authority_discovery,
        }
    }
}

/// Complete JAM transaction
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction sender
    pub sender: AccountId,
    /// Transaction nonce (prevents replay attacks)
    pub nonce: Nonce,
    /// Maximum gas to spend
    pub gas_limit: Gas,
    /// Gas price per unit
    pub gas_price: GasPrice,
    /// Transaction kind and parameters
    pub kind: TransactionKind,
    /// Digital signature
    pub signature: Signature,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        sender: AccountId,
        nonce: Nonce,
        gas_limit: Gas,
        gas_price: GasPrice,
        kind: TransactionKind,
        signature: Signature,
    ) -> Self {
        Self {
            sender,
            nonce,
            gas_limit,
            gas_price,
            kind,
            signature,
        }
    }

    /// Get transaction hash
    pub fn hash(&self) -> Hash {
        use crate::crypto::hashing::{Blake3Hasher, Hasher};
        let hasher = Blake3Hasher::new();
        hasher.hash(&self.encode())
    }

    /// Get transaction fee (gas_limit * gas_price)
    pub fn fee(&self) -> Balance {
        self.gas_limit.saturating_mul(self.gas_price)
    }

    /// Check if transaction is signed by the claimed sender
    pub fn verify_signature(&self) -> PrimitiveResult<bool> {
        // Create message to verify (all fields except signature)
        let _message = self.signature_message();

        // For now, we'll assume signature verification is handled elsewhere
        // In a real implementation, this would use the appropriate crypto module
        Ok(true) // Placeholder
    }

    /// Get the message that should be signed
    pub fn signature_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(self.sender.as_ref());
        message.extend_from_slice(&self.nonce.to_le_bytes());
        message.extend_from_slice(&self.gas_limit.0.to_le_bytes());
        message.extend_from_slice(&self.gas_price.to_le_bytes());
        message.extend_from_slice(&self.kind.encode());
        message
    }

    /// Check if transaction is a system transaction (no fee required)
    pub fn is_system_transaction(&self) -> bool {
        matches!(
            self.kind,
            TransactionKind::ValidatorUnregister
                | TransactionKind::AvailabilityReport { .. }
                | TransactionKind::DisputeVote { .. }
        )
    }

    /// Get the transaction weight (for block weight calculations)
    pub fn weight(&self) -> Weight {
        let base_weight = 10_000; // Base transaction weight
        let kind_weight = match &self.kind {
            TransactionKind::Transfer { .. } => 25_000,
            TransactionKind::ServiceCall { data, .. } => 50_000 + (data.len() as u64 * 10),
            TransactionKind::ServiceDeploy {
                code,
                initial_state,
            } => 100_000 + (code.len() as u64 * 50) + (initial_state.len() as u64 * 10),
            TransactionKind::ServiceUpdate { code, .. } => 80_000 + (code.len() as u64 * 50),
            TransactionKind::ValidatorRegister { .. } => 200_000,
            TransactionKind::ValidatorUnregister => 50_000,
            TransactionKind::Delegate { .. } => 30_000,
            TransactionKind::Undelegate { .. } => 30_000,
            TransactionKind::CoreAssign { .. } => 40_000,
            TransactionKind::AvailabilityReport { chunks, .. } => {
                60_000 + (chunks.iter().map(|c| c.len()).sum::<usize>() as u64 * 5)
            }
            TransactionKind::DisputeInitiate { evidence, .. } => {
                150_000 + (evidence.len() as u64 * 20)
            }
            TransactionKind::DisputeVote { justification, .. } => {
                30_000 + (justification.len() as u64 * 10)
            }
        };
        Weight(base_weight + kind_weight)
    }
}

impl Validate for Transaction {
    fn validate(&self) -> PrimitiveResult<()> {
        // Check gas limit is reasonable
        if self.gas_limit == Gas(0) {
            return Err(PrimitiveError::InvalidTransaction(
                "Gas limit cannot be zero".to_string(),
            ));
        }

        if self.gas_limit > Gas(10_000_000) {
            return Err(PrimitiveError::InvalidTransaction(
                "Gas limit too high".to_string(),
            ));
        }

        // Check gas price is reasonable
        if self.gas_price == 0 && !self.is_system_transaction() {
            return Err(PrimitiveError::InvalidTransaction(
                "Gas price cannot be zero for non-system transactions".to_string(),
            ));
        }

        // Validate transaction kind
        self.validate_kind()?;

        // Verify signature
        if !self.verify_signature()? {
            return Err(PrimitiveError::InvalidTransaction(
                "Invalid signature".to_string(),
            ));
        }

        Ok(())
    }
}

impl Transaction {
    /// Validate transaction kind-specific rules
    fn validate_kind(&self) -> PrimitiveResult<()> {
        match &self.kind {
            TransactionKind::Transfer { amount, .. } => {
                if *amount == Balance(0) {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Transfer amount cannot be zero".to_string(),
                    ));
                }
            }
            TransactionKind::ServiceCall { data, .. } => {
                if data.len() > 1024 * 1024 {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Service call data too large".to_string(),
                    ));
                }
            }
            TransactionKind::ServiceDeploy {
                code,
                initial_state,
            } => {
                if code.is_empty() {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Service code cannot be empty".to_string(),
                    ));
                }
                if code.len() > 5 * 1024 * 1024 {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Service code too large".to_string(),
                    ));
                }
                if initial_state.len() > 1024 * 1024 {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Initial state too large".to_string(),
                    ));
                }
            }
            TransactionKind::ServiceUpdate { code, .. } => {
                if code.is_empty() {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Service code cannot be empty".to_string(),
                    ));
                }
                if code.len() > 5 * 1024 * 1024 {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Service code too large".to_string(),
                    ));
                }
            }
            TransactionKind::ValidatorRegister { stake, .. } => {
                if *stake == Balance(0) {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Validator stake cannot be zero".to_string(),
                    ));
                }
            }
            TransactionKind::Delegate { amount, .. }
            | TransactionKind::Undelegate { amount, .. } => {
                if *amount == Balance(0) {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Delegation amount cannot be zero".to_string(),
                    ));
                }
            }
            TransactionKind::CoreAssign { duration, .. } => {
                if *duration == 0 {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Core assignment duration cannot be zero".to_string(),
                    ));
                }
            }
            TransactionKind::AvailabilityReport { chunks, .. } => {
                if chunks.is_empty() {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Availability report must include chunks".to_string(),
                    ));
                }
            }
            TransactionKind::DisputeInitiate { evidence, .. } => {
                if evidence.is_empty() {
                    return Err(PrimitiveError::InvalidTransaction(
                        "Dispute must include evidence".to_string(),
                    ));
                }
            }
            _ => {} // Other kinds have no specific validation
        }
        Ok(())
    }
}

/// Transaction pool entry with additional metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPoolEntry {
    /// The transaction
    pub transaction: Transaction,
    /// When it was received
    pub received_at: Timestamp,
    /// Priority score for ordering
    pub priority: u64,
    /// Number of times it was propagated
    pub propagation_count: u32,
}

impl TransactionPoolEntry {
    /// Create a new pool entry
    pub fn new(transaction: Transaction, received_at: Timestamp) -> Self {
        let priority = transaction.gas_price; // Simple priority based on gas price
        Self {
            transaction,
            received_at,
            priority,
            propagation_count: 0,
        }
    }

    /// Update priority based on current conditions
    pub fn update_priority(&mut self, current_time: Timestamp) {
        // Increase priority for older transactions
        let age_bonus = current_time.saturating_sub(self.received_at) / 1000; // Age in seconds
        self.priority = self.transaction.gas_price + age_bonus;
    }

    /// Check if transaction has expired
    pub fn is_expired(&self, current_time: Timestamp, max_lifetime: u64) -> bool {
        current_time.saturating_sub(self.received_at) > max_lifetime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn dummy_signature() -> Signature {
        Signature::Ed25519([0u8; 64])
    }

    fn dummy_account() -> AccountId {
        AccountId::from([0u8; 32])
    }

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(21000),
            20,
            TransactionKind::Transfer {
                to: AccountId::from([2u8; 32]),
                amount: Balance(1000),
            },
            dummy_signature(),
        );

        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.gas_limit, Gas(21000));
        assert_eq!(tx.fee(), Balance(420000));
    }

    #[test]
    fn test_transaction_kind_types() {
        let transfer = TransactionKind::Transfer {
            to: dummy_account(),
            amount: Balance(1000),
        };
        assert_eq!(transfer.transaction_type(), 0);
        assert_eq!(transfer.type_name(), "Transfer");
        assert!(!transfer.requires_stake());

        let validator_register = TransactionKind::ValidatorRegister {
            keys: ValidatorKeys::new(
                crate::crypto::Ed25519PublicKey::from([0u8; 32]),
                crate::crypto::bandersnatch::PublicKey::from([0u8; 32]),
                crate::crypto::Ed25519PublicKey::from([0u8; 32]),
                crate::crypto::Ed25519PublicKey::from([0u8; 32]),
            ),
            stake: Balance(1000000),
        };
        assert_eq!(validator_register.transaction_type(), 4);
        assert!(validator_register.requires_stake());
    }

    #[test]
    fn test_transaction_validation() {
        let valid_tx = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(21000),
            20,
            TransactionKind::Transfer {
                to: AccountId::from([2u8; 32]),
                amount: Balance(1000),
            },
            dummy_signature(),
        );
        assert!(valid_tx.validate().is_ok());

        let invalid_tx = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(0), // Invalid gas limit
            20,
            TransactionKind::Transfer {
                to: AccountId::from([2u8; 32]),
                amount: Balance(1000),
            },
            dummy_signature(),
        );
        assert!(invalid_tx.validate().is_err());
    }

    #[test]
    fn test_transaction_pool_entry() {
        let tx = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(21000),
            20,
            TransactionKind::Transfer {
                to: AccountId::from([2u8; 32]),
                amount: Balance(1000),
            },
            dummy_signature(),
        );

        let mut entry = TransactionPoolEntry::new(tx, Timestamp(1000000));
        assert_eq!(entry.priority, 20);

        entry.update_priority(Timestamp(1001000)); // 1 second later
        assert_eq!(entry.priority, 21); // Gas price + age bonus

        assert!(!entry.is_expired(Timestamp(1005000), 10000)); // Not expired
        assert!(entry.is_expired(Timestamp(1015000), 10000)); // Expired
    }

    #[test]
    fn test_transaction_weight_calculation() {
        let transfer = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(21000),
            20,
            TransactionKind::Transfer {
                to: AccountId::from([2u8; 32]),
                amount: Balance(1000),
            },
            dummy_signature(),
        );

        assert_eq!(transfer.weight(), Weight(35_000)); // Base + transfer weight

        let service_call = Transaction::new(
            AccountId::from([1u8; 32]),
            1,
            Gas(100000),
            20,
            TransactionKind::ServiceCall {
                service: ServiceId::new(1),
                method: 0,
                data: vec![0u8; 100],
            },
            dummy_signature(),
        );

        assert_eq!(service_call.weight(), Weight(61_000)); // Base + service call + data weight
    }
}
