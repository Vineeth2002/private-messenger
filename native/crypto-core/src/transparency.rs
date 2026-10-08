//! Transparency validation policy layer for Sovereign Private Messenger.
//!
//! This module implements the frozen tri-state policy contract:
//! VERIFIED, DEGRADED, and SECURITY FAILURE.
//!
//! It intentionally does NOT implement the Sparse Merkle Tree, Signed Tree Head
//! wire format, witness signatures, leaf serialization, or inclusion proofs.
//! Those require authoritative transparency vectors/spec bytes before they can
//! be treated as production-verified protocol code.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparencyState {
    Verified,
    Degraded,
    SecurityFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparencyCondition {
    /// Valid inclusion proof + valid STH signature + full witness quorum.
    FullQuorumVerified,

    /// Operational availability problems that do not prove an attack.
    WitnessTimeout,
    NetworkOffline,
    IncompleteWitnessQuorum,
    CachedSthWithin24h,

    /// Cryptographic or rollback evidence that must fail closed.
    StaleTreeHead,
    InclusionProofMismatch,
    ConflictingTreeHead,
    UncertifiedPrekeyParameters,
}

impl TransparencyCondition {
    pub const fn state(self) -> TransparencyState {
        match self {
            Self::FullQuorumVerified => TransparencyState::Verified,
            Self::WitnessTimeout
            | Self::NetworkOffline
            | Self::IncompleteWitnessQuorum
            | Self::CachedSthWithin24h => TransparencyState::Degraded,
            Self::StaleTreeHead
            | Self::InclusionProofMismatch
            | Self::ConflictingTreeHead
            | Self::UncertifiedPrekeyParameters => TransparencyState::SecurityFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparencyError {
    StaleTreeHead,
    InclusionProofMismatch,
    ConflictingTreeHead,
    UncertifiedPrekeyParameters,
}

impl TransparencyError {
    pub const fn state(self) -> TransparencyState {
        TransparencyState::SecurityFailure
    }
}

/// Classify a transparency condition according to the frozen operational policy.
/// This function performs no cryptographic verification itself.
pub const fn classify(condition: TransparencyCondition) -> TransparencyState {
    condition.state()
}

/// Enforce the client high-water rule.
///
/// A received tree sequence strictly below the cached high-water value is a
/// security failure. Equal or greater sequences pass this policy check; STH
/// signatures, inclusion proofs, consistency proofs, and witness quorum are
/// verified by the cryptographic transparency layer that will be added later.
pub const fn validate_high_water(
    cached_high_water: u64,
    received_sequence: u64,
) -> Result<(), TransparencyError> {
    if received_sequence < cached_high_water {
        Err(TransparencyError::StaleTreeHead)
    } else {
        Ok(())
    }
}

/// Advance the cached high-water sequence only after the received tree head has
/// passed the cryptographic verification layer.
pub const fn advance_high_water(cached_high_water: u64, verified_sequence: u64) -> u64 {
    if verified_sequence > cached_high_water {
        verified_sequence
    } else {
        cached_high_water
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_quorum_is_verified() {
        assert_eq!(
            classify(TransparencyCondition::FullQuorumVerified),
            TransparencyState::Verified
        );
    }

    #[test]
    fn operational_failures_are_degraded() {
        for condition in [
            TransparencyCondition::WitnessTimeout,
            TransparencyCondition::NetworkOffline,
            TransparencyCondition::IncompleteWitnessQuorum,
            TransparencyCondition::CachedSthWithin24h,
        ] {
            assert_eq!(classify(condition), TransparencyState::Degraded);
        }
    }

    #[test]
    fn cryptographic_faults_are_security_failures() {
        for condition in [
            TransparencyCondition::StaleTreeHead,
            TransparencyCondition::InclusionProofMismatch,
            TransparencyCondition::ConflictingTreeHead,
            TransparencyCondition::UncertifiedPrekeyParameters,
        ] {
            assert_eq!(classify(condition), TransparencyState::SecurityFailure);
        }
    }

    #[test]
    fn stale_sequence_fails_closed() {
        assert_eq!(
            validate_high_water(10, 9),
            Err(TransparencyError::StaleTreeHead)
        );
    }

    #[test]
    fn equal_or_newer_sequence_passes_high_water_policy() {
        assert_eq!(validate_high_water(10, 10), Ok(()));
        assert_eq!(validate_high_water(10, 11), Ok(()));
    }

    #[test]
    fn high_water_advances_only_forward() {
        assert_eq!(advance_high_water(10, 9), 10);
        assert_eq!(advance_high_water(10, 10), 10);
        assert_eq!(advance_high_water(10, 11), 11);
    }

    #[test]
    fn every_security_error_is_fatal() {
        for error in [
            TransparencyError::StaleTreeHead,
            TransparencyError::InclusionProofMismatch,
            TransparencyError::ConflictingTreeHead,
            TransparencyError::UncertifiedPrekeyParameters,
        ] {
            assert_eq!(error.state(), TransparencyState::SecurityFailure);
        }
    }
}
