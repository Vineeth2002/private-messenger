//! Crash-safe staging helpers for encrypted Double Ratchet snapshots.
//!
//! A transition is executed against a candidate restored from the active state's
//! zeroizing snapshot. The active state is never mutated by staging. The caller
//! persists `encrypted_snapshot` and its associated message record in one local
//! database transaction, then calls `into_committed_state` only after that
//! transaction has committed successfully.

use thiserror::Error;

use crate::double_ratchet::{RatchetError, RatchetState};
use crate::storage_record::{StorageRecordCipher, StorageRecordContext, StorageRecordError};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum RatchetPersistenceError {
    #[error("ratchet snapshot operation failed: {0}")]
    Ratchet(#[from] RatchetError),
    #[error("encrypted ratchet record operation failed: {0}")]
    Storage(#[from] StorageRecordError),
}

/// Seal a ratchet snapshot for durable storage. Plaintext snapshot bytes remain
/// inside Rust and are zeroized when this function returns.
pub(crate) fn seal_ratchet_state(
    state: &RatchetState,
    cipher: &StorageRecordCipher,
    context: &StorageRecordContext,
) -> Result<Vec<u8>, RatchetPersistenceError> {
    let snapshot = state.encode_persistence_snapshot()?;
    Ok(cipher.seal(context, snapshot.as_slice())?)
}

/// Restore a ratchet state only after record authentication and snapshot validation.
pub(crate) fn restore_ratchet_state(
    encrypted_record: &[u8],
    cipher: &StorageRecordCipher,
    context: &StorageRecordContext,
) -> Result<RatchetState, RatchetPersistenceError> {
    let snapshot = cipher.open(context, encrypted_record)?;
    Ok(RatchetState::restore_persistence_snapshot(
        snapshot.as_slice(),
    )?)
}

/// A staged transition owns a candidate state and the encrypted snapshot that
/// must be committed together with the associated message/outbox/inbox row.
/// It does not alter the active state supplied to `stage_ratchet_transition`.
pub(crate) struct StagedRatchetTransition<T> {
    output: T,
    encrypted_snapshot: Vec<u8>,
    candidate: RatchetState,
}

impl<T> StagedRatchetTransition<T> {
    pub(crate) fn output(&self) -> &T {
        &self.output
    }

    pub(crate) fn encrypted_snapshot(&self) -> &[u8] {
        &self.encrypted_snapshot
    }

    /// Call only after the SQLite transaction containing `encrypted_snapshot`
    /// and the corresponding message record has committed successfully.
    pub(crate) fn into_committed_state(self) -> RatchetState {
        self.candidate
    }
}

/// Apply one operation to an isolated candidate state and encrypt its resulting
/// snapshot. If the operation or sealing fails, the active state remains intact.
pub(crate) fn stage_ratchet_transition<T, F>(
    active: &RatchetState,
    cipher: &StorageRecordCipher,
    context: &StorageRecordContext,
    transition: F,
) -> Result<StagedRatchetTransition<T>, RatchetPersistenceError>
where
    F: FnOnce(&mut RatchetState) -> Result<T, RatchetError>,
{
    // RatchetState deliberately has no Clone implementation. Its strict snapshot
    // codec is the only supported way to make an independent candidate.
    let active_snapshot = active.encode_persistence_snapshot()?;
    let mut candidate = RatchetState::restore_persistence_snapshot(active_snapshot.as_slice())?;

    let output = transition(&mut candidate)?;
    let encrypted_snapshot = seal_ratchet_state(&candidate, cipher, context)?;

    Ok(StagedRatchetTransition {
        output,
        encrypted_snapshot,
        candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::double_ratchet::RatchetKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn test_state() -> RatchetState {
        let shared_secret: RatchetKey = [0x11; 32];
        let remote_private = StaticSecret::from([0x22; 32]);
        let remote_public = PublicKey::from(&remote_private).to_bytes();
        RatchetState::init_alice_from_test_bytes(&shared_secret, &remote_public, [0x33; 32])
            .expect("valid test ratchet state")
    }

    fn test_context(generation: u64) -> StorageRecordContext {
        StorageRecordContext {
            record_type: crate::storage_record::StorageRecordType::RatchetSnapshot,
            account_id: [0x41; 16],
            device_id: [0x42; 16],
            session_id: [0x43; 16],
            generation,
        }
    }

    #[test]
    fn encrypted_snapshot_roundtrip_restores_exact_ratchet_state() {
        let state = test_state();
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let context = test_context(1);

        let plaintext_snapshot = state.encode_persistence_snapshot().unwrap();
        let encrypted = seal_ratchet_state(&state, &cipher, &context).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext_snapshot.as_slice());

        let restored = restore_ratchet_state(&encrypted, &cipher, &context).unwrap();
        let restored_snapshot = restored.encode_persistence_snapshot().unwrap();
        assert_eq!(plaintext_snapshot.as_slice(), restored_snapshot.as_slice());
    }

    #[test]
    fn snapshot_rejects_wrong_generation_and_tampering() {
        let state = test_state();
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let context = test_context(9);
        let encrypted = seal_ratchet_state(&state, &cipher, &context).unwrap();

        assert!(restore_ratchet_state(&encrypted, &cipher, &test_context(10)).is_err());

        let mut tampered = encrypted;
        *tampered.last_mut().expect("tag exists") ^= 1;
        assert!(restore_ratchet_state(&tampered, &cipher, &context).is_err());
    }

    #[test]
    fn staged_transition_does_not_replace_active_state_before_commit() {
        let active = test_state();
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let context = test_context(2);
        let active_before = active.encode_persistence_snapshot().unwrap();

        let staged = stage_ratchet_transition(&active, &cipher, &context, |_candidate| {
            Ok(b"prepared-message".to_vec())
        })
        .expect("staging succeeds");

        assert_eq!(staged.output().as_slice(), b"prepared-message");
        let durable_candidate =
            restore_ratchet_state(staged.encrypted_snapshot(), &cipher, &context)
                .expect("staged encrypted snapshot restores");
        let durable_snapshot = durable_candidate.encode_persistence_snapshot().unwrap();
        assert_eq!(active_before.as_slice(), durable_snapshot.as_slice());

        // This is the promotion point. Production code must call it only after
        // the SQLite transaction has committed.
        let committed = staged.into_committed_state();
        let committed_snapshot = committed.encode_persistence_snapshot().unwrap();
        assert_eq!(active_before.as_slice(), committed_snapshot.as_slice());
    }

    #[test]
    fn failed_transition_leaves_active_state_unchanged() {
        let active = test_state();
        let cipher = StorageRecordCipher::new([0x44; 32]);
        let context = test_context(3);
        let before = active.encode_persistence_snapshot().unwrap();

        let result: Result<StagedRatchetTransition<()>, RatchetPersistenceError> =
            stage_ratchet_transition(&active, &cipher, &context, |_candidate| {
                Err(RatchetError::InvalidInitialState)
            });
        assert!(matches!(
            result,
            Err(RatchetPersistenceError::Ratchet(
                RatchetError::InvalidInitialState
            ))
        ));

        let after = active.encode_persistence_snapshot().unwrap();
        assert_eq!(before.as_slice(), after.as_slice());
    }
}
