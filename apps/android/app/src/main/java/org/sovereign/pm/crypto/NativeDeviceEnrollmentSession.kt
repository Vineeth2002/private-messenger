package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.deviceInitializeForAccount
import org.sovereign.pm.crypto.uniffi.identityRestore
import org.sovereign.pm.crypto.uniffi.recoveryInitialize

/**
 * Owns an additional device's opaque native context for an in-progress enrollment.
 * DSK/DDHK private material never leaves Rust.
 *
 * This is an in-memory session, not a durable lifecycle implementation. The native certificate
 * binding is transient. After restoring a sealed record, call signEnrollmentCertificate again
 * with the same recovery mnemonic and epoch; compare its returned bytes with the exact certificate
 * already referenced by the server request before attempting proof-of-possession signing.
 */
class NativeDeviceEnrollmentSession private constructor(
    private val nativeDevice: AccountContext,
) : AutoCloseable {

    fun identity(): AccountIdentity = AccountIdentity(
        accountId = nativeDevice.accountId(),
        deviceId = nativeDevice.deviceId(),
        dskPublicKey = nativeDevice.dskPublicKey(),
        ddhkPublicKey = nativeDevice.ddhkPublicKey(),
    )

    /** Signs an enrollment certificate from this context's own IDs and public keys. */
    fun signEnrollmentCertificate(recoveryMnemonic: String, epoch: ULong): ByteArray {
        val recoveryContext = recoveryInitialize(recoveryMnemonic)
        return try {
            recoveryContext.signDeviceEnrollmentForDevice(nativeDevice, epoch)
        } finally {
            recoveryContext.close()
        }
    }

    /**
     * Signs PoP only for the exact certificate bound by signEnrollmentCertificate.
     * The server must still validate challenge freshness and consume the challenge atomically.
     */
    fun signProofOfPossession(
        enrollmentCertificate: ByteArray,
        challengeId: ByteArray,
        challengeNonce: ByteArray,
    ): ByteArray = nativeDevice.signDeviceEnrollmentPopForChallenge(
        enrollmentCertificate,
        challengeId,
        challengeNonce,
    )

    /** Seal the local identity record. The caller's transient Storage DEK buffer is cleared here. */
    fun sealForStorage(storageKey: ByteArray): ByteArray = try {
        nativeDevice.sealForStorage(storageKey)
    } finally {
        storageKey.fill(0)
    }

    override fun close() {
        nativeDevice.close()
    }

    companion object {
        /** Creates a fresh device identity while preserving a valid existing UUIDv7 account ID. */
        fun create(existingAccountId: ByteArray): NativeDeviceEnrollmentSession =
            NativeDeviceEnrollmentSession(deviceInitializeForAccount(existingAccountId))

        /** Restore a sealed native identity. Its transient certificate binding must be re-established. */
        fun restore(record: ByteArray, storageKey: ByteArray): NativeDeviceEnrollmentSession = try {
            NativeDeviceEnrollmentSession(identityRestore(record, storageKey))
        } finally {
            storageKey.fill(0)
        }
    }
}