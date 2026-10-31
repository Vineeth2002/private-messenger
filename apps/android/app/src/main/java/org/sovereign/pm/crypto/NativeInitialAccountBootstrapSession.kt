package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.recoveryInitialize

/** Public, non-secret protocol material for the first device of a new account. */
data class NativeInitialAccountAuthorization(
    val identity: AccountIdentity,
    val enrollmentCertificate: ByteArray,
    val recoveryPublicKey: ByteArray,
    val recoveryCommitment: ByteArray,
)

/**
 * In-memory first-account bootstrap bound to a clone of the bridge's existing native identity.
 * It intentionally does not allocate a device or accept a caller-supplied account epoch.
 * Recreate this session after process death from the restored identity and the user's backed-up
 * recovery phrase; the deterministic certificate can be re-derived and rebound before PoP.
 */
class NativeInitialAccountBootstrapSession internal constructor(
    private val nativeDevice: AccountContext,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun identity(): AccountIdentity {
        ensureOpen()
        return AccountIdentity(
            accountId = nativeDevice.accountId(),
            deviceId = nativeDevice.deviceId(),
            dskPublicKey = nativeDevice.dskPublicKey(),
            ddhkPublicKey = nativeDevice.ddhkPublicKey(),
        )
    }

    /**
     * Derive the recovery public key/commitment and sign this same device at initial epoch 1.
     * The recovery mnemonic is neither retained by this object nor returned to the caller.
     */
    @Synchronized
    fun signAuthorization(recoveryMnemonic: String): NativeInitialAccountAuthorization {
        ensureOpen()
        require(recoveryMnemonic.isNotBlank()) { "Recovery phrase must not be blank." }

        val recoveryContext = recoveryInitialize(recoveryMnemonic)
        return try {
            val recoveryPublicKey = recoveryContext.recoveryPublicKey()
            val recoveryCommitment = recoveryContext.recoveryCommitment()
            require(recoveryPublicKey.size == 32 && recoveryCommitment.size == 32) {
                "Native recovery material has an unexpected public length."
            }
            val certificate = recoveryContext.signDeviceEnrollmentForDevice(
                nativeDevice,
                INITIAL_ACCOUNT_EPOCH,
            )
            NativeInitialAccountAuthorization(
                identity = identity(),
                enrollmentCertificate = certificate,
                recoveryPublicKey = recoveryPublicKey,
                recoveryCommitment = recoveryCommitment,
            )
        } finally {
            recoveryContext.close()
        }
    }

    /** Sign proof of possession for the exact certificate previously bound by signAuthorization. */
    @Synchronized
    fun signProofOfPossession(
        enrollmentCertificate: ByteArray,
        challengeId: ByteArray,
        challengeNonce: ByteArray,
    ): ByteArray {
        ensureOpen()
        require(enrollmentCertificate.size in 1..MAX_CERTIFICATE_BYTES) {
            "Enrollment certificate has an invalid length."
        }
        require(challengeId.size == CHALLENGE_ID_BYTES) { "Challenge ID must be 16 bytes." }
        require(challengeNonce.size == CHALLENGE_NONCE_BYTES) { "Challenge nonce must be 32 bytes." }
        return nativeDevice.signDeviceEnrollmentPopForChallenge(
            enrollmentCertificate,
            challengeId,
            challengeNonce,
        )
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            nativeDevice.close()
        }
    }

    private fun ensureOpen() {
        check(!closed) { "Initial-account bootstrap session is closed." }
    }

    private companion object {
        const val INITIAL_ACCOUNT_EPOCH: ULong = 1UL
        const val MAX_CERTIFICATE_BYTES = 4096
        const val CHALLENGE_ID_BYTES = 16
        const val CHALLENGE_NONCE_BYTES = 32
    }
}