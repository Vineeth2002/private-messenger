package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.decodeStrictCanonical as nativeDecodeStrictCanonical
import org.sovereign.pm.crypto.uniffi.identityInitialize
import org.sovereign.pm.crypto.uniffi.identityRestore
import org.sovereign.pm.crypto.uniffi.recoveryMnemonicGenerate

class UniFfiCryptoBridge : CryptoBridge {
    private var accountHandle: AccountContext? = null

    override fun decodeStrictCanonical(bytes: ByteArray): ByteArray =
        nativeDecodeStrictCanonical(bytes)

    override fun generateRecoveryMnemonic(): String = recoveryMnemonicGenerate()

    @Synchronized
    override fun initializeAccount(): AccountIdentity {
        val handle = identityInitialize()
        val identity = handle.toPublicIdentity()
        val previous = accountHandle
        accountHandle = handle
        previous?.close()
        return identity
    }

    @Synchronized
    override fun sealCurrentAccount(storageKey: ByteArray): ByteArray {
        val handle = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        return handle.sealForStorage(storageKey)
    }

    @Synchronized
    override fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity {
        val handle = identityRestore(record, storageKey)
        val identity = handle.toPublicIdentity()
        val previous = accountHandle
        accountHandle = handle
        previous?.close()
        return identity
    }

    /**
     * Clone the selected native context and bind it to the supplied public identity. The clone
     * remains valid if this bridge later restores or initializes another account.
     */
    @Synchronized
    override fun bindDeviceRequestSigner(identity: AccountIdentity): DeviceRequestSigner {
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val currentIdentity = current.toPublicIdentity()
        val matches = currentIdentity.accountId.contentEquals(identity.accountId) &&
            currentIdentity.deviceId.contentEquals(identity.deviceId) &&
            currentIdentity.dskPublicKey.contentEquals(identity.dskPublicKey) &&
            currentIdentity.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)
        require(matches) { "Requested signer identity does not match the active native account." }

        val boundHandle = AccountContext(current.uniffiClonePointer())
        return object : DeviceRequestSigner {
            private val lock = Any()
            private var closed = false

            override fun signDeviceHttpRequestV1(
                epoch: ULong,
                method: String,
                requestTarget: String,
                body: ByteArray,
            ): ByteArray = synchronized(lock) {
                check(!closed) { "Device request signer is closed." }
                boundHandle.signDeviceHttpRequestV1(epoch, method, requestTarget, body)
            }

            override fun close() = synchronized(lock) {
                if (!closed) {
                    closed = true
                    boundHandle.close()
                }
            }
        }
    }

    /**
     * Bind first-account authorization to the exact active identity already held by this bridge.
     * This clones the existing native context; it does not generate a replacement account/device.
     */
    @Synchronized
    fun beginInitialAccountBootstrap(identity: AccountIdentity): NativeInitialAccountBootstrapSession {
        val current = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        val currentIdentity = current.toPublicIdentity()
        val matches = currentIdentity.accountId.contentEquals(identity.accountId) &&
            currentIdentity.deviceId.contentEquals(identity.deviceId) &&
            currentIdentity.dskPublicKey.contentEquals(identity.dskPublicKey) &&
            currentIdentity.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)
        require(matches) { "Requested bootstrap identity does not match the active native account." }

        val boundHandle = AccountContext(current.uniffiClonePointer())
        return NativeInitialAccountBootstrapSession(boundHandle)
    }
    /**
     * Starts a separate in-memory enrollment context for a new device under an existing account.
     * It does not replace the bridge's current account handle or activate the new device.
     */
    fun beginAdditionalDeviceEnrollment(existingAccountId: ByteArray): NativeDeviceEnrollmentSession =
        NativeDeviceEnrollmentSession.create(existingAccountId)

    /** Restore a separately persisted enrollment-device context without changing the current account. */
    fun restoreAdditionalDeviceEnrollment(record: ByteArray, storageKey: ByteArray): NativeDeviceEnrollmentSession =
        NativeDeviceEnrollmentSession.restore(record, storageKey)

    private fun AccountContext.toPublicIdentity() = AccountIdentity(
        accountId = accountId(),
        deviceId = deviceId(),
        dskPublicKey = dskPublicKey(),
        ddhkPublicKey = ddhkPublicKey(),
    )
}
