package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.decodeStrictCanonical as nativeDecodeStrictCanonical
import org.sovereign.pm.crypto.uniffi.identityInitialize
import org.sovereign.pm.crypto.uniffi.identityRestore

class UniFfiCryptoBridge : CryptoBridge {
    private var accountHandle: AccountContext? = null

    override fun decodeStrictCanonical(bytes: ByteArray): ByteArray =
        nativeDecodeStrictCanonical(bytes)

    override fun initializeAccount(): AccountIdentity {
        val handle = identityInitialize()
        accountHandle = handle
        return handle.toPublicIdentity()
    }

    override fun sealCurrentAccount(storageKey: ByteArray): ByteArray {
        val handle = accountHandle
            ?: throw IllegalStateException("No native account context is initialized.")
        return handle.sealForStorage(storageKey)
    }

    override fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity {
        val handle = identityRestore(record, storageKey)
        accountHandle = handle
        return handle.toPublicIdentity()
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
