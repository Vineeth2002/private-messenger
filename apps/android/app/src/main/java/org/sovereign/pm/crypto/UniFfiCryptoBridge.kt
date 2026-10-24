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

    private fun AccountContext.toPublicIdentity() = AccountIdentity(
        accountId = accountId(),
        deviceId = deviceId(),
        dskPublicKey = dskPublicKey(),
        ddhkPublicKey = ddhkPublicKey(),
    )
}
