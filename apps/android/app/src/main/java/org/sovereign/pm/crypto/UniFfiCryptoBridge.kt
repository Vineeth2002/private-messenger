package org.sovereign.pm.crypto

import org.sovereign.pm.crypto.uniffi.AccountContext
import org.sovereign.pm.crypto.uniffi.decodeStrictCanonical as nativeDecodeStrictCanonical
import org.sovereign.pm.crypto.uniffi.identityInitialize

class UniFfiCryptoBridge : CryptoBridge {
    private var accountHandle: AccountContext? = null

    override fun decodeStrictCanonical(bytes: ByteArray): ByteArray {
        return nativeDecodeStrictCanonical(bytes)
    }

    override fun initializeAccount(): AccountIdentity {
        val handle = identityInitialize()
        accountHandle = handle

        return AccountIdentity(
            accountId = handle.accountId(),
            deviceId = handle.deviceId(),
            dskPublicKey = handle.dskPublicKey(),
            ddhkPublicKey = handle.ddhkPublicKey(),
        )
    }
}
