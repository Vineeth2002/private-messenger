package org.sovereign.pm.crypto

data class AccountIdentity(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
)

interface CryptoBridge {
    fun decodeStrictCanonical(bytes: ByteArray): ByteArray
    fun initializeAccount(): AccountIdentity
}
