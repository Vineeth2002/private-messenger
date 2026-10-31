package org.sovereign.pm.crypto

data class AccountIdentity(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
)

/** A request signer pinned to one native device context, not a mutable bridge-wide account. */
interface DeviceRequestSigner : AutoCloseable {
    fun signDeviceHttpRequestV1(
        epoch: ULong,
        method: String,
        requestTarget: String,
        body: ByteArray,
    ): ByteArray

    override fun close()
}

interface CryptoBridge {
    fun decodeStrictCanonical(bytes: ByteArray): ByteArray
    fun generateRecoveryMnemonic(): String
    fun initializeAccount(): AccountIdentity
    fun sealCurrentAccount(storageKey: ByteArray): ByteArray
    fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity

    /**
     * Bind a signer to the exact identity supplied by the caller. Production implementations
     * must retain an independent native context so later account replacement cannot change keys.
     */
    fun bindDeviceRequestSigner(identity: AccountIdentity): DeviceRequestSigner
}
