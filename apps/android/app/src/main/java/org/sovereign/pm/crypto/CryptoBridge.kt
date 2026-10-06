package org.sovereign.pm.crypto

/**
 * Future UniFFI boundary to native/crypto-core.
 *
 * RULE: operational secrets (ratchet root/chain/message keys, DH intermediates, private
 * identity keys, push private keys, media keys) NEVER cross this boundary. Callers hold
 * only opaque handles; the sole audited exception is the recovery mnemonic during
 * setup/import (transient, never persisted). Managed memory cannot be zeroized with certainty.
 */
@JvmInline value class SessionHandle(val id: Long)

interface CryptoBridge {
    /** Verifies canonical PM-CBOR-2026 or throws a categorized error. */
    fun decodeStrictCanonical(bytes: ByteArray): ByteArray
    // Later: openSession(handle), encrypt(handle, plaintext), decrypt(handle, envelope) ...
}
