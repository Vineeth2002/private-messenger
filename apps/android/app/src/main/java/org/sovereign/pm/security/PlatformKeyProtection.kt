package org.sovereign.pm.security

/**
 * PPAL (Platform Protection Assurance Level) baseline for V1 is Level 2:
 * protocol keys are generated/operated inside the zeroizing native Rust boundary,
 * encrypted at rest, and wrapped by a platform key-encryption key (KEK).
 *
 * NON-CLAIM: this layer does NOT assume the Android Keystore executes Ed25519 or
 * X25519. Keystore/StrongBox protect the KEK (storage wrapping), nothing more.
 */
enum class Ppal { LEVEL_1_HARDWARE_ISOLATED, LEVEL_2_WRAPPED_AT_REST }

enum class KekBacking { STRONGBOX, TEE, SOFTWARE }

data class KekCapabilities(val backing: KekBacking, val achievedPpal: Ppal)

interface PlatformKek {
    /** Capability discovery; never assume StrongBox. */
    fun discover(): KekCapabilities
    /** Wrap/unwrap opaque at-rest blobs. These bytes are ciphertext, not raw protocol secrets. */
    fun wrap(plaintextBlob: ByteArray): ByteArray
    fun unwrap(wrappedBlob: ByteArray): ByteArray
}

/** Phase A: intentionally unimplemented. Real implementation lands with the FFI boundary. */
class UnimplementedPlatformKek : PlatformKek {
    override fun discover(): KekCapabilities = TODO("Phase B: Android Keystore capability discovery")
    override fun wrap(plaintextBlob: ByteArray): ByteArray = TODO("Phase B")
    override fun unwrap(wrappedBlob: ByteArray): ByteArray = TODO("Phase B")
}
