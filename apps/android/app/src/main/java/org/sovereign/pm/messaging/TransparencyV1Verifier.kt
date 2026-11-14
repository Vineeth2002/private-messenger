package org.sovereign.pm.messaging

import org.sovereign.pm.crypto.uniffi.ktVerifyDeviceProofV1
import org.sovereign.pm.crypto.uniffi.ktVerifySignedPrekeyBindingV1

internal enum class TransparencyTrustState { VERIFIED, DEGRADED }

internal data class VerifiedKtDeviceProof(
    val trustState: TransparencyTrustState,
    val treeSize: ULong,
    val signedTreeHead: ByteArray,
    val signedTreeHeadDigest: ByteArray,
    val logId: ByteArray,
    val smtRoot: ByteArray,
    val historyRoot: ByteArray,
    val leafWire: ByteArray,
    val accountId: ByteArray,
    val epoch: ULong,
    val deviceId: ByteArray,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
    val certDh: ByteArray,
    val signedPrekeyPublicKey: ByteArray,
    val pushPublicKey: ByteArray,
)

/**
 * Native KT V1 verification entry point. Trust anchors are supplied by trusted app
 * configuration, never learned from the gateway response. A valid proof with fewer
 * than two configured witness signatures is returned as DEGRADED, not VERIFIED.
 *
 * The caller must load the previously accepted signed tree head from its persistent
 * checkpoint store and pass it to verifyDeviceProof. After this returns, the caller
 * must atomically persist the new signed tree head before using the peer keys.
 */
internal class TransparencyV1Verifier(
    logPublicKey: ByteArray,
    expectedLogId: ByteArray,
    witnessRegistryCanonicalCbor: ByteArray,
) {
    private val pinnedLogPublicKey = logPublicKey.copyOf()
    private val pinnedLogId = expectedLogId.copyOf()
    private val pinnedWitnessRegistry = witnessRegistryCanonicalCbor.copyOf()

    init {
        require(pinnedLogPublicKey.size == 32) { "Pinned KT log public key must be 32 bytes." }
        require(pinnedLogId.size == 32) { "Pinned KT log ID must be 32 bytes." }
        require(pinnedWitnessRegistry.isNotEmpty()) { "Pinned KT witness registry is required." }
    }

    fun verifyDeviceProof(
        proofBundle: ByteArray,
        consistencyBundle: ByteArray,
        previousSignedTreeHead: ByteArray,
        expectedAccountId: ByteArray,
        expectedDeviceId: ByteArray,
    ): VerifiedKtDeviceProof {
        require(proofBundle.isNotEmpty()) { "KT proof bundle is empty." }
        require(expectedAccountId.size == 16) { "Expected account ID must be 16 bytes." }
        require(expectedDeviceId.size == 16) { "Expected device ID must be 16 bytes." }
        val result = ktVerifyDeviceProofV1(
            proofBundle.copyOf(),
            consistencyBundle.copyOf(),
            previousSignedTreeHead.copyOf(),
            pinnedLogPublicKey.copyOf(),
            pinnedLogId.copyOf(),
            expectedAccountId.copyOf(),
            expectedDeviceId.copyOf(),
            pinnedWitnessRegistry.copyOf(),
        )
        return VerifiedKtDeviceProofCbor.decode(result)
    }

    /** Ensures the gateway SPK object is DSK-signed and exactly matches the verified KT leaf. */
    fun verifySignedPrekeyBinding(
        verifiedProof: VerifiedKtDeviceProof,
        signedPrekeyWire: ByteArray,
    ): ByteArray {
        require(signedPrekeyWire.isNotEmpty()) { "Signed-prekey wire object is empty." }
        return ktVerifySignedPrekeyBindingV1(
            verifiedProof.leafWire.copyOf(),
            signedPrekeyWire.copyOf(),
        )
    }

    fun close() {
        pinnedLogPublicKey.fill(0)
        pinnedLogId.fill(0)
        pinnedWitnessRegistry.fill(0)
    }
}

private object VerifiedKtDeviceProofCbor {
    private const val REQUIRED_FIELDS = 17UL
    private const val MAX_RESULT_BYTES = 32 * 1024
    private const val MAX_LEAF_BYTES = 1024
    private const val MAX_STH_BYTES = 1024

    fun decode(raw: ByteArray): VerifiedKtDeviceProof {
        require(raw.isNotEmpty() && raw.size <= MAX_RESULT_BYTES) {
            "Native KT verification result has an invalid size."
        }
        val reader = Reader(raw)
        val count = reader.readMapLength()
        require(count == REQUIRED_FIELDS) { "Native KT verification result has an unexpected schema." }
        val values = HashMap<Int, Any>(REQUIRED_FIELDS.toInt())
        var previousKey = 0
        repeat(count.toInt()) {
            val key = reader.readUnsigned()
            require(key in 1UL..REQUIRED_FIELDS && key.toInt() > previousKey) {
                "Native KT result keys are duplicated, unordered or unknown."
            }
            previousKey = key.toInt()
            values[key.toInt()] = when (key.toInt()) {
                1, 2, 3, 11 -> reader.readUnsigned()
                4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17 -> {
                    val max = when (key.toInt()) {
                        4 -> MAX_STH_BYTES
                        9 -> MAX_LEAF_BYTES
                        10, 12 -> 16
                        11 -> 8
                        13, 14, 16, 17 -> 32
                        15 -> 64
                        else -> 32
                    }
                    reader.readByteString(max)
                }
                else -> throw IllegalArgumentException("Unexpected KT verification field.")
            }
        }
        reader.requireFinished()
        require(values[1] == 1UL) { "Unsupported native KT result version." }
        val trustState = when (values[2]) {
            1UL -> TransparencyTrustState.VERIFIED
            2UL -> TransparencyTrustState.DEGRADED
            else -> throw IllegalArgumentException("Native KT verifier returned an unknown trust state.")
        }
        val accountId = values.bytes(10, 16)
        val deviceId = values.bytes(12, 16)
        val dsk = values.bytes(13, 32)
        val ddhk = values.bytes(14, 32)
        val certDh = values.bytes(15, 64)
        val spk = values.bytes(16, 32)
        val push = values.bytes(17, 32)
        return VerifiedKtDeviceProof(
            trustState = trustState,
            treeSize = values.uint(3),
            signedTreeHead = values.boundedBytes(4, MAX_STH_BYTES),
            signedTreeHeadDigest = values.bytes(5, 32),
            logId = values.bytes(6, 32),
            smtRoot = values.bytes(7, 32),
            historyRoot = values.bytes(8, 32),
            leafWire = values.boundedBytes(9, MAX_LEAF_BYTES),
            accountId = accountId,
            epoch = values.uint(11),
            deviceId = deviceId,
            dskPublicKey = dsk,
            ddhkPublicKey = ddhk,
            certDh = certDh,
            signedPrekeyPublicKey = spk,
            pushPublicKey = push,
        )
    }

    private fun Map<Int, Any>.bytes(key: Int, expectedSize: Int): ByteArray {
        val value = this[key] as? ByteArray ?: throw IllegalArgumentException("Missing KT result bytes field $key.")
        require(value.size == expectedSize) { "KT result field $key has an invalid byte length." }
        return value
    }

    private fun Map<Int, Any>.boundedBytes(key: Int, maxSize: Int): ByteArray {
        val value = this[key] as? ByteArray ?: throw IllegalArgumentException("Missing KT result bytes field $key.")
        require(value.isNotEmpty() && value.size <= maxSize) { "KT result field $key has an invalid byte length." }
        return value
    }

    private fun Map<Int, Any>.uint(key: Int): ULong =
        this[key] as? ULong ?: throw IllegalArgumentException("Missing KT result integer field $key.")

    private class Reader(private val data: ByteArray) {
        private var offset = 0

        fun readMapLength(): ULong {
            val head = readHead()
            require(head.majorType == 5) { "Expected a canonical CBOR map." }
            return head.value
        }

        fun readUnsigned(): ULong {
            val head = readHead()
            require(head.majorType == 0) { "Expected a CBOR unsigned integer." }
            return head.value
        }

        fun readByteString(maxBytes: Int): ByteArray {
            val head = readHead()
            require(head.majorType == 2 && head.value <= maxBytes.toULong()) {
                "KT result byte string has an invalid length or type."
            }
            val size = head.value.toInt()
            require(size <= data.size - offset) { "Truncated KT result byte string." }
            return data.copyOfRange(offset, offset + size).also { offset += size }
        }

        fun requireFinished() {
            require(offset == data.size) { "Trailing bytes in native KT verification result." }
        }

        private data class Head(val majorType: Int, val value: ULong)

        private fun readHead(): Head {
            require(offset < data.size) { "Truncated KT verification result." }
            val first = data[offset++].toInt() and 0xFF
            val major = first ushr 5
            val additional = first and 0x1F
            val value = when (additional) {
                in 0..23 -> additional.toULong()
                24 -> readArgument(1).also { require(it >= 24UL) { "Non-canonical CBOR argument." } }
                25 -> readArgument(2).also { require(it >= 256UL) { "Non-canonical CBOR argument." } }
                26 -> readArgument(4).also { require(it >= 65_536UL) { "Non-canonical CBOR argument." } }
                27 -> readArgument(8).also { require(it >= 4_294_967_296UL) { "Non-canonical CBOR argument." } }
                else -> throw IllegalArgumentException("Indefinite or reserved CBOR value is prohibited.")
            }
            return Head(major, value)
        }

        private fun readArgument(size: Int): ULong {
            require(size <= data.size - offset) { "Truncated CBOR argument." }
            var result = 0UL
            repeat(size) {
                result = (result shl 8) or (data[offset++].toInt() and 0xFF).toULong()
            }
            return result
        }
    }
}
