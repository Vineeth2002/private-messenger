package org.sovereign.pm.messaging

/** Public routing metadata decoded from the strict canonical MessageEnvelopeV1 bytes. */
internal data class MessageEnvelopeMetadataV1(
    val envelopeId: ByteArray,
    val senderDeviceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val accountEpoch: Long,
    val isPrekeyHandshake: Boolean,
    val prekeyHeader: PrekeyHandshakeMetadataV1?,
)

internal data class PrekeyHandshakeMetadataV1(
    val senderAccountId: ByteArray,
    val senderAccountEpoch: Long,
    val senderDskPublicKey: ByteArray,
    val senderDdhkPublicKey: ByteArray,
    val senderCertDh: ByteArray,
    val senderCertDhTimestamp: Long,
    val senderEphemeralPublicKey: ByteArray,
    val recipientSpkId: Long,
)

/**
 * Strict fixed-schema reader for metadata only. It first delegates canonical-CBOR validation
 * to native Rust; it never performs cryptographic acceptance. Rust stage_decrypt_message remains
 * authoritative for envelope schema, peer binding, Cert_dh, ratchet and AEAD checks.
 */
internal object MessageEnvelopeV1Wire {
    private const val MAX_WIRE_BYTES = 65_552
    private const val MAX_HEADER_BYTES = 4_096

    fun decode(raw: ByteArray, nativeCanonicalCheck: (ByteArray) -> ByteArray): MessageEnvelopeMetadataV1 {
        require(raw.isNotEmpty() && raw.size <= MAX_WIRE_BYTES) { "Message envelope has an invalid size." }
        val canonical = nativeCanonicalCheck(raw.copyOf())
        try {
            require(canonical.contentEquals(raw)) { "Message envelope is not exact canonical CBOR." }
        } finally {
            canonical.fill(0)
        }
        val reader = Reader(raw)
        require(reader.mapLength() == 8UL) { "MessageEnvelopeV1 must contain exactly eight fields." }
        val fields = HashMap<Int, Any>(8)
        var previous = 0UL
        repeat(8) {
            val key = reader.uint()
            require(key in 1UL..8UL && key > previous) { "Message envelope keys are duplicated, unordered or unknown." }
            previous = key
            fields[key.toInt()] = when (key.toInt()) {
                1 -> reader.uint()
                2, 3, 4 -> reader.bytes(16).also { require(it.size == 16) }
                5 -> reader.uint()
                6 -> reader.boolean()
                7 -> reader.bytes(MAX_HEADER_BYTES)
                8 -> reader.bytes(MAX_WIRE_BYTES)
                else -> error("unreachable")
            }
        }
        reader.finished()
        require(fields.uint(1) == 1UL) { "Unsupported message envelope version." }
        val envelopeId = fields.bytes(2, 16)
        val senderDeviceId = fields.bytes(3, 16)
        val recipientDeviceId = fields.bytes(4, 16)
        val epoch = fields.uint(5)
        require(epoch in 1UL..4_294_967_295UL) { "Envelope recipient epoch is outside the u32 range." }
        val isPrekey = fields.boolean(6)
        val header = fields.bytes(7, null)
        require(fields.bytes(8, null).isNotEmpty()) { "Message ciphertext is empty." }
        val parsedHeader = if (isPrekey) decodePrekeyHeader(header) else null
        return MessageEnvelopeMetadataV1(
            envelopeId, senderDeviceId, recipientDeviceId, epoch.toLong(), isPrekey, parsedHeader,
        )
    }

    private fun decodePrekeyHeader(raw: ByteArray): PrekeyHandshakeMetadataV1 {
        require(raw.isNotEmpty() && raw.size <= MAX_HEADER_BYTES) { "Prekey handshake header is invalid." }
        val reader = Reader(raw)
        val count = reader.mapLength()
        require(count == 10UL || count == 11UL) { "Prekey handshake header has an invalid field count." }
        val fields = HashMap<Int, Any>(11)
        var previous = 0UL
        repeat(count.toInt()) {
            val key = reader.uint()
            require(key in 1UL..11UL && key > previous) { "Prekey header keys are duplicated, unordered or unknown." }
            previous = key
            fields[key.toInt()] = when (key.toInt()) {
                1 -> reader.bytes(16).also { require(it.size == 16) }
                2, 6, 8, 9, 11 -> reader.uint()
                3, 4, 7, 10 -> reader.bytes(32).also { require(it.size == 32) }
                5 -> reader.bytes(64).also { require(it.size == 64) }
                else -> error("unreachable")
            }
        }
        reader.finished()
        require(fields.keys.containsAll(setOf(1, 2, 3, 4, 5, 6, 7, 8, 10, 11))) {
            "Prekey handshake header is missing required fields."
        }
        require(fields.uint(11) == 0UL) { "Initial prekey handshake sequence must be zero." }
        require(fields.uint(8) in 1UL..4_294_967_295UL) { "Recipient SPK ID is invalid." }
        require(fields[9] == null) { "One-time prekeys are not supported by this alpha flow." }
        return PrekeyHandshakeMetadataV1(
            senderAccountId = fields.bytes(1, 16),
            senderAccountEpoch = fields.uint(2).also { require(it in 1UL..4_294_967_295UL) }.toLong(),
            senderDskPublicKey = fields.bytes(3, 32),
            senderDdhkPublicKey = fields.bytes(4, 32),
            senderCertDh = fields.bytes(5, 64),
            senderCertDhTimestamp = fields.uint(6).also { require(it > 0UL) }.toLong(),
            senderEphemeralPublicKey = fields.bytes(7, 32),
            recipientSpkId = fields.uint(8).toLong(),
        )
    }

    private class Reader(private val data: ByteArray) {
        private var offset = 0
        private data class Head(val major: Int, val value: ULong)
        fun mapLength(): ULong = head(5).value
        fun uint(): ULong = head(0).value
        fun boolean(): Boolean {
            require(offset < data.size) { "Truncated CBOR boolean." }
            return when (data[offset++].toInt() and 0xff) {
                0xf4 -> false
                0xf5 -> true
                else -> throw IllegalArgumentException("Expected a canonical CBOR boolean.")
            }
        }
        fun bytes(maximum: Int): ByteArray {
            val length = head(2).value
            require(length <= maximum.toULong() && length <= (data.size - offset).toULong()) {
                "CBOR byte string exceeds its bound or is truncated."
            }
            val count = length.toInt()
            return data.copyOfRange(offset, offset + count).also { offset += count }
        }
        fun finished() { require(offset == data.size) { "Trailing bytes follow the CBOR object." } }
        private fun head(expectedMajor: Int): Head {
            require(offset < data.size) { "Truncated CBOR object." }
            val first = data[offset++].toInt() and 0xff
            val major = first ushr 5
            val additional = first and 0x1f
            require(major == expectedMajor) { "Unexpected CBOR type." }
            val value = when (additional) {
                in 0..23 -> additional.toULong()
                24 -> readArg(1).also { require(it >= 24UL) }
                25 -> readArg(2).also { require(it >= 256UL) }
                26 -> readArg(4).also { require(it >= 65_536UL) }
                27 -> readArg(8).also { require(it >= 4_294_967_296UL) }
                else -> throw IllegalArgumentException("Indefinite/reserved CBOR is prohibited.")
            }
            return Head(major, value)
        }
        private fun readArg(size: Int): ULong {
            require(size <= data.size - offset) { "Truncated CBOR argument." }
            var result = 0UL
            repeat(size) { result = (result shl 8) or (data[offset++].toInt() and 0xff).toULong() }
            return result
        }
    }

    private fun Map<Int, Any>.uint(key: Int): ULong = this[key] as? ULong
        ?: throw IllegalArgumentException("Missing unsigned CBOR field $key.")
    private fun Map<Int, Any>.boolean(key: Int): Boolean = this[key] as? Boolean
        ?: throw IllegalArgumentException("Missing boolean CBOR field $key.")
    private fun Map<Int, Any>.bytes(key: Int, size: Int?): ByteArray {
        val bytes = this[key] as? ByteArray ?: throw IllegalArgumentException("Missing byte-string field $key.")
        if (size != null) require(bytes.size == size) { "CBOR field $key has an invalid length." }
        return bytes
    }
}
