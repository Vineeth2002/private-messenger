package org.sovereign.pm.messaging

import org.sovereign.pm.crypto.CryptoBridge

internal data class DeviceDirectoryRecordV1(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val epoch: ULong,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
    val pushPublicKey: ByteArray?,
    val revoked: Boolean,
    val createdAt: ULong,
)

internal object DeviceDirectoryCborV1 {
    private const val MAX_DIRECTORY_BYTES = 4096
    private val REQUIRED_KEYS = setOf(1, 2, 3, 4, 5, 7, 8)

    fun decode(raw: ByteArray, crypto: CryptoBridge): DeviceDirectoryRecordV1 {
        require(raw.isNotEmpty() && raw.size <= MAX_DIRECTORY_BYTES) {
            "Device directory response has an invalid size"
        }

        // Native code verifies canonical CBOR. Kotlin then verifies this exact
        // application schema and rejects unknown or malformed fields.
        val canonical = crypto.decodeStrictCanonical(raw)
        require(canonical.contentEquals(raw)) {
            "Device directory response is not canonical"
        }

        val reader = Reader(raw)
        val mapLength = reader.readMapLength()
        require(mapLength == 7UL || mapLength == 8UL) {
            "Unexpected device directory map size"
        }

        var accountId: ByteArray? = null
        var deviceId: ByteArray? = null
        var epoch: ULong? = null
        var dskPublicKey: ByteArray? = null
        var ddhkPublicKey: ByteArray? = null
        var pushPublicKey: ByteArray? = null
        var revoked: Boolean? = null
        var createdAt: ULong? = null
        val seen = mutableSetOf<Int>()
        var previousKey = 0

        repeat(mapLength.toInt()) {
            val rawKey = reader.readUnsigned()
            require(rawKey <= 8UL) { "Unknown device directory key" }
            val key = rawKey.toInt()
            require(key > previousKey && seen.add(key)) {
                "Device directory keys are duplicated or out of order"
            }
            previousKey = key

            when (key) {
                1 -> accountId = reader.readByteString(16).also {
                    require(it.size == 16) { "Invalid account ID length" }
                }
                2 -> deviceId = reader.readByteString(16).also {
                    require(it.size == 16) { "Invalid device ID length" }
                }
                3 -> epoch = reader.readUnsigned().also {
                    require(it > 0UL) { "Invalid account epoch" }
                }
                4 -> dskPublicKey = reader.readByteString(32).also {
                    require(it.size == 32) { "Invalid DSK public key length" }
                }
                5 -> ddhkPublicKey = reader.readByteString(32).also {
                    require(it.size == 32) { "Invalid DDHK public key length" }
                }
                6 -> pushPublicKey = reader.readByteString(MAX_DIRECTORY_BYTES).also {
                    require(it.isNotEmpty()) { "Empty push public key" }
                }
                7 -> revoked = reader.readBoolean()
                8 -> createdAt = reader.readUnsigned().also {
                    require(it > 0UL) { "Invalid device creation timestamp" }
                }
                else -> throw IllegalArgumentException("Unknown device directory key: $key")
            }
        }

        reader.requireFinished()
        require(seen.containsAll(REQUIRED_KEYS)) {
            "Device directory is missing required fields"
        }
        require(seen.size == mapLength.toInt()) {
            "Device directory contains an invalid field set"
        }

        return DeviceDirectoryRecordV1(
            accountId = requireNotNull(accountId),
            deviceId = requireNotNull(deviceId),
            epoch = requireNotNull(epoch),
            dskPublicKey = requireNotNull(dskPublicKey),
            ddhkPublicKey = requireNotNull(ddhkPublicKey),
            pushPublicKey = pushPublicKey,
            revoked = requireNotNull(revoked),
            createdAt = requireNotNull(createdAt),
        )
    }

    private class Reader(private val data: ByteArray) {
        private var offset = 0

        fun readMapLength(): ULong {
            val head = readHead()
            require(head.majorType == 5) { "Expected a CBOR map" }
            return head.value
        }

        fun readUnsigned(): ULong {
            val head = readHead()
            require(head.majorType == 0) { "Expected an unsigned CBOR integer" }
            return head.value
        }

        fun readByteString(maxBytes: Int): ByteArray {
            val head = readHead()
            require(head.majorType == 2) { "Expected a CBOR byte string" }
            require(head.value <= maxBytes.toULong()) {
                "CBOR byte string exceeds its size limit"
            }
            val length = head.value.toInt()
            require(length <= data.size - offset) { "Truncated CBOR byte string" }
            return data.copyOfRange(offset, offset + length).also {
                offset += length
            }
        }

        fun readBoolean(): Boolean {
            require(offset < data.size) { "Truncated CBOR boolean" }
            return when (data[offset++].toInt() and 0xFF) {
                0xF4 -> false
                0xF5 -> true
                else -> throw IllegalArgumentException("Expected a CBOR boolean")
            }
        }

        fun requireFinished() {
            require(offset == data.size) { "Unexpected trailing bytes in device directory CBOR" }
        }

        private data class Head(val majorType: Int, val value: ULong)

        private fun readHead(): Head {
            require(offset < data.size) { "Truncated CBOR value" }
            val initial = data[offset++].toInt() and 0xFF
            val majorType = initial ushr 5
            val additionalInfo = initial and 0x1F
            val value = when (additionalInfo) {
                in 0..23 -> additionalInfo.toULong()
                24 -> readArgument(1).also {
                    require(it >= 24UL) { "Non-canonical CBOR integer" }
                }
                25 -> readArgument(2).also {
                    require(it >= 256UL) { "Non-canonical CBOR integer" }
                }
                26 -> readArgument(4).also {
                    require(it >= 65_536UL) { "Non-canonical CBOR integer" }
                }
                27 -> readArgument(8).also {
                    require(it >= 4_294_967_296UL) { "Non-canonical CBOR integer" }
                }
                else -> throw IllegalArgumentException(
                    "Indefinite or reserved CBOR length is not permitted"
                )
            }
            return Head(majorType, value)
        }

        private fun readArgument(byteCount: Int): ULong {
            require(byteCount <= data.size - offset) { "Truncated CBOR argument" }
            var result = 0UL
            repeat(byteCount) {
                result = (result shl 8) or (data[offset++].toInt() and 0xFF).toULong()
            }
            return result
        }
    }
}