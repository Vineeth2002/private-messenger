package org.sovereign.pm.messaging

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class MessageEnvelopeV1WireTest {
    @Test fun decodesCanonicalPrekeyEnvelopeAndHeaderMetadata() {
        val account = ByteArray(16) { (it + 1).toByte() }
        val sender = ByteArray(16) { (it + 17).toByte() }
        val recipient = ByteArray(16) { (it + 33).toByte() }
        val dsk = ByteArray(32) { (it + 1).toByte() }
        val ddhk = ByteArray(32) { (it + 2).toByte() }
        val cert = ByteArray(64) { (it + 3).toByte() }
        val eph = ByteArray(32) { (it + 4).toByte() }
        val header = mapOf(
            1 to bstr(account), 2 to uint(7), 3 to bstr(dsk), 4 to bstr(ddhk),
            5 to bstr(cert), 6 to uint(1_700_000_000), 7 to bstr(eph),
            8 to uint(9), 10 to bstr(ByteArray(32) { 5 }), 11 to uint(0),
        )
        val raw = mapOf(
            1 to uint(1), 2 to bstr(ByteArray(16) { 9 }), 3 to bstr(sender),
            4 to bstr(recipient), 5 to uint(3), 6 to byteArrayOf(0xf5.toByte()),
            7 to bstr(encodeMap(header)), 8 to bstr(byteArrayOf(1, 2, 3)),
        ).let(::encodeMap)
        val decoded = MessageEnvelopeV1Wire.decode(raw) { it.copyOf() }
        assertTrue(decoded.isPrekeyHandshake)
        assertArrayEquals(sender, decoded.senderDeviceId)
        assertArrayEquals(recipient, decoded.recipientDeviceId)
        assertArrayEquals(account, decoded.prekeyHeader!!.senderAccountId)
        assertEquals(7L, decoded.prekeyHeader.senderAccountEpoch)
        assertEquals(9L, decoded.prekeyHeader.recipientSpkId)
    }

    @Test fun rejectsTruncatedAndWrongSchemaEnvelopes() {
        assertThrows(IllegalArgumentException::class.java) {
            MessageEnvelopeV1Wire.decode(byteArrayOf(0xa0.toByte())) { it.copyOf() }
        }
        val wrong = encodeMap(mapOf(1 to uint(2)))
        assertThrows(IllegalArgumentException::class.java) {
            MessageEnvelopeV1Wire.decode(wrong) { it.copyOf() }
        }
    }

    private fun encodeMap(fields: Map<Int, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream(); out.write(head(5, fields.size.toULong()))
        for ((key, value) in fields.toSortedMap()) { out.write(uint(key.toLong())); out.write(value) }
        return out.toByteArray()
    }
    private fun uint(value: Long): ByteArray = head(0, value.toULong())
    private fun bstr(value: ByteArray): ByteArray = head(2, value.size.toULong()) + value
    private fun head(major: Int, value: ULong): ByteArray = when {
        value < 24UL -> byteArrayOf(((major shl 5) or value.toInt()).toByte())
        value <= 255UL -> byteArrayOf(((major shl 5) or 24).toByte(), value.toByte())
        value <= 65535UL -> byteArrayOf(((major shl 5) or 25).toByte(), (value.toInt() ushr 8).toByte(), value.toByte())
        value <= 4_294_967_295UL -> byteArrayOf(
            ((major shl 5) or 26).toByte(),
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte(),
        )
        else -> error("test helper only supports unsigned integers up to u32")
    }
}
