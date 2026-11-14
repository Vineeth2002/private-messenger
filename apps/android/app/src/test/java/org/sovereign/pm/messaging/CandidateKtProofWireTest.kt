package org.sovereign.pm.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CandidateKtProofWireTest {
    @Test
    fun extractsCurrentTreeSizeAndExactSignedTreeHead() {
        val sth = makeSth(treeSize = 8UL)
        val proof = makeCurrentProof(sth, treeSize = 8UL)

        val parsed = CandidateKtProofWire.inspectCurrentProof(proof)

        assertEquals(8UL, parsed.treeSize)
        assertArrayEquals(sth, parsed.signedTreeHead)
        assertEquals(8UL, CandidateKtProofWire.readSignedTreeHead(parsed.signedTreeHead).treeSize)
    }

    @Test
    fun rejectsWrongCurrentProofFieldCount() {
        val raw = Cbor.map(listOf(1UL to Cbor.uint(1UL)))
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKtProofWire.inspectCurrentProof(raw)
        }
    }

    @Test
    fun rejectsNonCanonicalAndOutOfOrderProofMap() {
        val sth = makeSth(treeSize = 3UL)
        val pairs = currentProofPairs(sth, 3UL)
        val reversed = Cbor.map(pairs.reversed())
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKtProofWire.inspectCurrentProof(reversed)
        }

        val canonical = makeCurrentProof(sth, 3UL)
        // Replace the first byte of map(14) with a non-minimal map-length encoding.
        val nonCanonical = byteArrayOf(0xb8.toByte(), 0x0e) + canonical.copyOfRange(1, canonical.size)
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKtProofWire.inspectCurrentProof(nonCanonical)
        }
    }


    @Test
    fun rejectsProofTreeSizeThatDoesNotMatchSignedTreeHead() {
        val sth = makeSth(treeSize = 7UL)
        val proof = makeCurrentProof(sth, treeSize = 8UL)
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKtProofWire.inspectCurrentProof(proof)
        }
    }

    @Test
    fun rejectsSthWithInvalidFieldShape() {
        val malformed = Cbor.map(listOf(1UL to Cbor.uint(1UL)))
        assertThrows(IllegalArgumentException::class.java) {
            CandidateKtProofWire.readSignedTreeHead(malformed)
        }
    }

    private fun makeCurrentProof(sth: ByteArray, treeSize: ULong): ByteArray =
        Cbor.map(currentProofPairs(sth, treeSize))

    private fun currentProofPairs(sth: ByteArray, treeSize: ULong): List<Pair<ULong, ByteArray>> = listOf(
        1UL to Cbor.uint(1UL),
        2UL to Cbor.bytes(ByteArray(100) { 0x11 }),
        3UL to Cbor.bytes(ByteArray(32) { 0x01 }),
        4UL to Cbor.bytes(ByteArray(32) { 0x02 }),
        5UL to Cbor.bytes(ByteArray(32) { 0x03 }),
        6UL to Cbor.array(List(256) { Cbor.bytes(ByteArray(32) { 0x04 }) }),
        7UL to Cbor.uint(treeSize),
        8UL to Cbor.bytes(ByteArray(32) { 0x05 }),
        9UL to Cbor.uint(treeSize - 1UL),
        10UL to Cbor.bytes(byteArrayOf(0xa1.toByte(), 0x01, 0x01)),
        11UL to Cbor.array(emptyList()),
        12UL to Cbor.bytes(sth),
        13UL to Cbor.uint(treeSize),
        14UL to Cbor.array(emptyList()),
    )

    private fun makeSth(treeSize: ULong): ByteArray = Cbor.map(listOf(
        1UL to Cbor.uint(1UL),
        2UL to Cbor.uint(treeSize),
        3UL to Cbor.bytes(ByteArray(32) { 0x21 }),
        4UL to Cbor.bytes(ByteArray(32) { 0x22 }),
        5UL to Cbor.uint(1_234UL),
        6UL to Cbor.bytes(ByteArray(32) { 0x23 }),
        7UL to Cbor.bytes(ByteArray(64) { 0x24 }),
    ))

    private object Cbor {
        fun uint(value: ULong): ByteArray = head(0, value)
        fun bytes(value: ByteArray): ByteArray = head(2, value.size.toULong()) + value
        fun array(items: List<ByteArray>): ByteArray = head(4, items.size.toULong()) + items.fold(ByteArray(0)) { acc, item -> acc + item }
        fun map(items: List<Pair<ULong, ByteArray>>): ByteArray =
            head(5, items.size.toULong()) + items.fold(ByteArray(0)) { acc, (key, value) -> acc + uint(key) + value }

        private fun head(major: Int, value: ULong): ByteArray {
            val prefix = major shl 5
            return when {
                value <= 23UL -> byteArrayOf((prefix or value.toInt()).toByte())
                value <= 0xffUL -> byteArrayOf((prefix or 24).toByte(), value.toByte())
                value <= 0xffffUL -> byteArrayOf((prefix or 25).toByte(), (value shr 8).toByte(), value.toByte())
                value <= 0xffff_ffffUL -> byteArrayOf(
                    (prefix or 26).toByte(), (value shr 24).toByte(), (value shr 16).toByte(),
                    (value shr 8).toByte(), value.toByte(),
                )
                else -> byteArrayOf(
                    (prefix or 27).toByte(), (value shr 56).toByte(), (value shr 48).toByte(),
                    (value shr 40).toByte(), (value shr 32).toByte(), (value shr 24).toByte(),
                    (value shr 16).toByte(), (value shr 8).toByte(), value.toByte(),
                )
            }
        }
    }
}
