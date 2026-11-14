package org.sovereign.pm.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class TransparencyCheckpointStoreTest {
    @Test
    fun checkpointSurvivesStoreRecreation() {
        val context = RuntimeEnvironment.getApplication()
        val fileName = "kt-v1-checkpoint-test-recreate.bin"
        File(context.noBackupFilesDir, fileName).delete()
        val first = TransparencyCheckpointStore(context, fileName)
        assertNull(first.loadCheckpoint())

        val sth = makeSth(treeSize = 5UL)
        first.persistVerified(makeVerified(sth, 5UL))

        val second = TransparencyCheckpointStore(context, fileName)
        assertArrayEquals(sth, second.loadCheckpoint())
        assertTrue(File(context.noBackupFilesDir, fileName).isFile)
    }

    @Test
    fun refusesRollbackAndSameSizeConflictingRoots() {
        val context = RuntimeEnvironment.getApplication()
        val fileName = "kt-v1-checkpoint-test-rollback.bin"
        File(context.noBackupFilesDir, fileName).delete()
        val store = TransparencyCheckpointStore(context, fileName)
        store.persistVerified(makeVerified(makeSth(5UL, rootByte = 0x31), 5UL))

        assertThrows(IllegalArgumentException::class.java) {
            store.persistVerified(makeVerified(makeSth(4UL, rootByte = 0x31), 4UL))
        }
        assertThrows(IllegalArgumentException::class.java) {
            store.persistVerified(makeVerified(makeSth(5UL, rootByte = 0x32), 5UL))
        }
        assertEqualsTreeSize(5UL, CandidateKtProofWire.readSignedTreeHead(store.loadCheckpoint()!!).treeSize)
    }

    @Test
    fun malformedExistingCheckpointFailsClosed() {
        val context = RuntimeEnvironment.getApplication()
        val fileName = "kt-v1-checkpoint-test-corrupt.bin"
        val file = File(context.noBackupFilesDir, fileName)
        file.delete()
        file.writeBytes(byteArrayOf(1, 2, 3, 4))

        val store = TransparencyCheckpointStore(context, fileName)
        assertThrows(IllegalArgumentException::class.java) {
            store.loadCheckpoint()
        }
        assertThrows(IllegalArgumentException::class.java) {
            store.persistVerified(makeVerified(makeSth(6UL), 6UL))
        }
    }

    private fun assertEqualsTreeSize(expected: ULong, actual: ULong) {
        org.junit.Assert.assertEquals(expected, actual)
    }

    private fun makeVerified(sth: ByteArray, treeSize: ULong): VerifiedKtDeviceProof {
        val parsed = CandidateKtProofWire.readSignedTreeHead(sth)
        return VerifiedKtDeviceProof(
            trustState = TransparencyTrustState.DEGRADED,
            treeSize = treeSize,
            signedTreeHead = sth,
            signedTreeHeadDigest = ByteArray(32) { 0x41 },
            logId = parsed.logId,
            smtRoot = parsed.smtRoot,
            historyRoot = parsed.historyRoot,
            leafWire = byteArrayOf(0xa0.toByte()),
            accountId = ByteArray(16) { 0x42 },
            epoch = 1UL,
            deviceId = ByteArray(16) { 0x43 },
            dskPublicKey = ByteArray(32) { 0x44 },
            ddhkPublicKey = ByteArray(32) { 0x45 },
            certDh = ByteArray(64) { 0x46 },
            signedPrekeyPublicKey = ByteArray(32) { 0x47 },
            pushPublicKey = ByteArray(32) { 0x48 },
        )
    }

    private fun makeSth(treeSize: ULong, rootByte: Byte = 0x31): ByteArray {
        fun uint(value: ULong): ByteArray = head(0, value)
        fun bytes(value: ByteArray): ByteArray = head(2, value.size.toULong()) + value
        val values = listOf(
            1UL to uint(1UL),
            2UL to uint(treeSize),
            3UL to bytes(ByteArray(32) { rootByte }),
            4UL to bytes(ByteArray(32) { 0x33 }),
            5UL to uint(1_234UL),
            6UL to bytes(ByteArray(32) { 0x34 }),
            7UL to bytes(ByteArray(64) { 0x35 }),
        )
        return head(5, values.size.toULong()) + values.fold(ByteArray(0)) { acc, (key, value) -> acc + uint(key) + value }
    }

    private fun head(major: Int, value: ULong): ByteArray {
        val prefix = major shl 5
        return when {
            value <= 23UL -> byteArrayOf((prefix or value.toInt()).toByte())
            value <= 0xffUL -> byteArrayOf((prefix or 24).toByte(), value.toByte())
            value <= 0xffffUL -> byteArrayOf((prefix or 25).toByte(), (value shr 8).toByte(), value.toByte())
            else -> error("Unexpected fixture argument size")
        }
    }
}
