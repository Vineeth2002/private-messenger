package org.sovereign.pm.security

import android.content.Context
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class IdentityStoreTest {

    private lateinit var context: Context
    private lateinit var recordFile: File

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        recordFile = File(context.noBackupFilesDir, FILE_NAME)
        removeTestArtifacts()
    }

    @After
    fun tearDown() {
        removeTestArtifacts()
    }

    @Test
    fun firstLaunchPersistsAndSubsequentLaunchRestoresIdentity() {
        val platformKek = FakePlatformKek()
        val firstBridge = FakeCryptoBridge()

        val created = IdentityStore(
            context,
            firstBridge,
            platformKek,
        ).loadOrCreate()

        assertEquals(
            IdentityOrigin.CREATED_AND_PERSISTED,
            created.origin,
        )
        assertTrue(recordFile.isFile)
        assertEquals(EXPECTED_FILE_BYTES.toLong(), recordFile.length())
        assertEquals(1, firstBridge.initializeCalls)

        val restoreBridge = FakeCryptoBridge()

        val restored = IdentityStore(
            context,
            restoreBridge,
            platformKek,
        ).loadOrCreate()

        assertEquals(IdentityOrigin.RESTORED, restored.origin)

        assertArrayEquals(
            created.identity.accountId,
            restored.identity.accountId,
        )
        assertArrayEquals(
            created.identity.deviceId,
            restored.identity.deviceId,
        )
        assertArrayEquals(
            created.identity.dskPublicKey,
            restored.identity.dskPublicKey,
        )
        assertArrayEquals(
            created.identity.ddhkPublicKey,
            restored.identity.ddhkPublicKey,
        )

        assertEquals(0, restoreBridge.initializeCalls)
        assertEquals(1, restoreBridge.restoreCalls)
    }

    @Test
    fun tamperedRecordFailsClosedWithoutReplacement() {
        val platformKek = FakePlatformKek()
        val firstBridge = FakeCryptoBridge()

        IdentityStore(
            context,
            firstBridge,
            platformKek,
        ).loadOrCreate()

        val tampered = recordFile.readBytes()
        tampered[tampered.lastIndex] =
            (tampered.last().toInt() xor 0x01).toByte()
        recordFile.writeBytes(tampered)

        val restoreBridge = FakeCryptoBridge()

        val failure = assertThrows(IllegalStateException::class.java) {
            IdentityStore(
                context,
                restoreBridge,
                platformKek,
            ).loadOrCreate()
        }

        assertTrue(
            failure.message.orEmpty().contains(
                "Saved identity could not be restored"
            )
        )
        assertEquals(0, restoreBridge.initializeCalls)
        assertArrayEquals(tampered, recordFile.readBytes())
    }

    @Test
    fun malformedRecordFailsClosedWithoutReplacement() {
        val platformKek = FakePlatformKek(keyExists = true)
        val bridge = FakeCryptoBridge()
        val malformed = byteArrayOf(1, 2, 3, 4)

        recordFile.writeBytes(malformed)

        assertThrows(IllegalStateException::class.java) {
            IdentityStore(
                context,
                bridge,
                platformKek,
            ).loadOrCreate()
        }

        assertEquals(0, bridge.initializeCalls)
        assertArrayEquals(malformed, recordFile.readBytes())
    }

    @Test
    fun missingRecordWithExistingStorageKeyFailsClosed() {
        val platformKek = FakePlatformKek(keyExists = true)
        val bridge = FakeCryptoBridge()

        assertFalse(recordFile.exists())

        assertThrows(IllegalStateException::class.java) {
            IdentityStore(
                context,
                bridge,
                platformKek,
            ).loadOrCreate()
        }

        assertEquals(0, bridge.initializeCalls)
        assertFalse(recordFile.exists())
    }

    @Test
    fun savedRecordWithMissingStorageKeyFailsClosed() {
        val platformKek = FakePlatformKek()
        val firstBridge = FakeCryptoBridge()

        IdentityStore(
            context,
            firstBridge,
            platformKek,
        ).loadOrCreate()

        val originalRecord = recordFile.readBytes()
        platformKek.keyExists = false

        val restoreBridge = FakeCryptoBridge()

        assertThrows(IllegalStateException::class.java) {
            IdentityStore(
                context,
                restoreBridge,
                platformKek,
            ).loadOrCreate()
        }

        assertEquals(0, restoreBridge.initializeCalls)
        assertArrayEquals(originalRecord, recordFile.readBytes())
    }

    private fun removeTestArtifacts() {
        listOf(
            recordFile,
            File(recordFile.path + ".bak"),
            File(recordFile.path + ".new"),
        ).forEach { file ->
            if (file.exists()) {
                check(file.delete()) {
                    "Could not clean test artifact: ${file.name}"
                }
            }
        }
    }

    private class FakeCryptoBridge : CryptoBridge {

        var initializeCalls = 0
            private set

        var restoreCalls = 0
            private set

        override fun decodeStrictCanonical(bytes: ByteArray): ByteArray =
            bytes.copyOf()

        override fun initializeAccount(): AccountIdentity {
            initializeCalls++
            return testIdentity()
        }

        override fun sealCurrentAccount(storageKey: ByteArray): ByteArray {
            require(storageKey.size == DEK_BYTES)
            return sealedRecord()
        }

        override fun restoreAccount(
            record: ByteArray,
            storageKey: ByteArray,
        ): AccountIdentity {
            restoreCalls++

            require(storageKey.size == DEK_BYTES)
            require(record.contentEquals(sealedRecord())) {
                "Test bridge rejected the modified sealed record."
            }

            return testIdentity()
        }
    }

    private class FakePlatformKek(
        var keyExists: Boolean = false,
    ) : PlatformKek {

        override fun hasExistingKey(): Boolean = keyExists

        override fun discover(): KekCapabilities = KekCapabilities(
            backing = KekBacking.SOFTWARE,
            achievedPpal = Ppal.LEVEL_2_WRAPPED_AT_REST,
        )

        override fun wrap(plaintextBlob: ByteArray): ByteArray {
            require(plaintextBlob.size == DEK_BYTES)

            keyExists = true

            return ByteArray(WRAPPED_DEK_BYTES) { index ->
                (index + 1).toByte()
            }
        }

        override fun unwrap(wrappedBlob: ByteArray): ByteArray {
            check(keyExists) {
                "Storage protection key is missing."
            }

            require(wrappedBlob.size == WRAPPED_DEK_BYTES)

            return ByteArray(DEK_BYTES) { index ->
                (index + 7).toByte()
            }
        }
    }

    private companion object {
        const val FILE_NAME = "identity-storage-v1.bin"
        const val DEK_BYTES = 32
        const val WRAPPED_DEK_BYTES = 60
        const val EXPECTED_FILE_BYTES = 202

        fun sealedRecord(): ByteArray =
            ByteArray(133) { index -> (index % 251).toByte() }

        fun testIdentity() = AccountIdentity(
            accountId = ByteArray(16) { (it + 1).toByte() },
            deviceId = ByteArray(16) { (it + 17).toByte() },
            dskPublicKey = ByteArray(32) { (it + 33).toByte() },
            ddhkPublicKey = ByteArray(32) { (it + 65).toByte() },
        )
    }
}
