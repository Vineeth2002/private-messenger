package org.sovereign.pm.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import java.io.File
import java.security.KeyStore

/**
 * Device/emulator integration tests. These exercise real UniFFI native code and a dedicated
 * test-only Keystore alias, never the production identity key.
 */
@RunWith(AndroidJUnit4::class)
class IdentityStoreInstrumentedTest {

    private lateinit var context: Context
    private lateinit var recordFile: File

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        recordFile = File(context.noBackupFilesDir, FILE_NAME)
        removeTestArtifacts()
    }

    @After
    fun tearDown() {
        removeTestArtifacts()
    }

    @Test
    fun firstLaunchAndNewNativeBridgeRestoreTheSameIdentity() {
        val created = newStore().loadOrCreate()

        assertEquals(IdentityOrigin.CREATED_AND_PERSISTED, created.origin)
        assertTrue(recordFile.isFile)
        assertEquals(EXPECTED_FILE_BYTES.toLong(), recordFile.length())
        assertEquals(Ppal.LEVEL_2_WRAPPED_AT_REST, created.kekCapabilities.achievedPpal)

        // New bridge and store instances exercise persisted restore with a new native handle.
        val restored = newStore().loadOrCreate()

        assertEquals(IdentityOrigin.RESTORED, restored.origin)
        assertArrayEquals(created.identity.accountId, restored.identity.accountId)
        assertArrayEquals(created.identity.deviceId, restored.identity.deviceId)
        assertArrayEquals(created.identity.dskPublicKey, restored.identity.dskPublicKey)
        assertArrayEquals(created.identity.ddhkPublicKey, restored.identity.ddhkPublicKey)
    }

    @Test
    fun tamperedSealedRecordFailsClosedAndPreservesTheFile() {
        newStore().loadOrCreate()
        val tampered = recordFile.readBytes()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
        recordFile.writeBytes(tampered)

        assertThrows(IllegalStateException::class.java) {
            newStore().loadOrCreate()
        }

        assertArrayEquals(tampered, recordFile.readBytes())
        assertTrue(testKeyExists())
    }

    @Test
    fun malformedRecordFailsClosedWithoutCreatingAStorageKey() {
        val malformed = byteArrayOf(1, 2, 3, 4, 5)
        recordFile.writeBytes(malformed)

        assertThrows(IllegalStateException::class.java) {
            newStore().loadOrCreate()
        }

        assertArrayEquals(malformed, recordFile.readBytes())
        assertFalse(testKeyExists())
    }

    @Test
    fun missingRecordWithExistingKeyFailsClosed() {
        newStore().loadOrCreate()
        assertTrue(recordFile.delete())

        assertThrows(IllegalStateException::class.java) {
            newStore().loadOrCreate()
        }

        assertFalse(recordFile.exists())
        assertTrue(testKeyExists())
    }

    @Test
    fun savedRecordWithMissingKeyFailsClosedWithoutReplacement() {
        newStore().loadOrCreate()
        val original = recordFile.readBytes()
        deleteTestKey()

        assertThrows(IllegalStateException::class.java) {
            newStore().loadOrCreate()
        }

        assertArrayEquals(original, recordFile.readBytes())
        assertFalse(testKeyExists())
    }

    @Test
    fun tamperedWrappedStorageKeyFailsClosedWithoutReplacement() {
        newStore().loadOrCreate()
        val original = recordFile.readBytes()
        // Outer header is 9 bytes; the wrapped DEK begins with a 12-byte AES-GCM IV.
        val tampered = original.copyOf()
        tampered[OUTER_HEADER_BYTES + AES_GCM_IV_BYTES] =
            (tampered[OUTER_HEADER_BYTES + AES_GCM_IV_BYTES].toInt() xor 0x01).toByte()
        recordFile.writeBytes(tampered)

        assertThrows(IllegalStateException::class.java) {
            newStore().loadOrCreate()
        }

        assertArrayEquals(tampered, recordFile.readBytes())
        assertTrue(testKeyExists())
    }

    private fun newStore(): IdentityStore =
        IdentityStore(
            context,
            UniFfiCryptoBridge(),
            AndroidKeystorePlatformKek(context, TEST_KEY_ALIAS),
            fileName = FILE_NAME,
        )

    private fun removeTestArtifacts() {
        listOf(
            recordFile,
            File(recordFile.path + ".bak"),
            File(recordFile.path + ".new"),
        ).forEach { file ->
            if (file.exists()) {
                check(file.delete()) { "Could not clean test artifact: ${file.name}" }
            }
        }
        deleteTestKey()
    }

    private fun testKeyExists(): Boolean = keyStore().containsAlias(TEST_KEY_ALIAS)

    private fun deleteTestKey() {
        val keyStore = keyStore()
        if (keyStore.containsAlias(TEST_KEY_ALIAS)) keyStore.deleteEntry(TEST_KEY_ALIAS)
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        // Strictly separate from the production identity-storage-v1.bin file.
        const val FILE_NAME = "identity-storage-test-instrumented-v1.bin"
        const val EXPECTED_FILE_BYTES = 202
        const val OUTER_HEADER_BYTES = 9
        const val AES_GCM_IV_BYTES = 12
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TEST_KEY_ALIAS = "org.sovereign.pm.test.identity-storage.v1"
    }
}
