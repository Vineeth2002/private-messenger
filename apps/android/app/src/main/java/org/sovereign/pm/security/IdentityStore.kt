package org.sovereign.pm.security

import android.content.Context
import android.util.AtomicFile
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.security.SecureRandom

internal enum class IdentityOrigin { CREATED_AND_PERSISTED, RESTORED }

internal data class IdentityLoadResult(
    val identity: AccountIdentity,
    val origin: IdentityOrigin,
    val kekCapabilities: KekCapabilities,
)

/**
 * Single-record, app-private storage. The file contains only the Android-Keystore-wrapped
 * Storage DEK and the Rust-sealed identity record. A present-but-invalid record is never
 * interpreted as a request to initialize a replacement identity.
 */
internal class IdentityStore(
    context: Context,
    private val bridge: CryptoBridge,
    private val platformKek: PlatformKek,
) {
    private val lock = Any()
    private val atomicFile = AtomicFile(File(context.noBackupFilesDir, FILE_NAME))

    fun loadOrCreate(): IdentityLoadResult = synchronized(lock) {
        if (hasAnyStorageArtifact()) restoreExisting() else createAndPersist()
    }

    private fun createAndPersist(): IdentityLoadResult {
        // A surviving Keystore alias with no record could mean the record was deleted or a
        // previous save was interrupted. Fail closed rather than silently minting a new identity.
        if (platformKek.hasExistingKey()) {
            throw IllegalStateException("Identity record is missing but its storage key exists; refusing replacement.")
        }

        val identity = bridge.initializeAccount()
        val storageKey = ByteArray(DEK_BYTES)
        var wrappedKey: ByteArray? = null
        var sealedRecord: ByteArray? = null
        var fileBytes: ByteArray? = null
        try {
            SecureRandom().nextBytes(storageKey)
            wrappedKey = platformKek.wrap(storageKey)
            sealedRecord = bridge.sealCurrentAccount(storageKey)
            fileBytes = encode(wrappedKey, sealedRecord)
            writeAtomically(fileBytes)
            return IdentityLoadResult(
                identity = identity,
                origin = IdentityOrigin.CREATED_AND_PERSISTED,
                kekCapabilities = platformKek.discover(),
            )
        } finally {
            storageKey.fill(0)
            wrappedKey?.fill(0)
            sealedRecord?.fill(0)
            fileBytes?.fill(0)
        }
    }

    private fun restoreExisting(): IdentityLoadResult {
        val fileBytes = readBoundedRecord()
        try {
            validateHeaderAndLength(fileBytes)
            val wrappedKey = fileBytes.copyOfRange(HEADER.size, HEADER.size + WRAPPED_DEK_BYTES)
            val sealedRecord = fileBytes.copyOfRange(HEADER.size + WRAPPED_DEK_BYTES, fileBytes.size)
            try {
                val storageKey = platformKek.unwrap(wrappedKey)
                try {
                    if (storageKey.size != DEK_BYTES) {
                        throw IllegalStateException("Stored identity could not be authenticated; no replacement was created.")
                    }
                    val identity = bridge.restoreAccount(sealedRecord, storageKey)
                    return IdentityLoadResult(
                        identity = identity,
                        origin = IdentityOrigin.RESTORED,
                        kekCapabilities = platformKek.discover(),
                    )
                } finally {
                    storageKey.fill(0)
                }
            } finally {
                wrappedKey.fill(0)
                sealedRecord.fill(0)
            }
        } catch (failure: Exception) {
            throw IllegalStateException(
                "Saved identity could not be restored. It was not replaced; preserve the storage files for recovery.",
                failure,
            )
        } finally {
            fileBytes.fill(0)
        }
    }

    private fun encode(wrappedKey: ByteArray, sealedRecord: ByteArray): ByteArray {
        if (wrappedKey.size != WRAPPED_DEK_BYTES || sealedRecord.size != SEALED_IDENTITY_BYTES) {
            throw IllegalStateException("Native identity storage returned an unexpected record size.")
        }
        return HEADER + wrappedKey + sealedRecord
    }

    private fun validateHeaderAndLength(bytes: ByteArray) {
        if (bytes.size != FILE_BYTES || !bytes.copyOfRange(0, HEADER.size).contentEquals(HEADER)) {
            throw IllegalStateException("Saved identity record has an unsupported format.")
        }
    }

    private fun hasAnyStorageArtifact(): Boolean {
        val base = atomicFile.baseFile
        return base.exists() || File(base.path + ".bak").exists() || File(base.path + ".new").exists()
    }

    private fun readBoundedRecord(): ByteArray {
        val input = try {
            atomicFile.openRead()
        } catch (failure: FileNotFoundException) {
            throw IllegalStateException("Identity storage artifacts exist but the record is missing; refusing replacement.", failure)
        }
        input.use { stream ->
            val buffer = ByteArray(FILE_BYTES + 1)
            var count = 0
            while (count < buffer.size) {
                val next = stream.read()
                if (next < 0) break
                buffer[count++] = next.toByte()
            }
            if (count != FILE_BYTES) {
                buffer.fill(0)
                throw IllegalStateException("Saved identity record has an invalid size.")
            }
            return buffer.copyOf(FILE_BYTES).also { buffer.fill(0) }
        }
    }

    private fun writeAtomically(bytes: ByteArray) {
        var output: FileOutputStream? = null
        try {
            output = atomicFile.startWrite()
            output.write(bytes)
            atomicFile.finishWrite(output)
            output = null
        } catch (failure: Exception) {
            output?.let { atomicFile.failWrite(it) }
            throw IllegalStateException("Identity could not be persisted atomically.", failure)
        }
    }

    private companion object {
        const val FILE_NAME = "identity-storage-v1.bin"
        const val DEK_BYTES = 32
        const val WRAPPED_DEK_BYTES = 12 + DEK_BYTES + 16
        const val SEALED_IDENTITY_BYTES = 133
        val HEADER = "PMIDFILE".toByteArray(Charsets.US_ASCII) + byteArrayOf(1)
        const val FILE_BYTES = 9 + WRAPPED_DEK_BYTES + SEALED_IDENTITY_BYTES
    }
}
