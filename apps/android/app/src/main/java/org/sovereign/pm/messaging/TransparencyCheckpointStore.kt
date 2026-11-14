package org.sovereign.pm.messaging

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Stores the last cryptographically verified public SignedTreeHeadV1 in noBackupFilesDir.
 * The checkpoint is signed public data, so it is not encrypted. Integrity/signature checking
 * is repeated by native Rust on every subsequent proof verification.
 *
 * This protects against accidental app backup/restore and torn writes, NOT a privileged local
 * attacker restoring an older valid checkpoint. Hard anti-rollback requires a trusted monotonic
 * platform counter or an independently trusted witness state; Android Keystore alone does not
 * provide a general monotonic counter.
 */
internal class TransparencyCheckpointStore(
    context: Context,
    fileName: String = FILE_NAME,
) {
    private val atomicFile = AtomicFile(File(context.noBackupFilesDir, fileName))

    internal fun <T> withExclusiveAccess(block: () -> T): T = synchronized(PROCESS_LOCK) { block() }

    fun loadCheckpoint(): ByteArray? = withExclusiveAccess { loadCheckpointLocked() }

    internal fun persistVerified(proof: VerifiedKtDeviceProof) = withExclusiveAccess {
        require(proof.signedTreeHead.isNotEmpty() && proof.signedTreeHead.size <= MAX_STH_BYTES)
        val newSth = CandidateKtProofWire.readSignedTreeHead(proof.signedTreeHead)
        require(newSth.treeSize == proof.treeSize)
        require(newSth.logId.contentEquals(proof.logId))
        require(newSth.smtRoot.contentEquals(proof.smtRoot))
        require(newSth.historyRoot.contentEquals(proof.historyRoot))

        val existing = loadCheckpointLocked()
        if (existing != null) {
            val previous = try {
                CandidateKtProofWire.readSignedTreeHead(existing)
            } catch (failure: Exception) {
                existing.fill(0)
                throw IllegalStateException("Existing signed-tree-head checkpoint is invalid; refusing overwrite.", failure)
            }
            existing.fill(0)
            require(previous.logId.contentEquals(newSth.logId)) { "KT log identity changed; refusing checkpoint replacement." }
            require(newSth.treeSize >= previous.treeSize) { "KT checkpoint rollback detected; refusing checkpoint replacement." }
            if (newSth.treeSize == previous.treeSize) {
                require(newSth.smtRoot.contentEquals(previous.smtRoot) &&
                    newSth.historyRoot.contentEquals(previous.historyRoot)) {
                    "Same-size conflicting KT checkpoint detected; refusing checkpoint replacement."
                }
            }
        }
        writeAtomically(encode(proof.signedTreeHead))
    }

    private fun loadCheckpointLocked(): ByteArray? {
        val base = atomicFile.baseFile
        val hasArtifacts = base.exists() || File(base.path + ".bak").exists() || File(base.path + ".new").exists()
        if (!hasArtifacts) return null
        val input = try {
            atomicFile.openRead()
        } catch (failure: FileNotFoundException) {
            throw IllegalStateException("KT checkpoint artifacts exist but the checkpoint is missing.", failure)
        }
        val raw = input.use { readBounded(it, MAX_RECORD_BYTES) }
        try {
            require(raw.size >= HEADER.size + 4) { "KT checkpoint record is truncated." }
            require(raw.copyOfRange(0, HEADER.size).contentEquals(HEADER)) { "KT checkpoint header/version is invalid." }
            val length = ByteBuffer.wrap(raw, HEADER.size, 4).order(ByteOrder.BIG_ENDIAN).int
            require(length in 1..MAX_STH_BYTES) { "KT checkpoint STH length is invalid." }
            require(raw.size == HEADER.size + 4 + length) { "KT checkpoint record has an invalid total length." }
            val sth = raw.copyOfRange(HEADER.size + 4, raw.size)
            CandidateKtProofWire.readSignedTreeHead(sth)
            return sth
        } finally {
            raw.fill(0)
        }
    }

    private fun encode(sth: ByteArray): ByteArray {
        require(sth.isNotEmpty() && sth.size <= MAX_STH_BYTES)
        return ByteBuffer.allocate(HEADER.size + 4 + sth.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(HEADER)
            .putInt(sth.size)
            .put(sth)
            .array()
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
            throw IllegalStateException("KT checkpoint could not be persisted atomically.", failure)
        } finally {
            bytes.fill(0)
        }
    }

    private fun readBounded(input: java.io.InputStream, maximumBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(512)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maximumBytes) {
                buffer.fill(0)
                throw IllegalStateException("KT checkpoint exceeds its size limit.")
            }
            output.write(buffer, 0, count)
        }
        buffer.fill(0)
        return output.toByteArray()
    }

    companion object {
        private val PROCESS_LOCK = Any()
        private const val FILE_NAME = "kt-v1-checkpoint.bin"
        private const val MAX_STH_BYTES = 1024
        private const val MAX_RECORD_BYTES = 8 + 4 + MAX_STH_BYTES
        private val HEADER = "PMKTSTH1".toByteArray(Charsets.US_ASCII)
    }
}
