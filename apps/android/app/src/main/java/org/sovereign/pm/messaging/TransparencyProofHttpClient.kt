package org.sovereign.pm.messaging

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

/**
 * Fetches the candidate KT V1 proof response and passes the exact canonical CBOR bytes
 * to Rust. No identity keys are accepted from the HTTP response without native proof
 * verification. The STH checkpoint is advanced only after native verification succeeds.
 *
 * All methods are blocking and MUST be called from an IO/background executor, never the
 * Android main thread.
 */
internal class TransparencyProofHttpClient(
    baseUrl: String,
    private val verifier: TransparencyV1Verifier,
    private val checkpointStore: TransparencyCheckpointStore,
    private val connectionFactory: (URL) -> HttpURLConnection = { url ->
        url.openConnection() as HttpURLConnection
    },
) : AutoCloseable {
    private val origin = normalizeOrigin(baseUrl)

    /**
     * Returns only after the proof verifies and the newer/equal STH checkpoint has been
     * atomically persisted. VERIFIED and DEGRADED are both cryptographically valid states;
     * callers must retain and display the distinction.
     */
    @Throws(IOException::class)
    fun fetchVerifiedDeviceProof(peerAccountId: ByteArray, peerDeviceId: ByteArray): VerifiedKtDeviceProof {
        require(peerAccountId.size == UUID_BYTES) { "Peer account ID must be 16 bytes." }
        require(peerDeviceId.size == UUID_BYTES) { "Peer device ID must be 16 bytes." }
        require(peerAccountId.any { it.toInt() != 0 }) { "Peer account ID cannot be zero." }
        require(peerDeviceId.any { it.toInt() != 0 }) { "Peer device ID cannot be zero." }

        return checkpointStore.withExclusiveAccess {
            val proofTarget = "/v1/candidate/kt/proof/v1/${uuidFromBytes(peerAccountId)}/${uuidFromBytes(peerDeviceId)}"
            val proofBundle = fetchCbor(proofTarget, MAX_PROOF_BYTES)
            val current = try {
                CandidateKtProofWire.inspectCurrentProof(proofBundle)
            } catch (failure: Exception) {
                throw IOException("Gateway returned a malformed KT V1 proof bundle.", failure)
            }

            val previousSth = try {
                checkpointStore.loadCheckpoint()
            } catch (failure: Exception) {
                throw IOException("Saved KT checkpoint is invalid; refusing to trust a replacement.", failure)
            }

            val consistencyBundle = if (previousSth == null) {
                ByteArray(0)
            } else {
                val oldSize = try {
                    CandidateKtProofWire.readSignedTreeHead(previousSth).treeSize
                } catch (failure: Exception) {
                    throw IOException("Saved KT checkpoint cannot be parsed; refusing to trust a replacement.", failure)
                }
                when {
                    current.treeSize > oldSize -> {
                        if (oldSize == 0UL) {
                            throw IOException("KT V1 does not support a consistency proof from a zero-sized checkpoint.")
                        }
                        fetchCbor(
                            "/v1/candidate/kt/consistency/v1?old_size=$oldSize",
                            MAX_CONSISTENCY_BYTES,
                        )
                    }
                    else -> ByteArray(0)
                }
            }

            val verified = try {
                verifier.verifyDeviceProof(
                    proofBundle = proofBundle,
                    consistencyBundle = consistencyBundle,
                    previousSignedTreeHead = previousSth ?: ByteArray(0),
                    expectedAccountId = peerAccountId,
                    expectedDeviceId = peerDeviceId,
                )
            } catch (failure: Exception) {
                throw IOException("Native KT V1 verification rejected the peer proof.", failure)
            }

            if (!verified.accountId.contentEquals(peerAccountId) ||
                !verified.deviceId.contentEquals(peerDeviceId) ||
                verified.treeSize != current.treeSize ||
                !verified.signedTreeHead.contentEquals(current.signedTreeHead)
            ) {
                throw IOException("Native KT verifier returned a result inconsistent with the requested peer or proof bundle.")
            }

            try {
                checkpointStore.persistVerified(verified)
            } catch (failure: Exception) {
                throw IOException("Verified KT checkpoint could not be persisted; peer keys are not released.", failure)
            }
            verified
        }
    }

    /** Bind a fetched candidate SPK to the already-verified leaf in native Rust. */
    @Throws(IOException::class)
    fun verifySignedPrekeyBinding(
        verifiedPeer: VerifiedKtDeviceProof,
        signedPrekeyWire: ByteArray,
    ): ByteArray = try {
        verifier.verifySignedPrekeyBinding(verifiedPeer, signedPrekeyWire)
    } catch (failure: Exception) {
        throw IOException("Native signed-prekey/KT-leaf binding verification failed.", failure)
    }

    private fun fetchCbor(target: String, maximumBytes: Int): ByteArray {
        require(target.startsWith("/") && !target.contains('\r') && !target.contains('\n')) {
            "Invalid KT request target."
        }
        val connection = connectionFactory(URL(origin + target))
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = DEFAULT_TIMEOUT_MS
            connection.readTimeout = DEFAULT_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.setRequestProperty("Accept", KT_MEDIA_TYPE)
            connection.setRequestProperty("Cache-Control", "no-cache")

            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_OK) {
                throw IOException("Gateway KT proof request failed with HTTP $status.")
            }
            if (mediaType(connection.contentType) != KT_MEDIA_TYPE) {
                throw IOException("Gateway returned an unexpected KT proof content type.")
            }
            val stream = connection.inputStream
            return stream.use { readBounded(it, maximumBytes) }
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream, maximumBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maximumBytes, 4096))
        val buffer = ByteArray(2048)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maximumBytes) throw IOException("Gateway KT proof response exceeds the size limit.")
            output.write(buffer, 0, count)
        }
        if (total == 0) throw IOException("Gateway returned an empty KT proof response.")
        return output.toByteArray()
    }

    private fun mediaType(value: String?): String? =
        value?.substringBefore(';')?.trim()?.lowercase(Locale.ROOT)

    override fun close() {
        verifier.close()
    }

    private fun uuidFromBytes(bytes: ByteArray): String {
        require(bytes.size == UUID_BYTES) { "UUID byte representation must be 16 bytes." }
        val hex = bytes.joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }
        return buildString(36) {
            append(hex.substring(0, 8))
            append('-')
            append(hex.substring(8, 12))
            append('-')
            append(hex.substring(12, 16))
            append('-')
            append(hex.substring(16, 20))
            append('-')
            append(hex.substring(20, 32))
        }
    }

    companion object {
        private const val UUID_BYTES = 16
        private const val KT_MEDIA_TYPE = "application/cbor"
        private const val DEFAULT_TIMEOUT_MS = 5000
        private const val MAX_PROOF_BYTES = 64 * 1024
        private const val MAX_CONSISTENCY_BYTES = 16 * 1024

        private fun normalizeOrigin(value: String): String {
            require(value.isNotBlank() && value == value.trim()) {
                "Gateway URL must not be empty or contain surrounding whitespace."
            }
            val uri = try {
                URI(value)
            } catch (failure: Exception) {
                throw IllegalArgumentException("Gateway URL is invalid.", failure)
            }
            require(uri.isAbsolute && uri.scheme.equals("https", ignoreCase = true)) {
                "KT proof retrieval requires an HTTPS gateway URL."
            }
            require(uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
                "Gateway URL must not contain credentials, query, or fragment."
            }
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
                "Gateway URL must be an origin without an application path."
            }
            require(uri.port == -1 || uri.port in 1..65535) { "Gateway URL contains an invalid port." }
            return uri.toASCIIString().trimEnd('/')
        }
    }
}

/**
 * The gateway's frozen candidate proof response is canonical PM-CBOR. This narrow reader
 * extracts only the STH and tree size needed to decide whether a consistency request is
 * required. Rust still performs the authoritative full parse and cryptographic verification.
 */
internal object CandidateKtProofWire {
    data class CurrentProofMetadata(val treeSize: ULong, val signedTreeHead: ByteArray)
    data class SthMetadata(
        val treeSize: ULong,
        val smtRoot: ByteArray,
        val historyRoot: ByteArray,
        val logId: ByteArray,
    )

    fun inspectCurrentProof(raw: ByteArray): CurrentProofMetadata {
        require(raw.isNotEmpty() && raw.size <= 64 * 1024)
        val reader = StrictCborReader(raw)
        require(reader.readMapLength() == 14UL) { "KT current proof map must contain exactly 14 fields." }
        var previousKey = 0UL
        var treeSize: ULong? = null
        var sth: ByteArray? = null
        repeat(14) {
            val key = reader.readUnsigned()
            require(key in 1UL..14UL && key > previousKey) { "KT proof keys are duplicated, unordered or unknown." }
            previousKey = key
            when (key.toInt()) {
                1 -> require(reader.readUnsigned() == 1UL) { "Unsupported KT proof version." }
                2 -> reader.readByteString(1024)
                3, 4, 5, 8 -> reader.readFixedBytes(32)
                6 -> reader.readHashArray(256, exactItems = 256)
                7 -> reader.readUnsigned()
                9 -> reader.readUnsigned()
                10 -> reader.readByteString(1024)
                11 -> reader.readHashArray(64, exactItems = null)
                12 -> sth = reader.readByteString(1024)
                13 -> treeSize = reader.readUnsigned()
                14 -> reader.readByteStringArray(3, 1024)
            }
        }
        reader.requireFinished()
        val acceptedSize = treeSize ?: throw IllegalArgumentException("KT proof is missing tree size.")
        require(acceptedSize > 0UL) { "KT current proof cannot refer to an empty tree." }
        val acceptedSth = sth ?: throw IllegalArgumentException("KT proof is missing signed tree head.")
        val sthMetadata = readSignedTreeHead(acceptedSth)
        require(sthMetadata.treeSize == acceptedSize) {
            "Proof tree size does not match the signed tree head."
        }
        return CurrentProofMetadata(acceptedSize, acceptedSth)
    }

    fun readSignedTreeHead(raw: ByteArray): SthMetadata {
        require(raw.isNotEmpty() && raw.size <= 1024)
        val reader = StrictCborReader(raw)
        require(reader.readMapLength() == 7UL) { "Signed tree head must contain exactly 7 fields." }
        var previousKey = 0UL
        var version: ULong? = null
        var treeSize: ULong? = null
        var smtRoot: ByteArray? = null
        var historyRoot: ByteArray? = null
        var logId: ByteArray? = null
        repeat(7) {
            val key = reader.readUnsigned()
            require(key in 1UL..7UL && key > previousKey) { "STH keys are duplicated, unordered or unknown." }
            previousKey = key
            when (key.toInt()) {
                1 -> version = reader.readUnsigned()
                2 -> treeSize = reader.readUnsigned()
                3 -> smtRoot = reader.readFixedBytes(32)
                4 -> historyRoot = reader.readFixedBytes(32)
                5 -> reader.readUnsigned()
                6 -> logId = reader.readFixedBytes(32)
                7 -> reader.readFixedBytes(64)
            }
        }
        reader.requireFinished()
        require(version == 1UL) { "Unsupported STH version." }
        return SthMetadata(
            treeSize = treeSize ?: throw IllegalArgumentException("STH tree size is missing."),
            smtRoot = smtRoot ?: throw IllegalArgumentException("STH SMT root is missing."),
            historyRoot = historyRoot ?: throw IllegalArgumentException("STH history root is missing."),
            logId = logId ?: throw IllegalArgumentException("STH log ID is missing."),
        )
    }
}

/** Minimal bounded canonical-CBOR reader for the fixed KT response shapes. */
private class StrictCborReader(private val data: ByteArray) {
    private var offset = 0

    fun readMapLength(): ULong = readContainerLength(expectedMajor = 5)
    fun readUnsigned(): ULong = readHead(expectedMajor = 0).value

    fun readByteString(maxBytes: Int): ByteArray {
        val length = readContainerLength(expectedMajor = 2)
        require(length <= maxBytes.toULong()) { "CBOR byte string exceeds its size limit." }
        return readRaw(length.toInt())
    }

    fun readFixedBytes(expectedBytes: Int): ByteArray =
        readByteString(expectedBytes).also { require(it.size == expectedBytes) { "CBOR field has an invalid byte length." } }

    fun readHashArray(maxItems: Int, exactItems: Int?): List<ByteArray> {
        val count = readContainerLength(expectedMajor = 4)
        require(count <= maxItems.toULong()) { "CBOR hash array exceeds its item limit." }
        if (exactItems != null) require(count == exactItems.toULong()) { "CBOR hash array has an invalid item count." }
        return List(count.toInt()) { readFixedBytes(32) }
    }

    fun readByteStringArray(maxItems: Int, maxBytesEach: Int): List<ByteArray> {
        val count = readContainerLength(expectedMajor = 4)
        require(count <= maxItems.toULong()) { "CBOR byte-string array exceeds its item limit." }
        return List(count.toInt()) { readByteString(maxBytesEach) }
    }

    fun requireFinished() {
        require(offset == data.size) { "Trailing bytes follow the KT CBOR object." }
    }

    private data class Head(val major: Int, val value: ULong)

    private fun readContainerLength(expectedMajor: Int): ULong {
        val head = readHead(expectedMajor)
        return head.value
    }

    private fun readHead(expectedMajor: Int): Head {
        require(offset < data.size) { "Truncated CBOR object." }
        val first = data[offset++].toInt() and 0xff
        val major = first ushr 5
        val additional = first and 0x1f
        require(major == expectedMajor) { "Unexpected CBOR major type." }
        val value = when (additional) {
            in 0..23 -> additional.toULong()
            24 -> readArgument(1).also { require(it >= 24UL) { "Non-canonical CBOR integer/length." } }
            25 -> readArgument(2).also { require(it >= 256UL) { "Non-canonical CBOR integer/length." } }
            26 -> readArgument(4).also { require(it >= 65_536UL) { "Non-canonical CBOR integer/length." } }
            27 -> readArgument(8).also { require(it >= 4_294_967_296UL) { "Non-canonical CBOR integer/length." } }
            else -> throw IllegalArgumentException("Indefinite or reserved CBOR values are prohibited.")
        }
        return Head(major, value)
    }

    private fun readArgument(bytes: Int): ULong {
        require(bytes <= data.size - offset) { "Truncated CBOR argument." }
        var result = 0UL
        repeat(bytes) { result = (result shl 8) or (data[offset++].toInt() and 0xff).toULong() }
        return result
    }

    private fun readRaw(count: Int): ByteArray {
        require(count >= 0 && count <= data.size - offset) { "Truncated CBOR byte string." }
        return data.copyOfRange(offset, offset + count).also { offset += count }
    }
}
