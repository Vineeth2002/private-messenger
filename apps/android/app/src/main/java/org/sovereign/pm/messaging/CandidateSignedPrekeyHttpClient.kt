package org.sovereign.pm.messaging

import org.sovereign.pm.crypto.CryptoBridge
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

/** HTTPS read client for the opt-in current-device signed-prekey route. */
internal class CandidateSignedPrekeyHttpClient(
    baseUrl: String,
    private val crypto: CryptoBridge,
    private val connectionFactory: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) {
    private val origin = normalizeOrigin(baseUrl)

    fun fetchCurrent(accountId: ByteArray, deviceId: ByteArray): ByteArray {
        require(accountId.size == 16 && deviceId.size == 16)
        val target = "/v1/candidate/devices/${uuid(accountId)}/${uuid(deviceId)}/signed-prekeys/v1"
        val connection = connectionFactory(URL(origin + target))
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.setRequestProperty("Accept", "application/cbor")
            connection.setRequestProperty("Cache-Control", "no-cache")
            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_OK) throw IOException("Signed-prekey lookup failed with HTTP $status.")
            if (connection.contentType?.substringBefore(';')?.trim()?.lowercase(Locale.ROOT) != "application/cbor") {
                throw IOException("Gateway returned an unexpected signed-prekey content type.")
            }
            val body = connection.inputStream.use { readBounded(it, MAX_RESPONSE_BYTES) }
            val canonical = crypto.decodeStrictCanonical(body)
            try { require(canonical.contentEquals(body)) { "Signed-prekey response is not canonical CBOR." } }
            finally { canonical.fill(0) }
            return SignedPrekeyArrayReader.oneItem(body)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream, max: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > max) throw IOException("Signed-prekey response exceeds its size limit.")
            output.write(buffer, 0, count)
        }
        if (total == 0) throw IOException("Gateway returned an empty signed-prekey response.")
        return output.toByteArray()
    }

    private fun uuid(bytes: ByteArray): String {
        val hex = bytes.joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }
        return "${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20,32)}"
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 12 * 1024
        private fun normalizeOrigin(value: String): String {
            val uri = URI(value)
            require(uri.isAbsolute && uri.scheme.equals("https", true) && !uri.host.isNullOrBlank())
            require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null)
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")
            return uri.toASCIIString().trimEnd('/')
        }
    }
}

internal object SignedPrekeyArrayReader {
    /** Gateway response is canonical CBOR array containing exactly one raw SignedPrekeyV1 map. */
    fun oneItem(raw: ByteArray): ByteArray {
        val reader = Reader(raw)
        require(reader.arrayLength() == 1UL) { "Gateway must return exactly one current signed prekey." }
        val item = reader.rawItem()
        reader.finished()
        return item
    }

    private class Reader(private val data: ByteArray) {
        private var offset = 0
        private data class Head(val major: Int, val value: ULong)
        fun arrayLength() = head(4).value
        fun rawItem(): ByteArray {
            val start = offset
            skip(0)
            return data.copyOfRange(start, offset)
        }
        fun finished() { require(offset == data.size) { "Trailing bytes after signed-prekey array." } }
        private fun skip(depth: Int) {
            require(depth <= 8 && offset < data.size) { "Invalid or excessive CBOR nesting." }
            val first = data[offset].toInt() and 0xff
            val major = first ushr 5
            val value = head(major).value
            when (major) {
                0, 1 -> Unit
                2, 3 -> advance(value.toInt())
                4 -> repeatBounded(value) { skip(depth + 1) }
                5 -> repeatBounded(value) { skip(depth + 1); skip(depth + 1) }
                7 -> require(first == 0xf4 || first == 0xf5 || first == 0xf6) { "Unsupported CBOR simple/floating value." }
                else -> throw IllegalArgumentException("Unsupported CBOR major type in signed prekey.")
            }
        }
        private fun repeatBounded(count: ULong, block: () -> Unit) {
            require(count <= 64UL) { "CBOR collection exceeds signed-prekey bounds." }
            repeat(count.toInt()) { block() }
        }
        private fun advance(count: Int) {
            require(count >= 0 && count <= data.size - offset) { "Truncated CBOR item." }
            offset += count
        }
        private fun head(expectedMajor: Int): Head {
            require(offset < data.size)
            val first = data[offset++].toInt() and 0xff
            val major = first ushr 5
            val additional = first and 31
            require(major == expectedMajor)
            val value = when (additional) {
                in 0..23 -> additional.toULong()
                24 -> readArg(1).also { require(it >= 24UL) }
                25 -> readArg(2).also { require(it >= 256UL) }
                26 -> readArg(4).also { require(it >= 65_536UL) }
                27 -> readArg(8).also { require(it >= 4_294_967_296UL) }
                else -> throw IllegalArgumentException("Indefinite/reserved CBOR values are prohibited.")
            }
            return Head(major, value)
        }
        private fun readArg(size: Int): ULong {
            require(size <= data.size - offset)
            var value = 0UL
            repeat(size) { value = (value shl 8) or (data[offset++].toInt() and 0xff).toULong() }
            return value
        }
    }
}

/** Fetches the current peer leaf + SPK, then checks the exact SPK against that native-verified leaf. */
internal class GatewayPeerPrekeyVerifier(
    private val proofClient: TransparencyProofHttpClient,
    private val signedPrekeyClient: CandidateSignedPrekeyHttpClient,
    private val allowDegradedForControlledAlpha: Boolean = false,
) : PeerPrekeyVerifier {
    fun candidateFor(accountId: ByteArray, deviceId: ByteArray): PeerPrekeyCandidate =
        PeerPrekeyCandidate(accountId.copyOf(), deviceId.copyOf())

    override fun verify(candidate: PeerPrekeyCandidate): VerifiedPeerPrekeyMaterial {
        val proof = proofClient.fetchVerifiedDeviceProof(candidate.accountId, candidate.deviceId)
        if (proof.trustState == TransparencyTrustState.DEGRADED && !allowDegradedForControlledAlpha) {
            throw IOException("Peer proof lacks a 2-of-3 witness quorum; degraded trust is disabled.")
        }
        val rawCandidate = signedPrekeyClient.fetchCurrent(candidate.accountId, candidate.deviceId)
        val verifiedSignedPrekey = try {
            proofClient.verifySignedPrekeyBinding(proof, rawCandidate)
        } finally {
            rawCandidate.fill(0)
        }
        return VerifiedPeerPrekeyMaterial(
            accountId = proof.accountId.copyOf(),
            deviceId = proof.deviceId.copyOf(),
            epoch = proof.epoch.toLong(),
            dskPublicKey = proof.dskPublicKey.copyOf(),
            ddhkPublicKey = proof.ddhkPublicKey.copyOf(),
            rawSignedPrekey = verifiedSignedPrekey,
        )
    }
}
