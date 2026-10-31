package org.sovereign.pm.enrollment

import org.json.JSONObject
import org.sovereign.pm.crypto.NativeDeviceEnrollmentSession
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.time.Instant

private const val MAX_CERTIFICATE_BYTES = 4096
private const val MAX_PROOF_BYTES = 2048
private const val MAX_HTTP_RESPONSE_BYTES = 8192
private const val REQUEST_BODY_LIMIT_BYTES = 16 * 1024
private const val CHALLENGE_PATH = "/v1/candidate/enrollment/challenges"
private const val ACTIVATE_PATH = "/v1/candidate/enrollment/activate"

/** Public challenge data returned by the candidate gateway. */
data class CandidateEnrollmentChallenge(
    val id: ByteArray,
    val nonce: ByteArray,
    val expiresAt: Instant,
) {
    init {
        require(id.size == 16) { "Challenge ID must be 16 bytes." }
        require(nonce.size == 32) { "Challenge nonce must be 32 bytes." }
    }
}

/** Failure returned by the candidate gateway or detected while validating its response. */
class CandidateEnrollmentHttpException(
    val httpStatus: Int,
    val errorCode: String,
) : IOException("Candidate enrollment request failed: HTTP $httpStatus ($errorCode)")

/** Small transport interface so retry behavior can be tested without a live server. */
interface CandidateEnrollmentApi {
    fun requestChallenge(
        enrollmentCertificate: ByteArray,
        recoveryPublicKey: ByteArray,
    ): CandidateEnrollmentChallenge

    fun activate(
        enrollmentCertificate: ByteArray,
        proof: ByteArray,
        recoveryPublicKey: ByteArray,
    )
}

/**
 * Synchronous HTTPS-only client for the candidate gateway contract.
 *
 * Construct with an explicitly configured origin such as "https://gateway.example.org".
 * It rejects cleartext HTTP, credentials in the URL, URL query/fragment data, redirects, oversized
 * responses, malformed challenge fields, and unexpected status codes. Call from a worker thread,
 * never from the Android main thread. No base URL is hard-coded in the app.
 */
class CandidateEnrollmentHttpClient(
    baseUrl: String,
    private val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    private val readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS,
    private val connectionFactory: (URL) -> HttpURLConnection = {
        it.openConnection() as HttpURLConnection
    },
) : CandidateEnrollmentApi {
    private val origin: String = validateOrigin(baseUrl)

    init {
        require(connectTimeoutMs in 1..MAX_TIMEOUT_MS) { "Invalid connect timeout." }
        require(readTimeoutMs in 1..MAX_TIMEOUT_MS) { "Invalid read timeout." }
    }

    override fun requestChallenge(
        enrollmentCertificate: ByteArray,
        recoveryPublicKey: ByteArray,
    ): CandidateEnrollmentChallenge {
        require(enrollmentCertificate.size in 1..MAX_CERTIFICATE_BYTES) {
            "Enrollment certificate has an invalid length."
        }
        require(recoveryPublicKey.size == 32) { "Recovery public key must be 32 bytes." }

        val request = JSONObject()
            .put("enrollment_certificate_hex", enrollmentCertificate.toHex())
            .put("recovery_public_key_hex", recoveryPublicKey.toHex())
        val response = post(CHALLENGE_PATH, request.toString())

        if (response.statusCode != HttpURLConnection.HTTP_OK) {
            throw responseException(response)
        }
        if (response.contentType?.mediaType() != "application/json") {
            throw CandidateEnrollmentHttpException(response.statusCode, "ERR_INVALID_RESPONSE")
        }

        try {
            val json = JSONObject(String(response.body, Charsets.UTF_8))
            val id = decodeFixedHex(json.requiredString("challenge_id_hex"), 16)
            val nonce = decodeFixedHex(json.requiredString("challenge_nonce_hex"), 32)
            val expiresAt = Instant.parse(json.requiredString("expires_at"))
            if (!expiresAt.isAfter(Instant.now())) {
                throw CandidateEnrollmentHttpException(
                    HttpURLConnection.HTTP_GONE,
                    "ERR_CHALLENGE_EXPIRED",
                )
            }
            return CandidateEnrollmentChallenge(id, nonce, expiresAt)
        } catch (failure: CandidateEnrollmentHttpException) {
            throw failure
        } catch (_: Exception) {
            throw CandidateEnrollmentHttpException(response.statusCode, "ERR_INVALID_RESPONSE")
        }
    }

    override fun activate(
        enrollmentCertificate: ByteArray,
        proof: ByteArray,
        recoveryPublicKey: ByteArray,
    ) {
        require(enrollmentCertificate.size in 1..MAX_CERTIFICATE_BYTES) {
            "Enrollment certificate has an invalid length."
        }
        require(proof.size in 1..MAX_PROOF_BYTES) { "Proof has an invalid length." }
        require(recoveryPublicKey.size == 32) { "Recovery public key must be 32 bytes." }

        val request = JSONObject()
            .put("enrollment_certificate_hex", enrollmentCertificate.toHex())
            .put("proof_hex", proof.toHex())
            .put("recovery_public_key_hex", recoveryPublicKey.toHex())
        val response = post(ACTIVATE_PATH, request.toString())
        if (response.statusCode != HttpURLConnection.HTTP_NO_CONTENT) {
            throw responseException(response)
        }
        if (response.body.isNotEmpty()) {
            throw CandidateEnrollmentHttpException(response.statusCode, "ERR_INVALID_RESPONSE")
        }
    }

    private fun post(path: String, json: String): HttpResponse {
        val body = json.toByteArray(Charsets.UTF_8)
        if (body.size > REQUEST_BODY_LIMIT_BYTES) {
            throw IllegalArgumentException("Enrollment request body exceeds the client limit.")
        }

        val connection = connectionFactory(URL(origin + path))
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setFixedLengthStreamingMode(body.size)

            connection.outputStream.use { output ->
                output.write(body)
            }

            val statusCode = connection.responseCode
            val responseStream: InputStream? = when {
                statusCode == HttpURLConnection.HTTP_NO_CONTENT -> null
                statusCode in 200..299 -> connection.inputStream
                else -> connection.errorStream
            }
            val responseBody = responseStream?.use { readBounded(it, MAX_HTTP_RESPONSE_BYTES) }
                ?: ByteArray(0)
            return HttpResponse(statusCode, connection.contentType, responseBody)
        } finally {
            connection.disconnect()
        }
    }

    private fun responseException(response: HttpResponse): CandidateEnrollmentHttpException {
        val errorCode = try {
            val value = JSONObject(String(response.body, Charsets.UTF_8)).opt("error")
            (value as? String)
                ?.takeIf { it.matches(Regex("ERR_[A-Z0-9_]{1,64}")) }
                ?: "ERR_HTTP_ERROR"
        } catch (_: Exception) {
            "ERR_HTTP_ERROR"
        }
        return CandidateEnrollmentHttpException(response.statusCode, errorCode)
    }

    private fun decodeFixedHex(value: String, expectedBytes: Int): ByteArray {
        if (value.length != expectedBytes * 2) {
            throw IllegalArgumentException("Hex field has an invalid length.")
        }
        val output = ByteArray(expectedBytes)
        for (index in output.indices) {
            val high = Character.digit(value[index * 2], 16)
            val low = Character.digit(value[index * 2 + 1], 16)
            if (high < 0 || low < 0) {
                throw IllegalArgumentException("Hex field is malformed.")
            }
            output[index] = ((high shl 4) or low).toByte()
        }
        return output
    }

    private fun JSONObject.requiredString(key: String): String =
        opt(key) as? String ?: throw IllegalArgumentException("Missing or invalid $key.")

    private fun String.mediaType(): String =
        substringBefore(';').trim().lowercase()

    private fun ByteArray.toHex(): String {
        val digits = "0123456789abcdef"
        val result = CharArray(size * 2)
        for (index in indices) {
            val value = this[index].toInt() and 0xff
            result[index * 2] = digits[value ushr 4]
            result[index * 2 + 1] = digits[value and 0x0f]
        }
        return String(result)
    }

    private fun validateOrigin(value: String): String {
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw IllegalArgumentException("Gateway base URL is invalid.")
        }
        require(uri.scheme.equals("https", ignoreCase = true)) {
            "Candidate enrollment requires an HTTPS gateway URL."
        }
        require(uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
            "Gateway base URL must be an HTTPS origin without credentials, query, or fragment."
        }
        require(uri.path.isNullOrEmpty() || uri.path == "/") {
            "Gateway base URL must not contain an application path."
        }
        require(uri.port == -1 || uri.port in 1..65535) { "Gateway port is invalid." }
        return uri.toASCIIString().trimEnd('/')
    }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (output.size() + count > maxBytes) {
                throw IOException("Candidate enrollment response exceeds the size limit.")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private data class HttpResponse(
        val statusCode: Int,
        val contentType: String?,
        val body: ByteArray,
    )

    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 5_000
        private const val DEFAULT_READ_TIMEOUT_MS = 5_000
        private const val MAX_TIMEOUT_MS = 60_000
    }
}

/**
 * Prepares the exact certificate/challenge/proof tuple and returns a pending activation object.
 * The enrollment epoch must come from a trusted existing-device handoff; callers must not guess it.
 *
 * If activate() fails after a network timeout, retain the returned pending object and retry
 * activate() on that same object. It preserves the exact certificate and proof until activation is
 * confirmed. This pending state is in-memory only; process-death recovery is not implemented here.
 */
class CandidateEnrollmentCoordinator(
    private val api: CandidateEnrollmentApi,
) {
    fun prepare(
        session: NativeDeviceEnrollmentSession,
        recoveryMnemonic: String,
        authoritativeEpoch: ULong,
    ): PendingCandidateEnrollment {
        val authorization = session.signEnrollmentAuthorization(recoveryMnemonic, authoritativeEpoch)
        var challenge: CandidateEnrollmentChallenge? = null
        try {
            challenge = api.requestChallenge(
                authorization.certificate,
                authorization.recoveryPublicKey,
            )
            if (!challenge.expiresAt.isAfter(Instant.now())) {
                throw CandidateEnrollmentHttpException(
                    HttpURLConnection.HTTP_GONE,
                    "ERR_CHALLENGE_EXPIRED",
                )
            }

            val proof = session.signProofOfPossession(
                authorization.certificate,
                challenge.id,
                challenge.nonce,
            )
            return PendingCandidateEnrollment(
                api = api,
                enrollmentCertificate = authorization.certificate.copyOf(),
                recoveryPublicKey = authorization.recoveryPublicKey.copyOf(),
                proof = proof,
                challengeId = challenge.id.copyOf(),
                challengeNonce = challenge.nonce.copyOf(),
                expiresAt = challenge.expiresAt,
            )
        } finally {
            authorization.certificate.fill(0)
            authorization.recoveryPublicKey.fill(0)
            challenge?.id?.fill(0)
            challenge?.nonce?.fill(0)
        }
    }
}

/**
 * Holds one exact activation attempt. A failed activation does not clear the bytes, allowing a
 * caller to retry safely after an uncertain network result. close() discards the attempt.
 */
class PendingCandidateEnrollment internal constructor(
    private val api: CandidateEnrollmentApi,
    private val enrollmentCertificate: ByteArray,
    private val recoveryPublicKey: ByteArray,
    private val proof: ByteArray,
    private val challengeId: ByteArray,
    private val challengeNonce: ByteArray,
    val expiresAt: Instant,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun activate() {
        check(!closed) { "Pending enrollment is already completed or closed." }
        // The server remains authoritative for expiry and consumed-challenge idempotency. In
        // particular, do not reject a retry locally just because the original challenge expired.
        api.activate(enrollmentCertificate, proof, recoveryPublicKey)
        clear()
    }

    @Synchronized
    override fun close() {
        if (!closed) clear()
    }

    private fun clear() {
        enrollmentCertificate.fill(0)
        recoveryPublicKey.fill(0)
        proof.fill(0)
        challengeId.fill(0)
        challengeNonce.fill(0)
        closed = true
    }
}