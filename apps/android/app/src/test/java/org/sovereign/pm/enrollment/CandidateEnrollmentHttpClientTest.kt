package org.sovereign.pm.enrollment

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CandidateEnrollmentHttpClientTest {
    @Test
    fun challengeRequestUsesContractAndParsesExactFields() {
        val challengeId = ByteArray(16) { (it + 1).toByte() }
        val nonce = ByteArray(32) { (it + 2).toByte() }
        val response = JSONObject()
            .put("challenge_id_hex", challengeId.toHex())
            .put("challenge_nonce_hex", nonce.toHex())
            .put("expires_at", "2099-01-01T00:00:00Z")
            .toString()
            .toByteArray(Charsets.UTF_8)

        var requestedUrl: URL? = null
        var connection: FakeConnection? = null
        val client = CandidateEnrollmentHttpClient(
            baseUrl = "https://gateway.example.test",
            connectionFactory = { url ->
                requestedUrl = url
                FakeConnection(url, HttpURLConnection.HTTP_OK, response, "application/json; charset=utf-8")
                    .also { connection = it }
            },
        )
        val certificate = byteArrayOf(0x01, 0x02, 0x03)
        val recoveryPublicKey = ByteArray(32) { 0x44 }

        val challenge = client.requestChallenge(certificate, recoveryPublicKey)

        assertEquals("/v1/candidate/enrollment/challenges", requestedUrl?.path)
        assertEquals("POST", connection?.requestMethod)
        assertEquals("application/json", connection?.getRequestProperty("Content-Type"))
        assertFalse(connection?.instanceFollowRedirects ?: true)
        assertTrue(connection?.disconnected == true)
        assertArrayEquals(challengeId, challenge.id)
        assertArrayEquals(nonce, challenge.nonce)
        assertEquals(Instant.parse("2099-01-01T00:00:00Z"), challenge.expiresAt)

        val sent = JSONObject(String(connection!!.writtenBytes(), Charsets.UTF_8))
        assertEquals(certificate.toHex(), sent.getString("enrollment_certificate_hex"))
        assertEquals(recoveryPublicKey.toHex(), sent.getString("recovery_public_key_hex"))
    }

    @Test
    fun activationSendsExactCertificateProofAndRecoveryKey() {
        var requestedUrl: URL? = null
        var connection: FakeConnection? = null
        val client = CandidateEnrollmentHttpClient(
            baseUrl = "https://gateway.example.test/",
            connectionFactory = { url ->
                requestedUrl = url
                FakeConnection(url, HttpURLConnection.HTTP_NO_CONTENT, byteArrayOf(), null)
                    .also { connection = it }
            },
        )
        val certificate = byteArrayOf(0x11, 0x22)
        val proof = byteArrayOf(0x33, 0x44, 0x55)
        val recoveryPublicKey = ByteArray(32) { 0x66 }

        client.activate(certificate, proof, recoveryPublicKey)

        assertEquals("/v1/candidate/enrollment/activate", requestedUrl?.path)
        val sent = JSONObject(String(connection!!.writtenBytes(), Charsets.UTF_8))
        assertEquals(certificate.toHex(), sent.getString("enrollment_certificate_hex"))
        assertEquals(proof.toHex(), sent.getString("proof_hex"))
        assertEquals(recoveryPublicKey.toHex(), sent.getString("recovery_public_key_hex"))
        assertTrue(connection?.disconnected == true)
    }

    @Test
    fun cleartextAndCredentialBearingBaseUrlsAreRejected() {
        for (baseUrl in listOf(
            "http://gateway.example.test",
            "https://user:password@gateway.example.test",
            "https://gateway.example.test/path",
            "https://gateway.example.test?token=x",
        )) {
            val result = runCatching { CandidateEnrollmentHttpClient(baseUrl) }
            assertTrue("Expected rejection for $baseUrl", result.isFailure)
        }
    }

    @Test
    fun redirectsAreNotFollowedAndAreReturnedAsFailures() {
        var connection: FakeConnection? = null
        val client = CandidateEnrollmentHttpClient(
            baseUrl = "https://gateway.example.test",
            connectionFactory = { url ->
                FakeConnection(
                    url,
                    HttpURLConnection.HTTP_MOVED_TEMP,
                    """{"error":"ERR_REDIRECT"}""".toByteArray(Charsets.UTF_8),
                    "application/json",
                ).also { connection = it }
            },
        )

        val failure = runCatching {
            client.requestChallenge(byteArrayOf(0x01), ByteArray(32))
        }.exceptionOrNull()

        assertTrue(failure is CandidateEnrollmentHttpException)
        assertEquals(HttpURLConnection.HTTP_MOVED_TEMP, (failure as CandidateEnrollmentHttpException).httpStatus)
        assertEquals("ERR_REDIRECT", failure.errorCode)
        assertFalse(connection?.instanceFollowRedirects ?: true)
    }

    @Test
    fun pendingActivationRetainsExactBytesAfterFailureAndClearsAfterSuccess() {
        val api = RetryingApi()
        val certificate = byteArrayOf(1, 2, 3)
        val recoveryKey = ByteArray(32) { 4 }
        val proof = byteArrayOf(5, 6, 7)
        val pending = PendingCandidateEnrollment(
            api = api,
            enrollmentCertificate = certificate,
            recoveryPublicKey = recoveryKey,
            proof = proof,
            challengeId = ByteArray(16) { 8 },
            challengeNonce = ByteArray(32) { 9 },
            expiresAt = Instant.parse("2099-01-01T00:00:00Z"),
        )

        val firstFailure = runCatching { pending.activate() }.exceptionOrNull()
        assertTrue(firstFailure is java.io.IOException)
        assertArrayEquals(byteArrayOf(1, 2, 3), api.firstCertificate)
        assertArrayEquals(byteArrayOf(5, 6, 7), api.firstProof)
        assertFalse(certificate.all { it == 0.toByte() })

        pending.activate()
        assertEquals(2, api.activationCalls)
        assertTrue(certificate.all { it == 0.toByte() })
        assertTrue(proof.all { it == 0.toByte() })
        assertTrue(recoveryKey.all { it == 0.toByte() })
        assertTrue(runCatching { pending.activate() }.isFailure)
    }

    private class RetryingApi : CandidateEnrollmentApi {
        var activationCalls = 0
        var firstCertificate = byteArrayOf()
        var firstProof = byteArrayOf()

        override fun requestChallenge(
            enrollmentCertificate: ByteArray,
            recoveryPublicKey: ByteArray,
        ): CandidateEnrollmentChallenge = error("Not used by this test")

        override fun activate(
            enrollmentCertificate: ByteArray,
            proof: ByteArray,
            recoveryPublicKey: ByteArray,
        ) {
            activationCalls++
            if (activationCalls == 1) {
                firstCertificate = enrollmentCertificate.copyOf()
                firstProof = proof.copyOf()
                throw java.io.IOException("simulated lost activation response")
            }
        }
    }

    private class FakeConnection(
        url: URL,
        private val status: Int,
        private val body: ByteArray,
        private val mediaType: String?,
    ) : HttpURLConnection(url) {
        private val output = ByteArrayOutputStream()
        var disconnected = false
            private set

        override fun connect() = Unit
        override fun disconnect() {
            disconnected = true
        }
        override fun usingProxy(): Boolean = false
        override fun getResponseCode(): Int = status
        override fun getContentType(): String? = mediaType
        override fun getOutputStream(): OutputStream = output
        override fun getInputStream(): InputStream = ByteArrayInputStream(body)
        override fun getErrorStream(): InputStream? =
            if (status in 200..299) null else ByteArrayInputStream(body)

        fun writtenBytes(): ByteArray = output.toByteArray()
    }

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
}