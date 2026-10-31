package org.sovereign.pm.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.ArrayDeque
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeviceMessageHttpClientTest {

    @Test
    fun sendSignsExactMethodTargetAndBody() {
        val fixture = Fixture()
        val envelope = byteArrayOf(0xA1.toByte(), 0x01, 0x02)
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/cbor"))
        fixture.responses.add(
            Response(
                202,
                """{"envelope_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","recipient_device_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","expires_at":"2026-10-30T12:00:00Z"}""".toByteArray(),
                "application/json",
            )
        )

        val receipt = fixture.client().sendEnvelope(envelope)
        assertEquals("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", receipt.envelopeId)
        assertEquals("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", receipt.recipientDeviceId)
        assertEquals(2, fixture.connections.size)
        assertEquals("GET", fixture.connections[0].requestMethod)
        assertEquals("/v1/devices/${fixture.accountUuid}/${fixture.deviceUuid}", fixture.connections[0].url.file)

        val request = fixture.connections[1]
        assertEquals("POST", request.requestMethod)
        assertEquals("/v1/demo/messages", request.url.file)
        assertTrue(request.requestBody.toByteArray().contentEquals(envelope))
        val authorization = request.requestHeaders["Authorization"]
            ?: throw AssertionError("Missing Authorization header")
        assertTrue(authorization.startsWith("PM-Device-V1 "))
        val proof = Base64.getUrlDecoder().decode(authorization.removePrefix("PM-Device-V1 "))
        assertEquals(145, proof.size)

        val signed = fixture.crypto.signedRequests.single()
        assertEquals("POST", signed.method)
        assertEquals("/v1/demo/messages", signed.requestTarget)
        assertTrue(signed.body.contentEquals(envelope))
        assertEquals(2UL, signed.epoch)
    }

    @Test
    fun fetchSignsExactQueryAndDecodesEnvelope() {
        val fixture = Fixture()
        val envelope = byteArrayOf(0xA1.toByte(), 0x02, 0x03)
        val encoded = Base64.getEncoder().encodeToString(envelope)
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/cbor"))
        fixture.responses.add(
            Response(
                200,
                """{"messages":[{"envelope_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","envelope_cbor_base64":"$encoded","created_at":"2026-10-30T10:00:00Z","expires_at":"2026-10-30T12:00:00Z"}]}""".toByteArray(),
                "application/json",
            )
        )

        val messages = fixture.client().fetchMessages(25)
        assertEquals(1, messages.size)
        assertTrue(messages.single().envelopeCbor.contentEquals(envelope))
        assertEquals(
            "/v1/demo/messages/${fixture.deviceUuid}?limit=25",
            fixture.connections[1].url.file,
        )
        val signed = fixture.crypto.signedRequests.single()
        assertEquals("GET", signed.method)
        assertEquals("/v1/demo/messages/${fixture.deviceUuid}?limit=25", signed.requestTarget)
        assertTrue(signed.body.isEmpty())
    }

    @Test
    fun acknowledgeSignsExactTargetWithEmptyBody() {
        val fixture = Fixture()
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/cbor"))
        fixture.responses.add(Response(204, ByteArray(0), null))

        fixture.client().acknowledgeMessage("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        val expectedTarget = "/v1/demo/messages/${fixture.deviceUuid}/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/ack"
        assertEquals(expectedTarget, fixture.connections[1].url.file)
        assertEquals("POST", fixture.connections[1].requestMethod)
        val signed = fixture.crypto.signedRequests.single()
        assertEquals(expectedTarget, signed.requestTarget)
        assertTrue(signed.body.isEmpty())
    }

    @Test
    fun revokedDeviceIsRejectedBeforeSigning() {
        val fixture = Fixture(revoked = true)
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/cbor"))
        try {
            fixture.client().fetchMessages()
            fail("Expected revoked device to be rejected")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message.orEmpty().contains("revoked", ignoreCase = true))
        }
        assertEquals(1, fixture.connections.size)
        assertTrue(fixture.crypto.signedRequests.isEmpty())
    }

    @Test
    fun directoryAccountMismatchIsRejectedBeforeSigning() {
        val fixture = Fixture(directoryAccountId = ByteArray(16) { 0x44 })
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/cbor"))
        try {
            fixture.client().fetchMessages()
            fail("Expected directory account mismatch")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message.orEmpty().contains("account ID"))
        }
        assertEquals(1, fixture.connections.size)
        assertTrue(fixture.crypto.signedRequests.isEmpty())
    }

    @Test
    fun directoryContentTypeMustBeApplicationCbor() {
        val fixture = Fixture()
        fixture.responses.add(Response(200, fixture.directoryBytes, "application/json"))
        try {
            fixture.client().fetchMessages()
            fail("Expected directory content type mismatch")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message.orEmpty().contains("content type"))
        }
        assertEquals(1, fixture.connections.size)
        assertTrue(fixture.crypto.signedRequests.isEmpty())
    }

    private data class Response(val status: Int, val body: ByteArray, val contentType: String?)
    private data class SignedRequest(
        val epoch: ULong,
        val method: String,
        val requestTarget: String,
        val body: ByteArray,
    )

    private class FakeCrypto : CryptoBridge {
        val signedRequests = mutableListOf<SignedRequest>()

        override fun decodeStrictCanonical(bytes: ByteArray): ByteArray = bytes.copyOf()
        override fun initializeAccount(): AccountIdentity = error("Not used in this test")
        override fun sealCurrentAccount(storageKey: ByteArray): ByteArray = error("Not used in this test")
        override fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity =
            error("Not used in this test")

        override fun generateRecoveryMnemonic(): String = error("Not used in this test")

        override fun bindDeviceRequestSigner(identity: AccountIdentity): org.sovereign.pm.crypto.DeviceRequestSigner =
            object : org.sovereign.pm.crypto.DeviceRequestSigner {
                override fun signDeviceHttpRequestV1(
                    epoch: ULong,
                    method: String,
                    requestTarget: String,
                    body: ByteArray,
                ): ByteArray {
                    signedRequests.add(SignedRequest(epoch, method, requestTarget, body.copyOf()))
                    return ByteArray(145) { it.toByte() }
                }

                override fun close() = Unit
            }
    }

    private class FakeConnection(
        url: URL,
        private val response: Response,
    ) : HttpURLConnection(url) {
        val requestHeaders = mutableMapOf<String, String>()
        val requestBody = ByteArrayOutputStream()

        override fun connect() = Unit
        override fun disconnect() = Unit
        override fun usingProxy(): Boolean = false
        override fun getOutputStream(): OutputStream = requestBody
        override fun getInputStream(): InputStream = ByteArrayInputStream(response.body)
        override fun getErrorStream(): InputStream? =
            if (response.status >= 400) ByteArrayInputStream(response.body) else null
        override fun getResponseCode(): Int = response.status
        override fun getHeaderField(name: String?): String? =
            if (name.equals("Content-Type", ignoreCase = true)) response.contentType else null
        override fun setRequestProperty(key: String, value: String) {
            requestHeaders[key] = value
        }
    }

    private class Fixture(
        private val localAccountId: ByteArray = ByteArray(16) { it.toByte() },
        directoryAccountId: ByteArray = localAccountId.copyOf(),
        private val revoked: Boolean = false,
    ) {
        private val localDeviceId = ByteArray(16) { (it + 16).toByte() }
        private val dsk = ByteArray(32) { (it + 32).toByte() }
        private val ddhk = ByteArray(32) { (it + 64).toByte() }
        val accountUuid = DeviceMessageHttpClientTest.uuid(localAccountId)
        val deviceUuid = DeviceMessageHttpClientTest.uuid(localDeviceId)
        val crypto = FakeCrypto()
        val responses = ArrayDeque<Response>()
        val connections = mutableListOf<FakeConnection>()
        val directoryBytes = DeviceMessageHttpClientTest.encodeDirectory(
            directoryAccountId,
            localDeviceId,
            dsk,
            ddhk,
            revoked,
        )

        fun client(): DeviceMessageHttpClient = DeviceMessageHttpClient(
            baseUrl = "https://gateway.example",
            crypto = crypto,
            identity = AccountIdentity(
                accountId = localAccountId.copyOf(),
                deviceId = localDeviceId.copyOf(),
                dskPublicKey = dsk.copyOf(),
                ddhkPublicKey = ddhk.copyOf(),
            ),
            connectionFactory = { url ->
                check(responses.isNotEmpty()) { "No fake HTTP response was queued" }
                FakeConnection(url, responses.removeFirst()).also { connections.add(it) }
            },
        )
    }

    private companion object {
        fun uuid(bytes: ByteArray): String {
            val hex = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-" +
                "${hex.substring(16, 20)}-${hex.substring(20, 32)}"
        }

        fun encodeDirectory(
            accountId: ByteArray,
            deviceId: ByteArray,
            dsk: ByteArray,
            ddhk: ByteArray,
            revoked: Boolean,
        ): ByteArray {
            val output = ByteArrayOutputStream()
            output.write(0xA7) // seven map entries; push key 6 is absent
            writeUnsigned(output, 1)
            writeByteString(output, accountId)
            writeUnsigned(output, 2)
            writeByteString(output, deviceId)
            writeUnsigned(output, 3)
            writeUnsigned(output, 2)
            writeUnsigned(output, 4)
            writeByteString(output, dsk)
            writeUnsigned(output, 5)
            writeByteString(output, ddhk)
            writeUnsigned(output, 7)
            output.write(if (revoked) 0xF5 else 0xF4)
            writeUnsigned(output, 8)
            writeUnsigned(output, 1_700_000_000L)
            return output.toByteArray()
        }

        fun writeByteString(output: ByteArrayOutputStream, bytes: ByteArray) {
            writeHead(output, 2, bytes.size.toULong())
            output.write(bytes)
        }

        fun writeUnsigned(output: ByteArrayOutputStream, value: Long) {
            writeHead(output, 0, value.toULong())
        }

        fun writeHead(output: ByteArrayOutputStream, majorType: Int, value: ULong) {
            when {
                value < 24UL -> output.write((majorType shl 5) or value.toInt())
                value <= 0xFFUL -> {
                    output.write((majorType shl 5) or 24)
                    output.write(value.toInt())
                }
                value <= 0xFFFFUL -> {
                    output.write((majorType shl 5) or 25)
                    output.write((value.toInt() shr 8) and 0xFF)
                    output.write(value.toInt() and 0xFF)
                }
                value <= 0xFFFF_FFFFUL -> {
                    output.write((majorType shl 5) or 26)
                    for (shift in 24 downTo 0 step 8) output.write((value shr shift).toInt() and 0xFF)
                }
                else -> {
                    output.write((majorType shl 5) or 27)
                    for (shift in 56 downTo 0 step 8) output.write((value shr shift).toInt() and 0xFF)
                }
            }
        }
    }
}