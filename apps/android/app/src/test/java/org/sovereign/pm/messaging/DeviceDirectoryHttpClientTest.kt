package org.sovereign.pm.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import org.sovereign.pm.crypto.DeviceRequestSigner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeviceDirectoryHttpClientTest {
    private val accountId = ByteArray(16) { (it + 1).toByte() }
    private val deviceId = ByteArray(16) { (0xA0 + it).toByte() }
    private val dsk = ByteArray(32) { (it + 3).toByte() }
    private val ddhk = ByteArray(32) { (it + 7).toByte() }

    @Test
    fun fetchUsesHttpsGetAndValidatesExactLocalIdentity() {
        val body = encodeDirectory(accountId, deviceId, dsk, ddhk, epoch = 9, revoked = false)
        var capturedUrl: URL? = null
        var captured: FakeConnection? = null
        val client = DeviceDirectoryHttpClient(
            baseUrl = "https://gateway.example.test/",
            crypto = FakeCryptoBridge(),
            identity = identity(),
            connectionFactory = { url ->
                capturedUrl = url
                FakeConnection(url, HttpURLConnection.HTTP_OK, body, "application/cbor; charset=utf-8")
                    .also { captured = it }
            },
        )

        val result = client.fetchOwnDirectory()

        assertEquals("/v1/devices/${uuid(accountId)}/${uuid(deviceId)}", capturedUrl?.path)
        assertEquals("GET", captured?.requestMethod)
        assertEquals("application/cbor", captured?.getRequestProperty("Accept"))
        assertFalse(captured?.instanceFollowRedirects ?: true)
        assertEquals(9UL, result.epoch)
        assertFalse(result.revoked)
        assertTrue(captured?.disconnected == true)
    }

    @Test
    fun mismatchedDirectoryPublicKeyIsRejected() {
        val wrongDsk = dsk.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val body = encodeDirectory(accountId, deviceId, wrongDsk, ddhk, epoch = 1, revoked = false)
        val client = client(body)

        val failure = runCatching { client.fetchOwnDirectory() }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertTrue(failure?.message?.contains("DSK") == true)
    }

    @Test
    fun revokedDeviceIsRejected() {
        val body = encodeDirectory(accountId, deviceId, dsk, ddhk, epoch = 1, revoked = true)
        val failure = runCatching { client(body).fetchOwnDirectory() }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertTrue(failure?.message?.contains("revoked") == true)
    }

    @Test
    fun mismatchedAccountAndDeviceIdsAreRejected() {
        val wrongAccount = accountId.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val accountFailure = runCatching {
            client(encodeDirectory(wrongAccount, deviceId, dsk, ddhk, epoch = 1, revoked = false)).fetchOwnDirectory()
        }.exceptionOrNull()
        assertTrue(accountFailure is IOException)
        assertTrue(accountFailure?.message?.contains("account ID") == true)

        val wrongDevice = deviceId.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val deviceFailure = runCatching {
            client(encodeDirectory(accountId, wrongDevice, dsk, ddhk, epoch = 1, revoked = false)).fetchOwnDirectory()
        }.exceptionOrNull()
        assertTrue(deviceFailure is IOException)
        assertTrue(deviceFailure?.message?.contains("device ID") == true)
    }

    @Test
    fun epochOutsideV1RangeIsRejected() {
        val body = encodeDirectory(accountId, deviceId, dsk, ddhk, epoch = 4_294_967_296L, revoked = false)
        val failure = runCatching { client(body).fetchOwnDirectory() }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertTrue(failure?.message?.contains("epoch") == true)
    }

    @Test
    fun redirectsAndUnexpectedStatusAreNotAccepted() {
        var captured: FakeConnection? = null
        val client = DeviceDirectoryHttpClient(
            baseUrl = "https://gateway.example.test",
            crypto = FakeCryptoBridge(),
            identity = identity(),
            connectionFactory = { url ->
                FakeConnection(url, HttpURLConnection.HTTP_MOVED_TEMP, byteArrayOf(), "application/json")
                    .also { captured = it }
            },
        )
        val failure = runCatching { client.fetchOwnDirectory() }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertFalse(captured?.instanceFollowRedirects ?: true)
    }

    @Test
    fun cleartextCredentialAndPathUrlsAreRejected() {
        val invalid = listOf(
            "http://gateway.example.test",
            "https://user:password@gateway.example.test",
            "https://gateway.example.test/api",
            "https://gateway.example.test?token=x",
            "https://gateway.example.test#fragment",
        )
        invalid.forEach { url ->
            val result = runCatching {
                DeviceDirectoryHttpClient(url, FakeCryptoBridge(), identity())
            }
            assertTrue("Expected URL rejection: $url", result.isFailure)
        }
    }

    private fun client(body: ByteArray): DeviceDirectoryHttpClient = DeviceDirectoryHttpClient(
        baseUrl = "https://gateway.example.test",
        crypto = FakeCryptoBridge(),
        identity = identity(),
        connectionFactory = { url ->
            FakeConnection(url, HttpURLConnection.HTTP_OK, body, "application/cbor")
        },
    )

    private fun identity() = AccountIdentity(accountId, deviceId, dsk, ddhk)

    private fun encodeDirectory(
        account: ByteArray,
        device: ByteArray,
        signingKey: ByteArray,
        dhKey: ByteArray,
        epoch: Long,
        revoked: Boolean,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(0xA7) // map(7)
        writeUnsigned(output, 1); writeBytes(output, account)
        writeUnsigned(output, 2); writeBytes(output, device)
        writeUnsigned(output, 3); writeUnsigned(output, epoch)
        writeUnsigned(output, 4); writeBytes(output, signingKey)
        writeUnsigned(output, 5); writeBytes(output, dhKey)
        writeUnsigned(output, 7); output.write(if (revoked) 0xF5 else 0xF4)
        writeUnsigned(output, 8); writeUnsigned(output, 1_700_000_000L)
        return output.toByteArray()
    }

    private fun writeBytes(output: ByteArrayOutputStream, value: ByteArray) {
        if (value.size <= 23) {
            output.write(0x40 or value.size)
        } else {
            output.write(0x58)
            output.write(value.size)
        }
        output.write(value)
    }

    private fun writeUnsigned(output: ByteArrayOutputStream, value: Long) {
        require(value >= 0) { "CBOR test helper only supports unsigned integers" }
        when {
            value <= 23 -> output.write(value.toInt())
            value <= 0xFF -> {
                output.write(0x18)
                output.write(value.toInt())
            }
            value <= 0xFFFF -> {
                output.write(0x19)
                output.write((value ushr 8).toInt())
                output.write(value.toInt())
            }
            value <= 0xFFFF_FFFFL -> {
                output.write(0x1A)
                for (shift in 24 downTo 0 step 8) {
                    output.write((value ushr shift).toInt() and 0xFF)
                }
            }
            else -> {
                output.write(0x1B)
                for (shift in 56 downTo 0 step 8) {
                    output.write((value ushr shift).toInt() and 0xFF)
                }
            }
        }
    }

    private fun uuid(bytes: ByteArray): String {
        val hex = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
    }

    private class FakeCryptoBridge : CryptoBridge {
        override fun decodeStrictCanonical(bytes: ByteArray): ByteArray = bytes.copyOf()
        override fun generateRecoveryMnemonic(): String = error("Not used")
        override fun initializeAccount(): AccountIdentity = error("Not used")
        override fun sealCurrentAccount(storageKey: ByteArray): ByteArray = error("Not used")
        override fun restoreAccount(record: ByteArray, storageKey: ByteArray): AccountIdentity = error("Not used")
        override fun bindDeviceRequestSigner(identity: AccountIdentity): DeviceRequestSigner = error("Not used")
    }

    private class FakeConnection(
        url: URL,
        private val status: Int,
        private val body: ByteArray,
        private val mediaType: String?,
    ) : HttpURLConnection(url) {
        var disconnected = false
            private set

        override fun connect() = Unit
        override fun disconnect() { disconnected = true }
        override fun usingProxy(): Boolean = false
        override fun getResponseCode(): Int = status
        override fun getContentType(): String? = mediaType
        override fun getInputStream(): InputStream = ByteArrayInputStream(body)
        override fun getErrorStream(): InputStream? =
            if (status in 200..299) null else ByteArrayInputStream(body)
    }
}