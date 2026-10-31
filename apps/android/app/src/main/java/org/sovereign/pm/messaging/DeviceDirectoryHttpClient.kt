package org.sovereign.pm.messaging

import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

/**
 * Reads the gateway's persistence-backed record for this exact local device.
 * The response is protected by normal HTTPS certificate validation, but it is not
 * independently signed and does not provide rollback-resistant evidence.
 */
internal class DeviceDirectoryHttpClient(
    baseUrl: String,
    private val crypto: CryptoBridge,
    private val identity: AccountIdentity,
    private val connectionFactory: (URL) -> HttpURLConnection = { url ->
        url.openConnection() as HttpURLConnection
    },
) {
    private val origin = normalizeOrigin(baseUrl)

    init {
        require(identity.accountId.size == UUID_BYTES) { "Local account ID must be 16 bytes" }
        require(identity.deviceId.size == UUID_BYTES) { "Local device ID must be 16 bytes" }
        require(identity.dskPublicKey.size == PUBLIC_KEY_BYTES) { "Local DSK must be 32 bytes" }
        require(identity.ddhkPublicKey.size == PUBLIC_KEY_BYTES) { "Local DDHK must be 32 bytes" }
    }

    @Throws(IOException::class)
    fun fetchOwnDirectory(): DeviceDirectoryRecordV1 {
        val target = "/v1/devices/${uuidFromBytes(identity.accountId)}/${uuidFromBytes(identity.deviceId)}"
        val response = executeGet(target)
        if (response.status != HttpURLConnection.HTTP_OK) {
            throw IOException("Gateway directory request failed with HTTP ${response.status}")
        }
        if (mediaType(response.contentType) != DIRECTORY_MEDIA_TYPE) {
            throw IOException("Gateway returned an unexpected directory content type")
        }

        val record = try {
            DeviceDirectoryCborV1.decode(response.body, crypto)
        } catch (error: Exception) {
            throw IOException("Gateway returned an invalid device directory record", error)
        }

        if (!record.accountId.contentEquals(identity.accountId)) {
            throw IOException("Directory account ID does not match the local identity")
        }
        if (!record.deviceId.contentEquals(identity.deviceId)) {
            throw IOException("Directory device ID does not match the local identity")
        }
        if (!record.dskPublicKey.contentEquals(identity.dskPublicKey)) {
            throw IOException("Directory DSK does not match the local identity")
        }
        if (!record.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)) {
            throw IOException("Directory DDHK does not match the local identity")
        }
        if (record.epoch == 0UL || record.epoch > MAX_V1_EPOCH) {
            throw IOException("Directory account epoch is outside the V1 range")
        }
        if (record.revoked) {
            throw IOException("Gateway directory marks this device as revoked")
        }
        return record
    }

    private fun executeGet(target: String): HttpResponse {
        require(target.startsWith("/") && !target.contains('\r') && !target.contains('\n')) {
            "Invalid directory request target"
        }
        val connection = connectionFactory(URL(origin + target))
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = DEFAULT_TIMEOUT_MS
            connection.readTimeout = DEFAULT_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.setRequestProperty("Accept", DIRECTORY_MEDIA_TYPE)

            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = if (stream == null) byteArrayOf() else stream.use { readBounded(it) }
            return HttpResponse(status, connection.contentType, body)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > MAX_DIRECTORY_BYTES) {
                throw IOException("Gateway directory response exceeds the size limit")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun mediaType(value: String?): String? =
        value?.substringBefore(';')?.trim()?.lowercase(Locale.ROOT)

    private fun uuidFromBytes(bytes: ByteArray): String {
        require(bytes.size == UUID_BYTES) { "UUID byte representation must be 16 bytes" }
        val hex = bytes.joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xFF) }
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

    private data class HttpResponse(
        val status: Int,
        val contentType: String?,
        val body: ByteArray,
    )

    companion object {
        private const val UUID_BYTES = 16
        private const val PUBLIC_KEY_BYTES = 32
        private const val DIRECTORY_MEDIA_TYPE = "application/cbor"
        private const val MAX_DIRECTORY_BYTES = 4096
        private const val DEFAULT_TIMEOUT_MS = 5000
        private const val MAX_V1_EPOCH = 4_294_967_295UL

        private fun normalizeOrigin(value: String): String {
            require(value.isNotBlank() && value == value.trim()) {
                "Gateway URL must not be empty or contain surrounding whitespace"
            }
            val uri = try {
                URI(value)
            } catch (error: Exception) {
                throw IllegalArgumentException("Gateway URL is invalid", error)
            }
            require(uri.isAbsolute && uri.scheme.equals("https", ignoreCase = true)) {
                "Device directory requires an HTTPS gateway URL"
            }
            require(uri.host != null && uri.rawUserInfo == null &&
                uri.rawQuery == null && uri.rawFragment == null) {
                "Gateway URL must not contain credentials, query, or fragment"
            }
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
                "Gateway URL must be an origin without an application path"
            }
            require(uri.port == -1 || uri.port in 1..65535) {
                "Gateway URL contains an invalid port"
            }
            return uri.toASCIIString().trimEnd('/')
        }
    }
}