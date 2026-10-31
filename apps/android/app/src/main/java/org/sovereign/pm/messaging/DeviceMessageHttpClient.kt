package org.sovereign.pm.messaging

import org.json.JSONObject
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.CryptoBridge
import org.sovereign.pm.crypto.DeviceRequestSigner
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.time.Instant
import java.util.Base64
import java.util.Locale

 data class DeviceMessageSendReceipt(
    val envelopeId: String,
    val recipientDeviceId: String,
    val expiresAt: String,
)

data class FetchedDeviceMessage(
    val envelopeId: String,
    val envelopeCbor: ByteArray,
    val createdAt: String,
    val expiresAt: String,
)

class DeviceMessageHttpException(
    val httpStatus: Int,
    val errorCode: String,
) : IOException("Device message HTTP error: $httpStatus ($errorCode)")

class DeviceMessageHttpClient(
    baseUrl: String,
    private val crypto: CryptoBridge,
    identity: AccountIdentity,
    private val connectTimeoutMs: Int = 5_000,
    private val readTimeoutMs: Int = 5_000,
    private val connectionFactory: (URL) -> HttpURLConnection = { url ->
        url.openConnection() as HttpURLConnection
    },
) : AutoCloseable {
    companion object {
        private const val DIRECTORY_MAX_BYTES = 4 * 1024
        private const val ERROR_MAX_BYTES = 8 * 1024
        private const val SEND_MAX_BYTES = 1 * 1024 * 1024
        private const val FETCH_MAX_RESPONSE_BYTES = 9 * 1024 * 1024
        private const val MAX_ENVELOPE_BYTES = 65_552
        private const val MAX_FETCH_COUNT = 100
        private const val DEFAULT_FETCH_COUNT = 50
        private const val DEVICE_PROOF_BYTES = 145
        private const val DIRECTORY_MEDIA_TYPE = "application/cbor"
        private const val MESSAGE_MEDIA_TYPE = "application/cbor"
        private const val JSON_MEDIA_TYPE = "application/json"
        private const val AUTH_SCHEME = "PM-Device-V1 "
        private val UUID_REGEX = Regex(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
                "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        )
    }

    private val origin: String
    private val accountId = identity.accountId.copyOf()
    private val deviceId = identity.deviceId.copyOf()
    private val dskPublicKey = identity.dskPublicKey.copyOf()
    private val ddhkPublicKey = identity.ddhkPublicKey.copyOf()
    private val requestSigner: DeviceRequestSigner

    init {
        require(accountId.size == 16) { "Account ID must be 16 bytes" }
        require(deviceId.size == 16) { "Device ID must be 16 bytes" }
        require(dskPublicKey.size == 32) { "DSK public key must be 32 bytes" }
        require(ddhkPublicKey.size == 32) { "DDHK public key must be 32 bytes" }
        require(connectTimeoutMs > 0 && readTimeoutMs > 0) { "HTTP timeouts must be positive" }

        val uri = URI(baseUrl.trim())
        require(uri.scheme.equals("https", ignoreCase = true)) {
            "Device message API requires HTTPS"
        }
        require(!uri.host.isNullOrBlank()) { "Invalid API host" }
        require(uri.rawUserInfo == null) { "API URL must not contain user information" }
        require(uri.rawQuery == null && uri.rawFragment == null) {
            "API URL must not contain a query or fragment"
        }
        require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
            "API URL must be an origin without a path"
        }
        require(uri.port == -1 || uri.port in 1..65535) { "Invalid API port" }
        origin = uri.toASCIIString().trimEnd('/')
        requestSigner = crypto.bindDeviceRequestSigner(
            AccountIdentity(
                accountId = accountId.copyOf(),
                deviceId = deviceId.copyOf(),
                dskPublicKey = dskPublicKey.copyOf(),
                ddhkPublicKey = ddhkPublicKey.copyOf(),
            )
        )
    }

    /** Sends exact canonical CBOR bytes. No automatic retry is performed. */
    fun sendEnvelope(envelopeCbor: ByteArray): DeviceMessageSendReceipt {
        require(envelopeCbor.isNotEmpty()) { "Envelope must not be empty" }
        require(envelopeCbor.size <= SEND_MAX_BYTES) {
            "Envelope exceeds the gateway's 1 MiB request limit"
        }

        val response = authenticatedRequest(
            method = "POST",
            requestTarget = "/v1/demo/messages",
            body = envelopeCbor.copyOf(),
            contentType = MESSAGE_MEDIA_TYPE,
            accept = JSON_MEDIA_TYPE,
            maxResponseBytes = ERROR_MAX_BYTES,
        )
        requireStatus(response.status, 202, response.body)

        val json = parseJson(response.body)
        val envelopeId = json.getString("envelope_id")
        val recipientDeviceId = json.getString("recipient_device_id")
        val expiresAt = json.getString("expires_at")
        require(isUuid(envelopeId)) { "Gateway returned an invalid envelope ID" }
        require(isUuid(recipientDeviceId)) { "Gateway returned an invalid recipient device ID" }
        requireValidTimestamp(expiresAt)

        return DeviceMessageSendReceipt(envelopeId, recipientDeviceId, expiresAt)
    }

    /** Fetches messages addressed to this local device identity. */
    fun fetchMessages(limit: Int = DEFAULT_FETCH_COUNT): List<FetchedDeviceMessage> {
        require(limit in 1..MAX_FETCH_COUNT) { "Fetch limit must be between 1 and $MAX_FETCH_COUNT" }
        val target = "/v1/demo/messages/${uuidFromBytes(deviceId)}?limit=$limit"
        val response = authenticatedRequest(
            method = "GET",
            requestTarget = target,
            body = ByteArray(0),
            contentType = null,
            accept = JSON_MEDIA_TYPE,
            maxResponseBytes = FETCH_MAX_RESPONSE_BYTES,
        )
        requireStatus(response.status, 200, response.body)

        val messages = parseJson(response.body).getJSONArray("messages")
        require(messages.length() <= limit) { "Gateway returned more messages than requested" }
        val output = ArrayList<FetchedDeviceMessage>(messages.length())
        for (index in 0 until messages.length()) {
            val item = messages.getJSONObject(index)
            val envelopeId = item.getString("envelope_id")
            val encodedEnvelope = item.getString("envelope_cbor_base64")
            val createdAt = item.getString("created_at")
            val expiresAt = item.getString("expires_at")

            require(isUuid(envelopeId)) { "Gateway returned an invalid envelope ID" }
            require(encodedEnvelope.isNotEmpty()) { "Gateway returned an empty message envelope" }
            val maxBase64Length = ((MAX_ENVELOPE_BYTES + 2) / 3) * 4
            require(encodedEnvelope.length <= maxBase64Length) {
                "Encoded envelope exceeds its size limit"
            }
            val envelopeBytes = try {
                Base64.getDecoder().decode(encodedEnvelope)
            } catch (error: IllegalArgumentException) {
                throw IOException("Gateway returned invalid base64 envelope data", error)
            }
            require(envelopeBytes.isNotEmpty() && envelopeBytes.size <= MAX_ENVELOPE_BYTES) {
                "Decoded envelope has an invalid size"
            }
            requireValidTimestamp(createdAt)
            requireValidTimestamp(expiresAt)
            output.add(FetchedDeviceMessage(envelopeId, envelopeBytes, createdAt, expiresAt))
        }
        return output
    }

    /** Acknowledges an envelope for this local device identity. */
    fun acknowledgeMessage(envelopeId: String) {
        require(isUuid(envelopeId)) { "Invalid envelope ID" }
        val target = "/v1/demo/messages/${uuidFromBytes(deviceId)}/$envelopeId/ack"
        val response = authenticatedRequest(
            method = "POST",
            requestTarget = target,
            body = ByteArray(0),
            contentType = null,
            accept = JSON_MEDIA_TYPE,
            maxResponseBytes = ERROR_MAX_BYTES,
        )
        requireStatus(response.status, 204, response.body)
        require(response.body.isEmpty()) {
            "Gateway returned an unexpected body for message acknowledgement"
        }
    }

    private data class HttpResponse(
        val status: Int,
        val body: ByteArray,
        val contentType: String?,
    )

    private fun authenticatedRequest(
        method: String,
        requestTarget: String,
        body: ByteArray,
        contentType: String?,
        accept: String,
        maxResponseBytes: Int,
    ): HttpResponse {
        // Current directory state is checked for each request. This is not a
        // rollback-resistant witness; the separate anti-rollback gate remains open.
        val directory = fetchAndValidateOwnDirectory()
        val proof = requestSigner.signDeviceHttpRequestV1(
            epoch = directory.epoch,
            method = method,
            requestTarget = requestTarget,
            body = body,
        )
        require(proof.size == DEVICE_PROOF_BYTES) {
            "Native signer returned a proof with an unexpected size"
        }
        val authorization = AUTH_SCHEME +
            Base64.getUrlEncoder().withoutPadding().encodeToString(proof)

        return executeRequest(
            method = method,
            requestTarget = requestTarget,
            body = body,
            contentType = contentType,
            accept = accept,
            authorization = authorization,
            maxResponseBytes = maxResponseBytes,
        )
    }

    private fun fetchAndValidateOwnDirectory(): DeviceDirectoryRecordV1 {
        val target = "/v1/devices/${uuidFromBytes(accountId)}/${uuidFromBytes(deviceId)}"
        val response = executeRequest(
            method = "GET",
            requestTarget = target,
            body = ByteArray(0),
            contentType = null,
            accept = DIRECTORY_MEDIA_TYPE,
            authorization = null,
            maxResponseBytes = DIRECTORY_MAX_BYTES,
        )
        requireStatus(response.status, 200, response.body)
        if (mediaType(response.contentType) != DIRECTORY_MEDIA_TYPE) {
            throw IOException("Gateway returned an unexpected directory content type")
        }

        val record = try {
            DeviceDirectoryCborV1.decode(response.body, crypto)
        } catch (error: Exception) {
            throw IOException("Invalid device directory record", error)
        }
        if (!record.accountId.contentEquals(accountId)) {
            throw IOException("Directory account ID does not match local identity")
        }
        if (!record.deviceId.contentEquals(deviceId)) {
            throw IOException("Directory device ID does not match local identity")
        }
        if (!record.dskPublicKey.contentEquals(dskPublicKey)) {
            throw IOException("Directory DSK does not match local identity")
        }
        if (!record.ddhkPublicKey.contentEquals(ddhkPublicKey)) {
            throw IOException("Directory DDHK does not match local identity")
        }
        if (record.revoked) throw IOException("This device is revoked")
        return record
    }

    private fun executeRequest(
        method: String,
        requestTarget: String,
        body: ByteArray,
        contentType: String?,
        accept: String,
        authorization: String?,
        maxResponseBytes: Int,
    ): HttpResponse {
        require(requestTarget.startsWith("/")) { "Request target must use absolute-path form" }
        require(!requestTarget.contains('\r') && !requestTarget.contains('\n')) {
            "Invalid request target"
        }
        val connection = connectionFactory(URL(origin + requestTarget))
        try {
            connection.requestMethod = method
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doInput = true
            connection.setRequestProperty("Accept", accept)
            if (contentType != null) connection.setRequestProperty("Content-Type", contentType)
            if (authorization != null) connection.setRequestProperty("Authorization", authorization)

            if (body.isNotEmpty()) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { output ->
                    output.write(body)
                    output.flush()
                }
            }

            val status = connection.responseCode
            val stream: InputStream? = if (status >= 400) connection.errorStream else connection.inputStream
            val responseBody = stream?.use { readBounded(it, maxResponseBytes) } ?: ByteArray(0)
            return HttpResponse(status, responseBody, connection.getHeaderField("Content-Type"))
        } finally {
            connection.disconnect()
        }
    }

    private fun requireStatus(actual: Int, expected: Int, responseBody: ByteArray) {
        if (actual == expected) return
        val code = try {
            JSONObject(String(responseBody, Charsets.UTF_8)).optString("error")
                .takeIf { it.isNotBlank() } ?: "ERR_HTTP_$actual"
        } catch (_: Exception) {
            "ERR_HTTP_$actual"
        }
        throw DeviceMessageHttpException(actual, code)
    }

    private fun parseJson(bytes: ByteArray): JSONObject {
        if (bytes.isEmpty()) throw IOException("Gateway returned an empty JSON response")
        return try {
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (error: Exception) {
            throw IOException("Gateway returned invalid JSON", error)
        }
    }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count == -1) break
            total += count
            if (total > maxBytes) throw IOException("HTTP response exceeds its configured size limit")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun mediaType(value: String?): String? =
        value?.substringBefore(';')?.trim()?.lowercase(Locale.ROOT)

    private fun requireValidTimestamp(value: String) {
        try {
            Instant.parse(value)
        } catch (error: Exception) {
            throw IOException("Gateway returned an invalid timestamp", error)
        }
    }

    private fun isUuid(value: String): Boolean = UUID_REGEX.matches(value)

    override fun close() {
        requestSigner.close()
    }

    private fun uuidFromBytes(bytes: ByteArray): String {
        require(bytes.size == 16) { "UUID byte representation must be 16 bytes" }
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
}