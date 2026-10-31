package org.sovereign.pm.bootstrap

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.time.Instant

private const val CHALLENGE_PATH = "/v1/bootstrap/initial-account/challenges"
private const val ACTIVATE_PATH = "/v1/bootstrap/initial-account/activate"

 data class InitialBootstrapChallenge(val id: ByteArray, val nonce: ByteArray, val expiresAt: Instant)

interface InitialAccountBootstrapApi {
    fun requestChallenge(certificate: ByteArray, recoveryPublicKey: ByteArray): InitialBootstrapChallenge
    fun activate(certificate: ByteArray, proof: ByteArray, recoveryPublicKey: ByteArray)
}

class InitialAccountBootstrapHttpClient(
    baseUrl: String,
    private val connectionFactory: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) : InitialAccountBootstrapApi {
    private val origin = validateOrigin(baseUrl)

    override fun requestChallenge(certificate: ByteArray, recoveryPublicKey: ByteArray): InitialBootstrapChallenge {
        require(certificate.size in 1..4096 && recoveryPublicKey.size == 32)
        val response = post(CHALLENGE_PATH, JSONObject()
            .put("enrollment_certificate_hex", certificate.toHex())
            .put("recovery_public_key_hex", recoveryPublicKey.toHex()).toString())
        if (response.status != 200 || response.contentType?.substringBefore(';')?.trim()?.lowercase() != "application/json") {
            throw bootstrapError(response)
        }
        try {
            val json = JSONObject(String(response.body, Charsets.UTF_8))
            val id = json.getString("challenge_id_hex").decodeHex(16)
            val nonce = json.getString("challenge_nonce_hex").decodeHex(32)
            val expiry = Instant.parse(json.getString("expires_at"))
            if (!expiry.isAfter(Instant.now())) throw IOException("Initial-account challenge expired.")
            return InitialBootstrapChallenge(id, nonce, expiry)
        } catch (e: Exception) { throw IOException("Invalid initial-account challenge response.", e) }
    }

    override fun activate(certificate: ByteArray, proof: ByteArray, recoveryPublicKey: ByteArray) {
        require(certificate.size in 1..4096 && proof.size in 1..2048 && recoveryPublicKey.size == 32)
        val response = post(ACTIVATE_PATH, JSONObject()
            .put("enrollment_certificate_hex", certificate.toHex())
            .put("proof_hex", proof.toHex())
            .put("recovery_public_key_hex", recoveryPublicKey.toHex()).toString())
        if (response.status != 204 || response.body.isNotEmpty()) throw bootstrapError(response)
    }

    private fun post(path: String, json: String): Response {
        val body = json.toByteArray(Charsets.UTF_8)
        require(body.size <= 16 * 1024)
        val c = connectionFactory(URL(origin + path))
        try {
            c.requestMethod = "POST"; c.connectTimeout = 5000; c.readTimeout = 5000
            c.instanceFollowRedirects = false; c.useCaches = false; c.doInput = true; c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json"); c.setRequestProperty("Accept", "application/json")
            c.setFixedLengthStreamingMode(body.size)
            c.outputStream.use { it.write(body) }
            val status = c.responseCode
            val stream = if (status in 200..299) c.inputStream else c.errorStream
            val bytes = stream?.use { readBounded(it, 8192) } ?: ByteArray(0)
            return Response(status, c.contentType, bytes)
        } finally { c.disconnect() }
    }

    private fun bootstrapError(r: Response): IOException {
        val code = try { JSONObject(String(r.body, Charsets.UTF_8)).optString("error", "ERR_HTTP_ERROR") }
            catch (_: Exception) { "ERR_HTTP_ERROR" }
        return IOException("Initial-account bootstrap failed: HTTP ${r.status} ($code)")
    }

    private fun validateOrigin(value: String): String {
        val uri = URI(value.trim())
        require(uri.scheme.equals("https", true) && !uri.host.isNullOrBlank() && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")) {
            "A valid HTTPS gateway origin is required."
        }
        return "https://${uri.rawAuthority}"
    }
    private fun readBounded(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream(); val buffer = ByteArray(1024)
        while (true) { val n=input.read(buffer); if(n<0) break; if(out.size()+n>max) throw IOException("Gateway response too large."); out.write(buffer,0,n) }
        return out.toByteArray()
    }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun String.decodeHex(expected: Int): ByteArray {
        require(length == expected*2)
        return ByteArray(expected) { i ->
            val high = Character.digit(this[i * 2], 16)
            val low = Character.digit(this[i * 2 + 1], 16)
            require(high >= 0 && low >= 0) { "malformed hex" }
            ((high shl 4) or low).toByte()
        }
    }
    private data class Response(val status: Int, val contentType: String?, val body: ByteArray)
}
