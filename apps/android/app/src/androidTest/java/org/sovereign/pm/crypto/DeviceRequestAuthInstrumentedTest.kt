package org.sovereign.pm.crypto

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Base64

/** Exercises DeviceRequestAuthV1 through the real Android UniFFI/JNA boundary. */
@RunWith(AndroidJUnit4::class)
class DeviceRequestAuthInstrumentedTest {

    @Test
    fun nativeAccountContextCreatesRequestProofForItsIdentity() {
        val bridge = UniFfiCryptoBridge()
        val identity = bridge.initializeAccount()
        val epoch = 2UL
        val method = "POST"
        val requestTarget = "/v1/candidate/messages?limit=10"
        val body = "{\"ciphertext\":\"android-instrumentation\"}".toByteArray(Charsets.UTF_8)

        // The signer is pinned to this exact native identity and owns an independent
        // native handle. Close it after the proof is produced; the proof is public data.
        val signer = bridge.bindDeviceRequestSigner(identity)
        val proof = try {
            signer.signDeviceHttpRequestV1(
                epoch = epoch,
                method = method,
                requestTarget = requestTarget,
                body = body,
            )
        } finally {
            signer.close()
        }

        // version(1) | account(16) | device(16) | epoch(8) | timestamp(8) | nonce(32) | Ed25519 signature(64).
        assertEquals("Request proof must be exactly 145 bytes", 145, proof.size)
        assertEquals("Request proof version must be 1", 1, proof[0].toInt() and 0xff)
        assertArrayEquals("Proof account ID must match native identity", identity.accountId, proof.copyOfRange(1, 17))
        assertArrayEquals("Proof device ID must match native identity", identity.deviceId, proof.copyOfRange(17, 33))
        assertEquals("Proof epoch must match requested epoch", epoch, readUnsignedBigEndian(proof, 33, 8))

        val timestamp = readUnsignedBigEndian(proof, 41, 8).toLong()
        val now = System.currentTimeMillis() / 1000L
        assertTrue(
            "Proof timestamp must be within the server's 5-minute tolerance",
            kotlin.math.abs(now - timestamp) <= 300L
        )

        assertTrue("Proof nonce must not be all zero", proof.copyOfRange(49, 81).any { it.toInt() != 0 })
        assertTrue("Ed25519 signature must not be all zero", proof.copyOfRange(81, 145).any { it.toInt() != 0 })
        assertEquals("Native DSK public key must be 32 bytes", 32, identity.dskPublicKey.size)

        // Export only public verification material and the short-lived test proof.
        // The private DSK remains inside the native Rust AccountContext.
        val authorizationHeader = "PM-Device-V1 " + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(proof)
        val fixture = JSONObject()
            .put("authorization_header", authorizationHeader)
            .put("public_key_hex", identity.dskPublicKey.toLowerHex())
            .put("method", method)
            .put("request_target", requestTarget)
            .put("body_base64", Base64.getEncoder().encodeToString(body))
            .toString()

        // Gradle uninstalls the target APK after connected instrumentation tests.
        // Emit the public-only fixture into the per-test logcat artifact so it survives teardown.
        Log.i("PM_GATE1_AUTH", "PM_GATE1_ANDROID_PROOF_JSON=" + fixture)

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        File(context.cacheDir, "pm-gate1-android-proof.json").writeText(fixture, Charsets.UTF_8)
    }

    @Test
    fun requestSigningRequiresAnInitializedNativeAccount() {
        val bridge = UniFfiCryptoBridge()
        val uninitializedIdentity = AccountIdentity(
            accountId = ByteArray(16),
            deviceId = ByteArray(16),
            dskPublicKey = ByteArray(32),
            ddhkPublicKey = ByteArray(32),
        )

        // Binding must fail before any native account context has been initialized.
        val binding = runCatching {
            bridge.bindDeviceRequestSigner(uninitializedIdentity)
        }
        assertTrue("Signer binding must fail before account initialization", binding.isFailure)
    }

    private fun readUnsignedBigEndian(bytes: ByteArray, offset: Int, length: Int): ULong {
        require(length in 1..8)
        require(offset >= 0 && offset + length <= bytes.size)

        var result = 0UL
        for (index in offset until offset + length) {
            result = (result shl 8) or bytes[index].toUByte().toULong()
        }
        return result
    }

    private fun ByteArray.toLowerHex(): String = buildString(size * 2) {
        for (byte in this@toLowerHex) append("%02x".format(byte.toInt() and 0xff))
    }
}
