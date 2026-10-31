package org.sovereign.pm.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real UniFFI test for first-account authorization using the existing device context. */
@RunWith(AndroidJUnit4::class)
class NativeInitialAccountBootstrapInstrumentedTest {

    @Test
    fun firstAccountAuthorizationUsesTheExistingIdentityAndProofIsContextBound() {
        val bridge = UniFfiCryptoBridge()
        // This identity exists only in this instrumentation test; no production identity store
        // or app data is read, deleted, or replaced.
        val existingIdentity = bridge.initializeAccount()
        val mnemonic = bridge.generateRecoveryMnemonic()
        assertEquals(24, mnemonic.trim().split(Regex("\\s+")).size)

        val session = bridge.beginInitialAccountBootstrap(existingIdentity)
        try {
            val sessionIdentity = session.identity()
            assertArrayEquals(existingIdentity.accountId, sessionIdentity.accountId)
            assertArrayEquals(existingIdentity.deviceId, sessionIdentity.deviceId)
            assertArrayEquals(existingIdentity.dskPublicKey, sessionIdentity.dskPublicKey)
            assertArrayEquals(existingIdentity.ddhkPublicKey, sessionIdentity.ddhkPublicKey)

            val authorization = session.signAuthorization(mnemonic)
            try {
                assertTrue(authorization.enrollmentCertificate.isNotEmpty())
                assertEquals(32, authorization.recoveryPublicKey.size)
                assertEquals(32, authorization.recoveryCommitment.size)
                assertArrayEquals(existingIdentity.accountId, authorization.identity.accountId)
                assertArrayEquals(existingIdentity.deviceId, authorization.identity.deviceId)

                val challengeId = ByteArray(16) { (it + 1).toByte() }
                val challengeNonce = ByteArray(32) { (it + 1).toByte() }
                val proof = session.signProofOfPossession(
                    authorization.enrollmentCertificate,
                    challengeId,
                    challengeNonce,
                )
                assertTrue("Proof of possession must not be empty", proof.isNotEmpty())

                val alteredCertificate = authorization.enrollmentCertificate.copyOf()
                alteredCertificate[alteredCertificate.lastIndex] =
                    (alteredCertificate.last().toInt() xor 1).toByte()
                var alteredCertificateRejected = false
                try {
                    session.signProofOfPossession(alteredCertificate, challengeId, challengeNonce)
                } catch (_: Exception) {
                    alteredCertificateRejected = true
                }
                assertTrue("Native device context must reject a modified certificate", alteredCertificateRejected)

                alteredCertificate.fill(0)
                challengeId.fill(0)
                challengeNonce.fill(0)
                proof.fill(0)
            } finally {
                authorization.enrollmentCertificate.fill(0)
            }
        } finally {
            session.close()
        }

        var closedSessionRejected = false
        try {
            session.identity()
        } catch (_: IllegalStateException) {
            closedSessionRejected = true
        }
        assertTrue("A closed session must reject further native calls", closedSessionRejected)
    }

    @Test
    fun bootstrapRejectsAnIdentityThatDoesNotMatchTheActiveNativeHandle() {
        val bridge = UniFfiCryptoBridge()
        val identity = bridge.initializeAccount()
        val mismatched = identity.copy(dskPublicKey = identity.dskPublicKey.copyOf().apply {
            this[0] = (this[0].toInt() xor 1).toByte()
        })

        var rejected = false
        try {
            bridge.beginInitialAccountBootstrap(mismatched)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue("Bootstrap must only bind to the exact active identity", rejected)
    }
}