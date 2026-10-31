package org.sovereign.pm.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs real UniFFI calls on an Android device or emulator.
 *
 * These tests validate native enrollment behavior through the Android bridge.
 * They do not perform server activation.
 */
@RunWith(AndroidJUnit4::class)
class NativeDeviceEnrollmentSessionInstrumentedTest {

    @Test
    fun additionalDeviceEnrollmentAndPopAreBoundToNativeContext() {
        val bridge = UniFfiCryptoBridge()
        val existingIdentity = bridge.initializeAccount()

        val session =
            bridge.beginAdditionalDeviceEnrollment(existingIdentity.accountId)

        try {
            val newIdentity = session.identity()

            assertArrayEquals(
                "Additional device must belong to the existing account",
                existingIdentity.accountId,
                newIdentity.accountId
            )

            assertFalse(
                "Additional device must have a different device ID",
                existingIdentity.deviceId.contentEquals(newIdentity.deviceId)
            )

            assertTrue(
                "DSK public key must not be empty",
                newIdentity.dskPublicKey.isNotEmpty()
            )

            assertTrue(
                "DDHK public key must not be empty",
                newIdentity.ddhkPublicKey.isNotEmpty()
            )

            val recoveryMnemonic =
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

            val certificate =
                session.signEnrollmentCertificate(recoveryMnemonic, 2UL)

            assertTrue(
                "Enrollment certificate must not be empty",
                certificate.isNotEmpty()
            )

            val challengeId = ByteArray(16) { (it + 1).toByte() }
            val challengeNonce = ByteArray(32) { (it + 1).toByte() }

            val proof = session.signProofOfPossession(
                certificate,
                challengeId,
                challengeNonce
            )

            assertTrue(
                "Proof of possession must not be empty",
                proof.isNotEmpty()
            )

            val alteredCertificate = certificate.copyOf()
            alteredCertificate[alteredCertificate.lastIndex] =
                (alteredCertificate.last().toInt() xor 1).toByte()

            var alteredCertificateRejected = false

            try {
                session.signProofOfPossession(
                    alteredCertificate,
                    challengeId,
                    challengeNonce
                )
            } catch (_: Exception) {
                alteredCertificateRejected = true
            }

            assertTrue(
                "Native binding must reject an altered enrollment certificate",
                alteredCertificateRejected
            )
        } finally {
            session.close()
        }
    }

    @Test
    fun certificateFromAnotherSessionIsRejected() {
        val bridge = UniFfiCryptoBridge()
        val existingIdentity = bridge.initializeAccount()

        val firstSession =
            bridge.beginAdditionalDeviceEnrollment(existingIdentity.accountId)

        try {
            val secondSession =
                bridge.beginAdditionalDeviceEnrollment(existingIdentity.accountId)

            try {
                val recoveryMnemonic =
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

                val firstCertificate =
                    firstSession.signEnrollmentCertificate(
                        recoveryMnemonic,
                        2UL
                    )

                val secondCertificate =
                    secondSession.signEnrollmentCertificate(
                        recoveryMnemonic,
                        2UL
                    )

                assertFalse(
                    "Different device sessions must have different certificates",
                    firstCertificate.contentEquals(secondCertificate)
                )

                val challengeId = ByteArray(16) { (it + 1).toByte() }
                val challengeNonce = ByteArray(32) { (it + 1).toByte() }

                var crossSessionRejected = false

                try {
                    secondSession.signProofOfPossession(
                        firstCertificate,
                        challengeId,
                        challengeNonce
                    )
                } catch (_: Exception) {
                    crossSessionRejected = true
                }

                assertTrue(
                    "A session must reject a certificate bound to another device",
                    crossSessionRejected
                )

                val validProof = secondSession.signProofOfPossession(
                    secondCertificate,
                    challengeId,
                    challengeNonce
                )

                assertTrue(
                    "The session must still sign proof for its own certificate",
                    validProof.isNotEmpty()
                )
            } finally {
                secondSession.close()
            }
        } finally {
            firstSession.close()
        }
    }

    @Test
    fun closedEnrollmentSessionRejectsFurtherNativeCalls() {
        val bridge = UniFfiCryptoBridge()
        val existingIdentity = bridge.initializeAccount()

        val session =
            bridge.beginAdditionalDeviceEnrollment(existingIdentity.accountId)

        session.close()

        var closedSessionRejected = false

        try {
            session.identity()
        } catch (_: IllegalStateException) {
            closedSessionRejected = true
        }

        assertTrue(
            "A closed enrollment session must reject further native calls",
            closedSessionRejected
        )
    }
}
