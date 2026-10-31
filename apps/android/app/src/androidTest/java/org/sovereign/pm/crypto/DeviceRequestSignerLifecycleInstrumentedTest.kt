package org.sovereign.pm.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceRequestSignerLifecycleInstrumentedTest {

    @Test
    fun boundSignerRemainsOnOriginalNativeAccountAfterBridgeReplacement() {
        val bridge = UniFfiCryptoBridge()
        val originalIdentity = bridge.initializeAccount()
        val signer = bridge.bindDeviceRequestSigner(originalIdentity)

        try {
            val replacementIdentity = bridge.initializeAccount()
            assertFalse(originalIdentity.accountId.contentEquals(replacementIdentity.accountId))
            assertFalse(originalIdentity.deviceId.contentEquals(replacementIdentity.deviceId))

            val proof = signer.signDeviceHttpRequestV1(
                epoch = 1UL,
                method = "GET",
                requestTarget = "/v1/demo/messages",
                body = ByteArray(0),
            )
            assertEquals(145, proof.size)
        } finally {
            signer.close()
        }

        val afterClose = runCatching {
            signer.signDeviceHttpRequestV1(
                epoch = 1UL,
                method = "GET",
                requestTarget = "/v1/demo/messages",
                body = ByteArray(0),
            )
        }
        assertTrue("Closed signer must reject further use", afterClose.isFailure)
    }

    @Test
    fun refusesToBindIdentityThatIsNotTheActiveNativeAccount() {
        val bridge = UniFfiCryptoBridge()
        val oldIdentity = bridge.initializeAccount()
        val activeIdentity = bridge.initializeAccount()

        val rejected = runCatching { bridge.bindDeviceRequestSigner(oldIdentity) }
        assertTrue("Signer binding must reject a different account identity", rejected.isFailure)

        val signer = bridge.bindDeviceRequestSigner(activeIdentity)
        signer.close()
    }
}