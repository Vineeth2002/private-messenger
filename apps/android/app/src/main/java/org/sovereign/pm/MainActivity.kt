package org.sovereign.pm

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import org.sovereign.pm.crypto.UniFfiCryptoBridge

class MainActivity : ComponentActivity() {
    private lateinit var bridge: UniFfiCryptoBridge

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        bridge = UniFfiCryptoBridge()

        val canonicalResult = runCatching {
            bridge.decodeStrictCanonical(byteArrayOf(0x18, 0x18))
        }.getOrElse {
            error("Canonical test failed: ${it::class.simpleName}: ${it.message}")
        }

        val identity = runCatching {
            bridge.initializeAccount()
        }.getOrElse {
            error("Account context initialization failed: ${it::class.simpleName}: ${it.message}")
        }

        setContent {
            Text(
                "Sovereign PM\n" +
                    "UniFFI CBOR: PASS (${canonicalResult.joinToString()})\n" +
                    "Account context: PASS\n" +
                    "Account ID: ${identity.accountId.toHex()}\n" +
                    "Device ID: ${identity.deviceId.toHex()}\n" +
                    "DSK public: ${identity.dskPublicKey.size} bytes\n" +
                    "DDHK public: ${identity.ddhkPublicKey.size} bytes"
            )
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }
}
