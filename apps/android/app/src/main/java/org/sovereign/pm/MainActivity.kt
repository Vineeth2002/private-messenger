package org.sovereign.pm

import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import org.sovereign.pm.security.AndroidKeystorePlatformKek
import org.sovereign.pm.security.IdentityStore

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }

        val bridge = UniFfiCryptoBridge()
        val canonicalResult = runCatching {
            bridge.decodeStrictCanonical(byteArrayOf(0x18, 0x18))
        }
        val identityResult = runCatching {
            IdentityStore(
                applicationContext,
                bridge,
                AndroidKeystorePlatformKek(applicationContext),
            ).loadOrCreate()
        }

        setContent {
            val screenText = buildString {
                append("Sovereign PM\n")
                if (canonicalResult.isSuccess) {
                    append("UniFFI CBOR: PASS\n")
                } else {
                    append("UniFFI CBOR: FAIL\n")
                }
                identityResult.fold(
                    onSuccess = { result ->
                        append("Identity storage: ${result.origin}\n")
                        append("At-rest encryption: PASS\n")
                        append("Keystore backing: ${result.kekCapabilities.backing}\n")
                        append("PPAL: ${result.kekCapabilities.achievedPpal}\n")
                        append("Account ID prefix: ${result.identity.accountId.copyOfRange(0, 4).toHex()}\n")
                    },
                    onFailure = {
                        append("Identity storage: FAILED\n")
                        append("The saved identity was not automatically replaced.\n")
                        append("Preserve app data and review storage/Keystore diagnostics before recovery.\n")
                    },
                )
            }
            Text(screenText)
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
