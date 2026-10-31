package org.sovereign.pm

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import org.sovereign.pm.bootstrap.InitialAccountBootstrapCoordinator
import org.sovereign.pm.bootstrap.InitialAccountBootstrapHttpClient
import org.sovereign.pm.messaging.DeviceDirectoryHttpClient
import org.sovereign.pm.security.AndroidKeystorePlatformKek
import org.sovereign.pm.security.IdentityStore
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private val directoryExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Recovery phrases are displayed in this activity even in debug builds.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

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
        val identityLoad = identityResult.getOrNull()

        setContent {
            var gatewayOrigin by remember { mutableStateOf("") }
            var isVerifying by remember { mutableStateOf(false) }
            var directoryStatus by remember { mutableStateOf("Not checked") }
            var directoryEpoch by remember { mutableStateOf<String?>(null) }
            var recoveryPhrase by remember { mutableStateOf<String?>(null) }
            var recoveryPhraseBackedUp by remember { mutableStateOf(false) }
            var isRegistering by remember { mutableStateOf(false) }
            var registrationStatus by remember { mutableStateOf("Not registered") }

            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text("Sovereign PM", style = MaterialTheme.typography.headlineMedium)
                        Text("Local cryptographic state", style = MaterialTheme.typography.titleMedium)
                        Text(if (canonicalResult.isSuccess) "UniFFI canonical CBOR: PASS" else "UniFFI canonical CBOR: FAIL")
                        if (identityLoad == null) {
                            Text("Identity storage: FAILED")
                            Text("The saved identity was not automatically replaced. Preserve app data and inspect Keystore/storage diagnostics before recovery.")
                            Text(identityResult.exceptionOrNull()?.message ?: "Identity initialization failed")
                        } else {
                            Text("Identity storage: ${identityLoad.origin}")
                            Text("At-rest encryption: PASS")
                            Text("Keystore backing: ${identityLoad.kekCapabilities.backing}")
                            Text("PPAL: ${identityLoad.kekCapabilities.achievedPpal}")
                            Text("Account ID: ${identityLoad.identity.accountId.toHexPrefix()}")
                            Text("Device ID: ${identityLoad.identity.deviceId.toHexPrefix()}")
                        }

                        Text("Initial account registration", style = MaterialTheme.typography.titleMedium)
                        Text("This registers the existing local identity as the first device. It does not create a replacement identity.")
                        Button(
                            onClick = {
                                recoveryPhrase = bridge.generateRecoveryMnemonic()
                                recoveryPhraseBackedUp = false
                                registrationStatus = "Recovery phrase generated. Back it up before registration."
                            },
                            enabled = identityLoad != null && !isRegistering,
                        ) { Text("Generate recovery phrase") }
                        recoveryPhrase?.let { phrase ->
                            Text("Recovery phrase — write it down offline and never share it:")
                            Text(phrase, style = MaterialTheme.typography.bodyLarge)
                            androidx.compose.foundation.layout.Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                Checkbox(checked = recoveryPhraseBackedUp, onCheckedChange = { recoveryPhraseBackedUp = it })
                                Text("I have securely backed up this recovery phrase")
                            }
                        }
                        Button(
                            onClick = {
                                val activeIdentity = identityLoad?.identity
                                val phrase = recoveryPhrase
                                if (activeIdentity != null && phrase != null && recoveryPhraseBackedUp && gatewayOrigin.isNotBlank()) {
                                    isRegistering = true
                                    registrationStatus = "Registering first device…"
                                    val configuredOrigin = gatewayOrigin
                                    directoryExecutor.execute {
                                        val registration = runCatching {
                                            val session = bridge.beginInitialAccountBootstrap(activeIdentity)
                                            try {
                                                InitialAccountBootstrapCoordinator(
                                                    InitialAccountBootstrapHttpClient(configuredOrigin),
                                                ).register(session, phrase)
                                            } finally { session.close() }
                                        }
                                        val directory = if (registration.isSuccess) runCatching {
                                            DeviceDirectoryHttpClient(
                                                baseUrl = configuredOrigin,
                                                crypto = bridge,
                                                identity = activeIdentity,
                                            ).fetchOwnDirectory()
                                        } else null
                                        mainHandler.post {
                                            if (!isDestroyed) {
                                                isRegistering = false
                                                registration.fold(
                                                    onSuccess = {
                                                        registrationStatus = "Account and first device registered."
                                                        recoveryPhrase = null
                                                        recoveryPhraseBackedUp = false
                                                        directory?.fold(
                                                            onSuccess = { record ->
                                                                directoryEpoch = record.epoch.toString()
                                                                directoryStatus = "PASS — Gateway directory matches this local device."
                                                            },
                                                            onFailure = { failure ->
                                                                directoryStatus = "Registration succeeded; directory check failed: ${failure.message ?: failure.javaClass.simpleName}"
                                                            },
                                                        )
                                                    },
                                                    onFailure = { failure -> registrationStatus = "Registration failed: ${failure.message ?: failure.javaClass.simpleName}" },
                                                )
                                            }
                                        }
                                    }
                                } else {
                                    registrationStatus = "Generate and back up the recovery phrase, then enter the HTTPS gateway origin."
                                }
                            },
                            enabled = identityLoad != null && recoveryPhrase != null && recoveryPhraseBackedUp && gatewayOrigin.isNotBlank() && !isRegistering,
                        ) { Text(if (isRegistering) "Registering…" else "Register this device") }
                        Text("Registration: $registrationStatus")

                        Text("Gateway directory check", style = MaterialTheme.typography.titleMedium)
                        Text("Enter the HTTPS gateway origin. The app will fetch this device's directory record and compare its account ID, device ID, DSK and DDHK with the locally stored identity.")
                        OutlinedTextField(
                            value = gatewayOrigin,
                            onValueChange = {
                                gatewayOrigin = it
                                directoryStatus = "Not checked"
                                directoryEpoch = null
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("HTTPS gateway origin") },
                            placeholder = { Text("https://gateway.example") },
                            singleLine = true,
                            enabled = !isVerifying && !isRegistering,
                        )
                        if (directoryStatus == "Enter an HTTPS gateway origin.") {
                            Text(
                                directoryStatus,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                        Button(
                            onClick = {
                                if (gatewayOrigin.isBlank()) {
                                    directoryStatus = "Enter an HTTPS gateway origin."
                                    directoryEpoch = null
                                } else {
                                    val activeIdentity = identityLoad?.identity
                                    if (activeIdentity != null) {
                                        isVerifying = true
                                        directoryStatus = "Connecting to gatewayâ€¦"
                                        directoryEpoch = null
                                        val configuredOrigin = gatewayOrigin
                                        directoryExecutor.execute {
                                            val verification = runCatching {
                                                DeviceDirectoryHttpClient(
                                                    baseUrl = configuredOrigin,
                                                    crypto = bridge,
                                                    identity = activeIdentity,
                                                ).fetchOwnDirectory()
                                            }
                                            mainHandler.post {
                                                if (!isDestroyed) {
                                                    isVerifying = false
                                                    verification.fold(
                                                        onSuccess = { record ->
                                                            directoryEpoch = record.epoch.toString()
                                                            directoryStatus = "Directory matches the local account, device and public keys. Device is not marked revoked."
                                                        },
                                                        onFailure = { failure ->
                                                            directoryStatus = "Verification failed: ${failure.message ?: failure.javaClass.simpleName}"
                                                        },
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            enabled = identityLoad != null && !isVerifying,
                        ) {
                            Text(if (isVerifying) "Checkingâ€¦" else "Verify my device")
}
                        Text("Directory result: $directoryStatus")
                        directoryEpoch?.let { Text("Gateway-reported account epoch: $it") }
                        Text("Security boundary: HTTPS authenticates the configured gateway using Android's normal certificate validation. This directory response is canonical CBOR, not a gateway-signed statement; this check is not rollback-resistant and is not sufficient by itself to authorize enrollment.")
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        directoryExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun ByteArray.toHexPrefix(): String =
        take(4).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}