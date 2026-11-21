package org.sovereign.pm

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.sovereign.pm.bootstrap.InitialAccountBootstrapCoordinator
import org.sovereign.pm.bootstrap.InitialAccountBootstrapHttpClient
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import org.sovereign.pm.messaging.AlphaMessengerWorkspace
import org.sovereign.pm.messaging.DeviceDirectoryHttpClient
import org.sovereign.pm.security.AndroidKeystorePlatformKek
import org.sovereign.pm.security.IdentityStore
import org.sovereign.pm.ui.theme.SovereignTheme
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private val directoryExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private var debugMirrorEnabled by mutableStateOf(false)
    private var activityInForeground by mutableStateOf(false)
    private val debugMirrorTimeout = Runnable { disableDebugScreenMirroring() }
    private val debugMirrorWindowMs = 120_000L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        disableDebugScreenMirroring()

        val bridge = UniFfiCryptoBridge()
        val canonicalResult = runCatching {
            bridge.decodeStrictCanonical(byteArrayOf(0x18, 0x18))
        }
        val identityStore = IdentityStore(
            applicationContext,
            bridge,
            AndroidKeystorePlatformKek(applicationContext),
        )
        val identityResult = runCatching { identityStore.loadOrCreate() }
        val identityLoad = identityResult.getOrNull()

        setContent {
            var gatewayOrigin by remember {
                mutableStateOf(
                    applicationContext.getSharedPreferences("pm-ui-settings-v1", MODE_PRIVATE)
                        .getString("gateway_origin", "").orEmpty(),
                )
            }
            var isVerifying by remember { mutableStateOf(false) }
            var directoryStatus by remember { mutableStateOf("Not checked") }
            var directoryEpoch by remember { mutableStateOf<String?>(null) }
            var recoveryPhrase by remember { mutableStateOf<String?>(null) }
            var recoveryPhraseBackedUp by remember { mutableStateOf(false) }
            var isRegistering by remember { mutableStateOf(false) }
            var registrationStatus by remember { mutableStateOf("Not registered") }
            var showGatewaySettings by remember { mutableStateOf(false) }

            SovereignTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    if (!showGatewaySettings) {
                        AlphaMessengerWorkspace(
                            context = applicationContext,
                            identityStore = identityStore,
                            crypto = bridge,
                            identity = identityLoad?.identity,
                            gatewayOrigin = gatewayOrigin,
                            onOpenSettings = { showGatewaySettings = true },
                            isActivityForeground = activityInForeground,
                            hidePrivateContent = debugMirrorEnabled,
                        )
                    } else {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .verticalScroll(rememberScrollState())
                                .padding(horizontal = 18.dp, vertical = 16.dp),
                            verticalArrangement = Arrangement.spacedBy(16.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text("Server & Gateway", style = MaterialTheme.typography.headlineMedium)
                                    Text(
                                        "Device, identity and network setup",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                TextButton(onClick = { showGatewaySettings = false }) { Text("Done") }
                            }

                            if (isDebuggableBuild()) {
                                Card(modifier = Modifier.fillMaxWidth()) {
                                    Column(modifier = Modifier.padding(12.dp)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Checkbox(
                                                checked = debugMirrorEnabled,
                                                enabled = recoveryPhrase == null && !isRegistering,
                                                onCheckedChange = { requested ->
                                                    if (requested && recoveryPhrase == null && !isRegistering) {
                                                        enableDebugScreenMirroring()
                                                    } else {
                                                        disableDebugScreenMirroring()
                                                    }
                                                },
                                            )
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text("Temporary screen mirroring", fontWeight = FontWeight.Medium)
                                                Text("Debug builds only", style = MaterialTheme.typography.bodySmall)
                                            }
                                        }
                                        if (debugMirrorEnabled) {
                                            Text(
                                                "MIRRORING ENABLED - sensitive data hidden. Automatically locks after 2 minutes or when the app leaves the foreground.",
                                                color = MaterialTheme.colorScheme.error,
                                                style = MaterialTheme.typography.bodySmall,
                                                modifier = Modifier.padding(horizontal = 12.dp),
                                            )
                                        }
                                    }
                                }
                            }

                            SectionHeading(
                                title = "Device security",
                                subtitle = "Cryptographic identity and local storage health.",
                            )

                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    StatusRow(
                                        "Canonical CBOR",
                                        if (canonicalResult.isSuccess) "PASS" else "FAIL",
                                        canonicalResult.isSuccess,
                                    )
                                    HorizontalDivider()
                                    if (identityLoad == null) {
                                        StatusRow("Identity storage", "FAILED", false)
                                        Text(
                                            identityResult.exceptionOrNull()?.message ?: "Identity initialization failed",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error,
                                        )
                                    } else {
                                        StatusRow("Identity storage", identityLoad.origin.name, true)
                                        StatusRow("At-rest encryption", "PASS", true)
                                        StatusRow("Keystore backing", identityLoad.kekCapabilities.backing.toString())
                                        StatusRow("PPAL", identityLoad.kekCapabilities.achievedPpal.toString())
                                        HorizontalDivider()
                                        Text(
                                            "LOCAL IDENTIFIERS",
                                            style = MaterialTheme.typography.labelMedium,
                                            color = MaterialTheme.colorScheme.primary,
                                            fontWeight = FontWeight.Bold,
                                        )
                                        if (debugMirrorEnabled) {
                                            Text(
                                                "Account and device identifiers are hidden during screen mirroring.",
                                                style = MaterialTheme.typography.bodySmall,
                                            )
                                        } else {
                                            StatusRow("Account ID", identityLoad.identity.accountId.toHexPrefix())
                                            StatusRow("Device ID", identityLoad.identity.deviceId.toHexPrefix())
                                        }
                                    }
                                }
                            }

                            SectionHeading(
                                title = "Account setup",
                                subtitle = "Register this existing identity as your first device.",
                            )

                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Text(
                                        "This process registers the existing local identity. It does not create a replacement identity.",
                                        style = MaterialTheme.typography.bodyMedium,
                                    )

                                    Button(
                                        onClick = {
                                            disableDebugScreenMirroring()
                                            recoveryPhrase = bridge.generateRecoveryMnemonic()
                                            recoveryPhraseBackedUp = false
                                            registrationStatus = "Recovery phrase generated. Back it up before registration."
                                        },
                                        enabled = identityLoad != null && !isRegistering,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text("Generate recovery phrase")
                                    }

                                    recoveryPhrase?.let { phrase ->
                                        Card(
                                            colors = CardDefaults.cardColors(
                                                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                            ),
                                        ) {
                                            Column(
                                                modifier = Modifier.padding(14.dp),
                                                verticalArrangement = Arrangement.spacedBy(10.dp),
                                            ) {
                                                Text(
                                                    "Your recovery phrase",
                                                    fontWeight = FontWeight.Bold,
                                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                                )
                                                Text(
                                                    phrase,
                                                    style = MaterialTheme.typography.bodyLarge,
                                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                                )
                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                    Checkbox(
                                                        checked = recoveryPhraseBackedUp,
                                                        onCheckedChange = { recoveryPhraseBackedUp = it },
                                                    )
                                                    Text(
                                                        "I have securely backed up this phrase",
                                                        style = MaterialTheme.typography.bodySmall,
                                                    )
                                                }
                                            }
                                        }
                                    }

                                    OutlinedTextField(
                                        value = gatewayOrigin,
                                        onValueChange = {
                                            gatewayOrigin = it
                                            applicationContext.getSharedPreferences("pm-ui-settings-v1", MODE_PRIVATE)
                                                .edit().putString("gateway_origin", it).apply()
                                            directoryStatus = "Not checked"
                                            directoryEpoch = null
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        label = { Text("HTTPS gateway origin") },
                                        placeholder = { Text("https://gateway.example") },
                                        singleLine = true,
                                        enabled = !isVerifying && !isRegistering,
                                    )

                                    Button(
                                        onClick = {
                                            val activeIdentity = identityLoad?.identity
                                            val phrase = recoveryPhrase
                                            if (
                                                activeIdentity != null &&
                                                phrase != null &&
                                                recoveryPhraseBackedUp &&
                                                gatewayOrigin.isNotBlank()
                                            ) {
                                                disableDebugScreenMirroring()
                                                isRegistering = true
                                                registrationStatus = "Registering first device..."
                                                val configuredOrigin = gatewayOrigin
                                                directoryExecutor.execute {
                                                    val registration = runCatching {
                                                        val session = bridge.beginInitialAccountBootstrap(activeIdentity)
                                                        try {
                                                            InitialAccountBootstrapCoordinator(
                                                                InitialAccountBootstrapHttpClient(configuredOrigin),
                                                            ).register(session, phrase)
                                                        } finally {
                                                            session.close()
                                                        }
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
                                                                            directoryStatus = "PASS - Gateway directory matches this local device."
                                                                        },
                                                                        onFailure = { failure ->
                                                                            directoryStatus = "Registration succeeded; directory check failed: ${failure.message ?: failure.javaClass.simpleName}"
                                                                        },
                                                                    )
                                                                },
                                                                onFailure = { failure ->
                                                                    registrationStatus = "Registration failed: ${failure.message ?: failure.javaClass.simpleName}"
                                                                },
                                                            )
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        enabled = identityLoad != null &&
                                            recoveryPhrase != null &&
                                            recoveryPhraseBackedUp &&
                                            gatewayOrigin.isNotBlank() &&
                                            !isRegistering,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(if (isRegistering) "Registering..." else "Register this device")
                                    }

                                    Text(
                                        registrationStatus,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (registrationStatus.startsWith("Registration failed")) {
                                            MaterialTheme.colorScheme.error
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        },
                                    )
                                }
                            }

                            SectionHeading(
                                title = "Gateway connection",
                                subtitle = "Verify that the gateway recognizes this local device.",
                            )

                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    OutlinedTextField(
                                        value = gatewayOrigin,
                                        onValueChange = {
                                            gatewayOrigin = it
                                            applicationContext.getSharedPreferences("pm-ui-settings-v1", MODE_PRIVATE)
                                                .edit().putString("gateway_origin", it).apply()
                                            directoryStatus = "Not checked"
                                            directoryEpoch = null
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        label = { Text("HTTPS gateway origin") },
                                        placeholder = { Text("https://gateway.example") },
                                        singleLine = true,
                                        enabled = !isVerifying && !isRegistering,
                                    )

                                    Button(
                                        onClick = {
                                            if (gatewayOrigin.isBlank()) {
                                                directoryStatus = "Enter an HTTPS gateway origin."
                                                directoryEpoch = null
                                            } else {
                                                val activeIdentity = identityLoad?.identity
                                                if (activeIdentity != null) {
                                                    isVerifying = true
                                                    directoryStatus = "Connecting to gateway..."
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
                                                                        directoryStatus = "Directory matches the local account, device and public keys."
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
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(if (isVerifying) "Checking..." else "Verify my device")
                                    }

                                    Text(
                                        directoryStatus,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (
                                            directoryStatus.startsWith("Verification failed") ||
                                            directoryStatus == "Enter an HTTPS gateway origin."
                                        ) {
                                            MaterialTheme.colorScheme.error
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        },
                                    )

                                    directoryEpoch?.let { StatusRow("Gateway account epoch", it) }
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }
            }
        }
    }

    private fun isDebuggableBuild(): Boolean =
        (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

    private fun enableDebugScreenMirroring() {
        if (!isDebuggableBuild()) {
            disableDebugScreenMirroring()
            return
        }
        debugMirrorEnabled = true
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        mainHandler.removeCallbacks(debugMirrorTimeout)
        mainHandler.postDelayed(debugMirrorTimeout, debugMirrorWindowMs)
    }

    private fun disableDebugScreenMirroring() {
        mainHandler.removeCallbacks(debugMirrorTimeout)
        debugMirrorEnabled = false
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun onResume() {
        super.onResume()
        activityInForeground = true
    }

    override fun onPause() {
        activityInForeground = false
        disableDebugScreenMirroring()
        super.onPause()
    }

    override fun onDestroy() {
        disableDebugScreenMirroring()
        directoryExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun ByteArray.toHexPrefix(): String =
        take(4).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

@Composable
private fun SectionHeading(
    title: String,
    subtitle: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun StatusRow(
    label: String,
    value: String,
    positive: Boolean? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = when (positive) {
                true -> MaterialTheme.colorScheme.primary
                false -> MaterialTheme.colorScheme.error
                null -> MaterialTheme.colorScheme.onSurface
            },
        )
    }
}
