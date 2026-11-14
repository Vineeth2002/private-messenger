package org.sovereign.pm.messaging

import androidx.compose.foundation.layout.padding

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue

import androidx.compose.ui.unit.dp
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Public-only pairing data. The code is a transport container, not an authorization certificate. */
internal data class AlphaPairingRecord(
    val accountId: ByteArray,
    val deviceId: ByteArray,
    val epoch: Long,
    val dskPublicKey: ByteArray,
    val ddhkPublicKey: ByteArray,
    val rawSignedPrekey: ByteArray,
) {
    fun fingerprint(): String = AlphaPairingCode.fingerprint(this)
}

internal object AlphaPairingCode {
    private const val PREFIX = "PM-ALPHA1:"
    private val MAGIC = byteArrayOf(0x50, 0x4d, 0x41, 0x31) // PMA1
    private const val MAX_SPK_BYTES = 4096
    private const val FIXED_BYTES = 4 + 16 + 16 + 4 + 32 + 32 + 2

    fun encode(record: AlphaPairingRecord): String {
        validate(record)
        val raw = ByteBuffer.allocate(FIXED_BYTES + record.rawSignedPrekey.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(record.accountId)
            .put(record.deviceId)
            .putInt(record.epoch.toInt())
            .put(record.dskPublicKey)
            .put(record.ddhkPublicKey)
            .putShort(record.rawSignedPrekey.size.toShort())
            .put(record.rawSignedPrekey)
            .array()
        return PREFIX + Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun decode(code: String): AlphaPairingRecord {
        val normalized = code.trim()
        require(normalized.startsWith(PREFIX) && normalized.length <= 8192) {
            "Pairing code must start with $PREFIX and be no more than 8 KiB."
        }
        val raw = try {
            Base64.decode(normalized.removePrefix(PREFIX), Base64.URL_SAFE or Base64.NO_WRAP)
        } catch (failure: IllegalArgumentException) {
            throw IllegalArgumentException("Pairing code is not valid URL-safe Base64.", failure)
        }
        require(raw.size in (FIXED_BYTES + 1)..(FIXED_BYTES + MAX_SPK_BYTES)) {
            "Pairing code has an invalid length."
        }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4)
        input.get(magic)
        require(magic.contentEquals(MAGIC)) { "Pairing code version is unsupported." }
        val account = ByteArray(16)
        input.get(account)
        val device = ByteArray(16)
        input.get(device)
        val epoch = input.int.toLong() and 0xffff_ffffL
        val dsk = ByteArray(32)
        input.get(dsk)
        val ddhk = ByteArray(32)
        input.get(ddhk)
        val spkLength = input.short.toInt() and 0xffff
        require(spkLength in 1..MAX_SPK_BYTES && spkLength == input.remaining()) {
            "Pairing code signed-prekey length is invalid."
        }
        val spk = ByteArray(spkLength)
        input.get(spk)
        val record = AlphaPairingRecord(account, device, epoch, dsk, ddhk, spk)
        validate(record)
        return record
    }

    fun fingerprint(record: AlphaPairingRecord): String {
        validate(record)
        val domain = "PM-ALPHA-PAIR-FINGERPRINT-v1".toByteArray(Charsets.US_ASCII)
        val epochBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(record.epoch.toInt()).array()
        val material = domain + record.accountId + record.deviceId + epochBytes + record.dskPublicKey + record.ddhkPublicKey
        val digest = MessageDigest.getInstance("SHA-256").digest(material)
        return digest.joinToString("") { "%02X".format(it.toInt() and 0xff) }
            .chunked(8).joinToString(" ")
    }

    private fun validate(record: AlphaPairingRecord) {
        require(record.accountId.size == 16 && record.deviceId.size == 16)
        require(record.epoch in 1L..0xffff_ffffL)
        require(record.dskPublicKey.size == 32 && record.ddhkPublicKey.size == 32)
        require(record.rawSignedPrekey.isNotEmpty() && record.rawSignedPrekey.size <= MAX_SPK_BYTES)
    }
}

/** Stores only public pairing material in app-private preferences. No protocol private key is present. */
internal class AlphaPeerPinStore(context: Context, private val crypto: UniFfiCryptoBridge) {
    private val prefs: SharedPreferences = context.getSharedPreferences("pm-alpha-peer-pins-v1", Context.MODE_PRIVATE)

    fun preview(code: String): AlphaPairingRecord {
        val record = AlphaPairingCode.decode(code)
        val verified = crypto.verifySignedPrekeyForPairing(
            record.rawSignedPrekey,
            record.dskPublicKey,
            record.accountId,
            record.epoch,
            record.deviceId,
        )
        try {
            require(verified.contentEquals(record.rawSignedPrekey))
        } finally {
            verified.fill(0)
        }
        return record
    }

    fun pin(record: AlphaPairingRecord) {
        // A stable device ID cannot silently switch identity keys inside this alpha pin store.
        val existingCode = prefs.getString(key(record), null)
        if (existingCode != null) {
            val existing = AlphaPairingCode.decode(existingCode)
            require(existing.fingerprint() == record.fingerprint()) {
                "This device ID is already pinned to a different identity fingerprint. Do not overwrite it in-place."
            }
            require(existing.rawSignedPrekey.contentEquals(record.rawSignedPrekey)) {
                "This device's signed prekey changed. Do not silently replace an existing alpha pin; perform an explicit re-pairing procedure."
            }
        }
        // Re-verify at the persistence boundary; UI confirmation alone is not sufficient.
        val verified = crypto.verifySignedPrekeyForPairing(
            record.rawSignedPrekey,
            record.dskPublicKey,
            record.accountId,
            record.epoch,
            record.deviceId,
        )
        verified.fill(0)
        check(prefs.edit().putString(key(record), AlphaPairingCode.encode(record)).commit()) {
            "Could not persist the paired-device pin."
        }
    }

    fun requirePinned(accountId: ByteArray, deviceId: ByteArray): AlphaPairingRecord {
        require(accountId.size == 16 && deviceId.size == 16)
        val lookup = "peer_${hex(accountId)}_${hex(deviceId)}"
        val code = prefs.getString(lookup, null)
            ?: throw IOException("Peer device is not manually pinned. Import and compare its fingerprint first.")
        return try {
            preview(code).also { record ->
                require(record.accountId.contentEquals(accountId) && record.deviceId.contentEquals(deviceId)) {
                    "Stored pairing-code identity does not match its pin key."
                }
            }
        } catch (failure: Exception) {
            throw IOException("Stored alpha peer pin is invalid; refusing to trust it.", failure)
        }
    }

    fun listPinnedPeers(): List<AlphaPairingRecord> = prefs.all.entries.mapNotNull { entry ->
        val code = entry.value as? String ?: return@mapNotNull null
        if (!entry.key.startsWith("peer_")) return@mapNotNull null
        runCatching { AlphaPairingCode.decode(code) }.getOrNull()?.takeIf { key(it) == entry.key }
    }.distinctBy { hex(it.accountId) + "_" + hex(it.deviceId) }

    private fun key(record: AlphaPairingRecord) = "peer_${hex(record.accountId)}_${hex(record.deviceId)}"
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Outbound trust: a device must be pinned and its candidate SPK must be DSK-signed and identity-bound. */
internal class AlphaPeerPrekeyVerifier(
    private val pins: AlphaPeerPinStore,
    private val crypto: UniFfiCryptoBridge,
) : PeerPrekeyVerifier {
    override fun verify(candidate: PeerPrekeyCandidate): VerifiedPeerPrekeyMaterial {
        val pin = pins.requirePinned(candidate.accountId, candidate.deviceId)
        val raw = crypto.verifySignedPrekeyForPairing(
            pin.rawSignedPrekey, pin.dskPublicKey, pin.accountId, pin.epoch, pin.deviceId,
        )
        return VerifiedPeerPrekeyMaterial(
            accountId = pin.accountId.copyOf(),
            deviceId = pin.deviceId.copyOf(),
            epoch = pin.epoch,
            dskPublicKey = pin.dskPublicKey.copyOf(),
            ddhkPublicKey = pin.ddhkPublicKey.copyOf(),
            rawSignedPrekey = raw,
        )
    }
}

/** Inbound trust: manual fingerprint pinning replaces KT quorum only for this controlled alpha.
 * Native Rust still verifies Cert_dh, the Double Ratchet transition and AEAD authentication.
 */
internal class AlphaPinnedInboundPeerTrustVerifier(
    private val pins: AlphaPeerPinStore,
) : InboundPeerTrustVerifier {
    override fun verifyFirstContact(
        metadata: MessageEnvelopeMetadataV1,
        header: PrekeyHandshakeMetadataV1,
    ): VerifiedPeerIdentity {
        val pin = pins.requirePinned(header.senderAccountId, metadata.senderDeviceId)
        require(pin.accountId.contentEquals(header.senderAccountId))
        require(pin.deviceId.contentEquals(metadata.senderDeviceId))
        require(pin.epoch == header.senderAccountEpoch)
        require(pin.dskPublicKey.contentEquals(header.senderDskPublicKey))
        require(pin.ddhkPublicKey.contentEquals(header.senderDdhkPublicKey))
        // The native first-message decrypt path verifies this exact Cert_dh signature.
        return VerifiedPeerIdentity(
            accountId = pin.accountId.copyOf(),
            deviceId = pin.deviceId.copyOf(),
            epoch = pin.epoch,
            dskPublicKey = pin.dskPublicKey.copyOf(),
            ddhkPublicKey = pin.ddhkPublicKey.copyOf(),
            certDh = header.senderCertDh.copyOf(),
            trustState = TransparencyTrustState.DEGRADED,
        )
    }

    override fun verifyExistingSession(session: StoredMessagingSession): VerifiedPeerIdentity {
        val pin = pins.requirePinned(session.peerAccountId, session.peerDeviceId)
        require(pin.epoch == session.peerEpoch) { "Pinned peer epoch changed; create a new verified pairing." }
        return VerifiedPeerIdentity(
            accountId = pin.accountId.copyOf(),
            deviceId = pin.deviceId.copyOf(),
            epoch = pin.epoch,
            dskPublicKey = pin.dskPublicKey.copyOf(),
            ddhkPublicKey = pin.ddhkPublicKey.copyOf(),
            certDh = ByteArray(64),
            trustState = TransparencyTrustState.DEGRADED,
        )
    }
}

internal data class AlphaChatLine(
    val peerDeviceHex: String,
    val direction: StoredMessageDirection,
    val body: String,
    val createdAtMillis: Long,
)

internal data class AlphaMessagingRuntime(
    val engine: PersistentMessagingEngine,
    val client: DeviceMessageHttpClient,
    val epoch: Long,
)

internal fun createAlphaMessagingRuntime(
    context: Context,
    identityStore: org.sovereign.pm.security.IdentityStore,
    crypto: UniFfiCryptoBridge,
    identity: AccountIdentity,
    gatewayOrigin: String,
    database: LocalMessagingDatabase,
    pins: AlphaPeerPinStore,
): AlphaMessagingRuntime {
    require(gatewayOrigin.startsWith("https://", ignoreCase = true)) { "Enter the HTTPS gateway origin first." }
    val directory = DeviceDirectoryHttpClient(gatewayOrigin, crypto, identity).fetchOwnDirectory()
    require(!directory.revoked) { "This device is marked revoked in the gateway directory." }
    require(directory.accountId.contentEquals(identity.accountId) &&
        directory.deviceId.contentEquals(identity.deviceId) &&
        directory.dskPublicKey.contentEquals(identity.dskPublicKey) &&
        directory.ddhkPublicKey.contentEquals(identity.ddhkPublicKey)) {
        "Gateway directory identity does not match the locally stored account/device keys."
    }
    val epoch = directory.epoch.toLong()
    val engine = PersistentMessagingEngine(
        identityStore = identityStore,
        crypto = crypto,
        database = database,
        localIdentity = identity,
        localEpoch = epoch,
        peerPrekeyVerifier = AlphaPeerPrekeyVerifier(pins, crypto),
    )
    return AlphaMessagingRuntime(engine, DeviceMessageHttpClient(gatewayOrigin, crypto, identity), epoch)
}

/** Foreground-only closed alpha UI. The worker is active only while this composable is on screen. */
@androidx.compose.runtime.Composable
internal fun AlphaMessagingPanel(
    context: Context,
    identityStore: org.sovereign.pm.security.IdentityStore,
    crypto: UniFfiCryptoBridge,
    identity: AccountIdentity?,
    gatewayOrigin: String,
) {
    val database = androidx.compose.runtime.remember(context) { LocalMessagingDatabase(context) }
    val pins = androidx.compose.runtime.remember(context, crypto) { AlphaPeerPinStore(context, crypto) }
    val worker = androidx.compose.runtime.remember { java.util.concurrent.Executors.newSingleThreadScheduledExecutor() }
    val handler = androidx.compose.runtime.remember { android.os.Handler(android.os.Looper.getMainLooper()) }
    var localEpoch by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<Long?>(null) }
    var myPairingCode by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf("") }
    var importCode by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf("") }
    var previewRecord by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<AlphaPairingRecord?>(null) }
    var fingerprintConfirmed by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    var peers by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(emptyList<AlphaPairingRecord>()) }
    var selectedPeerKey by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf("") }
    var draft by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf("") }
    var lines by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(emptyList<AlphaChatLine>()) }
    var status by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf("Not initialized. Register this device and configure the HTTPS gateway first.") }
    var busy by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    var polling by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    var pollTask by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<java.util.concurrent.ScheduledFuture<*>?>(null) }

    androidx.compose.runtime.DisposableEffect(worker, database) {
        onDispose {
            pollTask?.cancel(true)
            worker.shutdownNow()
            database.close()
        }
    }

    fun refreshPeers() {
        peers = runCatching { pins.listPinnedPeers() }.getOrDefault(emptyList())
        if (selectedPeerKey.isBlank() && peers.isNotEmpty()) {
            selectedPeerKey = peers.first().deviceId.toPeerKey()
        }
    }

    fun runSync() {
        val activeIdentity = identity ?: throw IllegalStateException("Local identity is unavailable.")
        val runtime = createAlphaMessagingRuntime(context, identityStore, crypto, activeIdentity, gatewayOrigin, database, pins)
        try {
            val result = runtime.engine.processIncomingMessages(runtime.client, AlphaPinnedInboundPeerTrustVerifier(pins), 50)
            val updated = ArrayList<AlphaChatLine>()
            for (peer in pins.listPinnedPeers()) {
                val sessions = database.getSessionsForPeerDevice(peer.deviceId)
                for (session in sessions) {
                    for (message in runtime.engine.listMessages(session.sessionId, 200)) {
                        val plaintext = runtime.engine.openStoredMessageBody(session.sessionId, message.localMessageId)
                        try {
                            updated += AlphaChatLine(
                                peerDeviceHex = peer.deviceId.toPeerKey(),
                                direction = message.direction,
                                body = plaintext.toString(Charsets.UTF_8),
                                createdAtMillis = message.createdAtMillis,
                            )
                        } finally {
                            plaintext.fill(0)
                        }
                    }
                }
            }
            updated.sortBy { it.createdAtMillis }
            handler.post {
                localEpoch = runtime.epoch
                lines = updated
                status = "Sync complete: ${result.inserted} new, ${result.duplicates} duplicate, ${result.deferred} deferred. Alpha trust is manual fingerprint pinning, not production KT."
                busy = false
            }
        } finally {
            runtime.client.close()
        }
    }

    androidx.compose.foundation.layout.Column(
        modifier = androidx.compose.ui.Modifier.fillMaxWidth().padding(top = 20.dp),
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp),
    ) {
        androidx.compose.material3.Text("Controlled two-device messaging alpha", style = androidx.compose.material3.MaterialTheme.typography.titleLarge)
        androidx.compose.material3.Text("Manual fingerprint pairing replaces KT witness quorum only in this alpha. This is not production trust. Native signed-prekey, Cert_dh, ratchet and AEAD checks remain enabled.")
        androidx.compose.material3.Text("Gateway: ${if (gatewayOrigin.startsWith("https://", true)) gatewayOrigin else "HTTPS origin required"}")
        androidx.compose.material3.Button(
            onClick = {
                if (identity == null || gatewayOrigin.isBlank()) {
                    status = "Load the existing identity and enter the HTTPS gateway origin above."
                } else {
                    busy = true
                    status = "Checking local device directory and preparing signed-prekey…"
                    worker.execute {
                        val result = runCatching {
                            val runtime = createAlphaMessagingRuntime(context, identityStore, crypto, identity, gatewayOrigin, database, pins)
                            try {
                                val spk = runtime.engine.getOrCreateAlphaSignedPrekey(1L)
                                try {
                                    val record = AlphaPairingRecord(
                                        identity.accountId.copyOf(), identity.deviceId.copyOf(), runtime.epoch,
                                        identity.dskPublicKey.copyOf(), identity.ddhkPublicKey.copyOf(), spk.copyOf(),
                                    )
                                    Triple(AlphaPairingCode.encode(record), record.fingerprint(), runtime.epoch)
                                } finally { spk.fill(0) }
                            } finally { runtime.client.close() }
                        }
                        handler.post {
                            busy = false
                            result.fold(
                                onSuccess = { (code, fp, epoch) ->
                                    myPairingCode = code
                                    localEpoch = epoch
                                    status = "Local signed-prekey is ready. Share the pairing code and compare this fingerprint through a separate trusted channel: $fp"
                                },
                                onFailure = { status = "Pairing-code creation failed: ${it.message ?: it.javaClass.simpleName}" },
                            )
                        }
                    }
                }
            }, enabled = identity != null && gatewayOrigin.startsWith("https://", true) && !busy,
        ) { androidx.compose.material3.Text("Create my pairing code") }
        if (myPairingCode.isNotBlank()) {
            androidx.compose.material3.OutlinedTextField(
                value = myPairingCode, onValueChange = {}, readOnly = true,
                modifier = androidx.compose.ui.Modifier.fillMaxWidth(), label = { androidx.compose.material3.Text("My public pairing code") },
            )
            androidx.compose.material3.Button(onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Private Messenger alpha pairing", myPairingCode))
                status = "Pairing code copied. Send it over a separate channel."
            }) { androidx.compose.material3.Text("Copy my pairing code") }
        }

        androidx.compose.material3.Divider()
        androidx.compose.material3.Text("Import and pin the other device", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
        androidx.compose.material3.OutlinedTextField(
            value = importCode, onValueChange = { importCode = it; previewRecord = null; fingerprintConfirmed = false },
            modifier = androidx.compose.ui.Modifier.fillMaxWidth(), label = { androidx.compose.material3.Text("Paste the other device's pairing code") },
        )
        androidx.compose.material3.Button(onClick = {
            val parsed = runCatching { pins.preview(importCode) }
            parsed.fold(
                onSuccess = { previewRecord = it; fingerprintConfirmed = false; status = "Signed-prekey signature and identity binding passed. Compare the fingerprint below with the other device through a separate trusted channel." },
                onFailure = { previewRecord = null; status = "Pairing code rejected: ${it.message ?: it.javaClass.simpleName}" },
            )
        }, enabled = importCode.isNotBlank() && !busy) { androidx.compose.material3.Text("Validate pairing code") }
        previewRecord?.let { record ->
            androidx.compose.material3.Text("Peer fingerprint (compare out of band):")
            androidx.compose.material3.Text(record.fingerprint(), style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
            androidx.compose.material3.Text("Account: ${record.accountId.toShortHex()}   Device: ${record.deviceId.toShortHex()}   Epoch: ${record.epoch}")
            androidx.compose.foundation.layout.Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                androidx.compose.material3.Checkbox(checked = fingerprintConfirmed, onCheckedChange = { fingerprintConfirmed = it })
                androidx.compose.material3.Text("I compared the full fingerprint with the other device over a separate trusted channel")
            }
            androidx.compose.material3.Button(onClick = {
                runCatching { pins.pin(record) }.fold(
                    onSuccess = {
                        refreshPeers()
                        selectedPeerKey = record.deviceId.toPeerKey()
                        importCode = ""
                        previewRecord = null
                        fingerprintConfirmed = false
                        status = "Peer pinned locally. This is manual alpha trust, not a KT-verified production identity."
                    },
                    onFailure = { status = "Could not pin peer: ${it.message ?: it.javaClass.simpleName}" },
                )
            }, enabled = fingerprintConfirmed && !busy) { androidx.compose.material3.Text("Trust and pin this device") }
        }

        androidx.compose.material3.Divider()
        androidx.compose.material3.Text("Paired devices", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
        androidx.compose.material3.Button(onClick = { refreshPeers() }) { androidx.compose.material3.Text("Refresh paired devices") }
        peers.forEach { peer ->
            val key = peer.deviceId.toPeerKey()
            val displayKey = peer.deviceId.toShortHex()
            androidx.compose.material3.Button(onClick = { selectedPeerKey = key }) {
                androidx.compose.material3.Text((if (selectedPeerKey == key) "Selected: " else "Select: ") + displayKey + "  (epoch ${peer.epoch})")
            }
        }

        androidx.compose.material3.OutlinedTextField(
            value = draft, onValueChange = { draft = it }, modifier = androidx.compose.ui.Modifier.fillMaxWidth(),
            label = { androidx.compose.material3.Text("Message") },
        )
        androidx.compose.material3.Button(onClick = {
            val target = peers.firstOrNull { it.deviceId.toPeerKey() == selectedPeerKey }
            if (identity == null || target == null || draft.isBlank()) {
                status = "Select a pinned peer and enter a non-empty message."
            } else {
                val textToSend = draft
                busy = true
                worker.execute {
                    val result = runCatching {
                        val runtime = createAlphaMessagingRuntime(context, identityStore, crypto, identity, gatewayOrigin, database, pins)
                        try {
                            val session = runtime.engine.getOrCreateAlphaSession(PeerPrekeyCandidate(target.accountId, target.deviceId))
                            runtime.engine.encryptAndPersistOutgoing(session.sessionId, textToSend.toByteArray(Charsets.UTF_8))
                            runtime.engine.submitNextReadyOutbox(runtime.client)
                            runSync()
                        } finally { runtime.client.close() }
                    }
                    handler.post {
                        busy = false
                        result.fold(
                            onSuccess = { draft = ""; status = "Encrypted message submitted. Sync the receiving device to retrieve it." },
                            onFailure = { status = "Send failed or delivery is ambiguous: ${it.message ?: it.javaClass.simpleName}. Check outbox state before retrying." },
                        )
                    }
                }
            }
        }, enabled = identity != null && selectedPeerKey.isNotBlank() && draft.isNotBlank() && !busy) {
            androidx.compose.material3.Text("Encrypt and send")
        }

        androidx.compose.material3.Button(onClick = {
            if (identity == null || !gatewayOrigin.startsWith("https://", true)) {
                status = "Identity and HTTPS gateway origin are required."
            } else {
                busy = true
                worker.execute {
                    val result = runCatching { runSync() }
                    handler.post {
                        busy = false
                        result.onFailure { status = "Sync failed: ${it.message ?: it.javaClass.simpleName}" }
                    }
                }
            }
        }, enabled = identity != null && gatewayOrigin.startsWith("https://", true) && !busy) {
            androidx.compose.material3.Text(if (busy) "Working…" else "Sync now")
        }
        androidx.compose.material3.Button(onClick = {
            if (!polling && identity != null && gatewayOrigin.startsWith("https://", true)) {
                polling = true
                pollTask = worker.scheduleWithFixedDelay({ runCatching { runSync() }.onFailure { failure -> handler.post { status = "Foreground sync error: ${failure.message ?: failure.javaClass.simpleName}" } } }, 0, 3, java.util.concurrent.TimeUnit.SECONDS)
                status = "Foreground polling active (3-second interval). It stops when this screen closes or you press Stop."
            } else {
                pollTask?.cancel(true)
                pollTask = null
                polling = false
                status = "Foreground polling stopped."
            }
        }, enabled = identity != null && gatewayOrigin.startsWith("https://", true)) {
            androidx.compose.material3.Text(if (polling) "Stop foreground polling" else "Start foreground polling")
        }

        androidx.compose.material3.Text("Conversation", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
        lines.filter { selectedPeerKey.isBlank() || it.peerDeviceHex == selectedPeerKey }.forEach { line ->
            androidx.compose.material3.Text("${line.direction}: ${line.body}")
        }
        androidx.compose.material3.Text("Status: $status")
    }
}

private fun ByteArray.toShortHex(): String = take(6).joinToString("") { "%02x".format(it.toInt() and 0xff) }
private fun ByteArray.toPeerKey(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }