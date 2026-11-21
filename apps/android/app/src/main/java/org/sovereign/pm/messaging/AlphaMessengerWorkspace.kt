package org.sovereign.pm.messaging

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.ContactsContract
import android.speech.tts.TextToSpeech
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import java.security.MessageDigest
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.sovereign.pm.crypto.AccountIdentity
import org.sovereign.pm.crypto.UniFfiCryptoBridge
import org.sovereign.pm.security.IdentityStore
import org.sovereign.pm.ui.components.DisclosureCard
import org.sovereign.pm.ui.components.FingerprintBlock
import org.sovereign.pm.ui.components.GeometricIdenticon
import org.sovereign.pm.ui.components.SovereignBackIcon
import org.sovereign.pm.ui.components.SovereignSettingsIcon
import org.sovereign.pm.ui.state.OutboxMessageStatus
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit


@Composable
internal fun AlphaMessengerWorkspace(
    context: Context,
    identityStore: IdentityStore,
    crypto: UniFfiCryptoBridge,
    identity: AccountIdentity?,
    gatewayOrigin: String,
    onOpenSettings: () -> Unit,
    isActivityForeground: Boolean,
    hidePrivateContent: Boolean = false,
) {
    val appContext = context.applicationContext
    val database = remember(appContext) { LocalMessagingDatabase(appContext) }
    val pins = remember(appContext, crypto) { AlphaPeerPinStore(appContext, crypto) }
    val worker: ScheduledExecutorService = remember { Executors.newSingleThreadScheduledExecutor() }
    val handler = remember { Handler(Looper.getMainLooper()) }
    val aliases = remember(appContext) {
        appContext.getSharedPreferences("pm-local-contact-aliases-v1", Context.MODE_PRIVATE)
    }
    val lensPrefs = remember(appContext) {
        appContext.getSharedPreferences("pm-language-lens-v1", Context.MODE_PRIVATE)
    }
    val simPrefs = remember(appContext) {
        appContext.getSharedPreferences("pm-sim-binding-v1", Context.MODE_PRIVATE)
    }

    var simRefreshTick by remember { mutableStateOf(0) }
    var simStatus by remember(simRefreshTick) {
        mutableStateOf(evaluateSimBindingState(appContext, simPrefs))
    }
    var detectedClipboardInvite by remember { mutableStateOf<String?>(null) }

    var phonebookContacts by remember { mutableStateOf<List<PhonebookContact>>(emptyList()) }
    var contactsPermissionGranted by remember {
        mutableStateOf(
            androidx.core.content.ContextCompat.checkSelfPermission(
                appContext,
                Manifest.permission.READ_CONTACTS,
            ) == PackageManager.PERMISSION_GRANTED,
        )
    }

    var discoveredMatches by remember { mutableStateOf<Map<String, DiscoveredPeerMatch>>(emptyMap()) }
    var isDiscoveringContacts by remember { mutableStateOf(false) }

    fun syncPhoneAndEmailContacts() {
        isDiscoveringContacts = true
        worker.execute {
            val loaded = loadDevicePhoneAndEmailContacts(appContext)
            val currentPhone = simPrefs.getString("registered_phone", "").orEmpty()
            val matches = discoverMatchingContacts(
                context = appContext,
                gatewayOrigin = gatewayOrigin,
                contacts = loaded,
                selfPhoneNumber = currentPhone,
            )
            handler.post {
                phonebookContacts = loaded
                discoveredMatches = matches
                isDiscoveringContacts = false
            }
        }
    }

    var statusMessage by remember { mutableStateOf<String?>(null) }
    val contactsPermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        contactsPermissionGranted = granted
        if (granted) {
            syncPhoneAndEmailContacts()
        } else {
            statusMessage = "Contacts permission denied. You can still type any mobile number or email below."
        }
    }

    val phonePermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) {
        simRefreshTick += 1
    }

    LaunchedEffect(contactsPermissionGranted) {
        if (contactsPermissionGranted && phonebookContacts.isEmpty()) {
            syncPhoneAndEmailContacts()
        }
    }

    LaunchedEffect(isActivityForeground) {
        if (isActivityForeground) {
            simRefreshTick += 1
        }
    }

    var route by remember { mutableStateOf(MessengerRoute.CHATS) }
    var peers by remember { mutableStateOf(emptyList<MessengerPeer>()) }
    var selectedPeerKey by remember { mutableStateOf<String?>(null) }
    var draft by remember { mutableStateOf("") }
    var importCode by remember { mutableStateOf("") }
    var localNickname by remember { mutableStateOf("") }
    var previewRecord by remember { mutableStateOf<AlphaPairingRecord?>(null) }
    var fingerprintConfirmed by remember { mutableStateOf(false) }
    var myPairingCode by remember { mutableStateOf("") }
    var myFingerprint by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var syncSubtitle by remember { mutableStateOf("Private chat") }
    var speakingMessageId by remember { mutableStateOf<String?>(null) }
    val focusManager = LocalFocusManager.current

    // Per-peer preferred reading language + in-memory translation cache (never alters stored ciphertext)
    var peerLanguages by remember { mutableStateOf<Map<String, LensLanguage>>(emptyMap()) }
    val lensCache = remember { mutableStateMapOf<String, LensRenderState>() }
    val summaryCache = remember { mutableStateMapOf<String, AttachmentSummaryState>() }

    fun summarizeAttachmentOnDemand(msg: MessengerMessage, targetLang: LensLanguage) {
        val key = "${msg.localMessageId}:${targetLang.code}"
        val existing = summaryCache[key]
        if (existing != null && (existing.loading || existing.summaryText != null)) return
        summaryCache[key] = AttachmentSummaryState(loading = true)
        worker.execute {
            val result = runCatching { buildConciseDocumentOrPhotoSummary(msg.body, targetLang) }
            handler.post {
                result.fold(
                    onSuccess = { summary ->
                        summaryCache[key] = AttachmentSummaryState(
                            loading = false,
                            summaryText = summary,
                            detectedSourceText = msg.body,
                        )
                    },
                    onFailure = { err ->
                        summaryCache[key] = AttachmentSummaryState(
                            loading = false,
                            error = err.message ?: "Unable to summarize",
                        )
                    },
                )
            }
        }
    }

    // On-device Android TextToSpeech engine for listening to original or translated messages
    var ttsReady by remember { mutableStateOf(false) }
    val ttsEngine = remember(appContext) {
        TextToSpeech(appContext) { status ->
            if (status == TextToSpeech.SUCCESS) {
                ttsReady = true
            }
        }
    }

    DisposableEffect(ttsEngine) {
        onDispose {
            runCatching {
                ttsEngine.stop()
                ttsEngine.shutdown()
            }
        }
    }

    val selectedPeer = peers.firstOrNull { it.stableKey == selectedPeerKey }
    val gatewayConfigured = isLocalOrHttpsGatewayOrigin(gatewayOrigin)

    fun getPeerLanguage(peerKey: String): LensLanguage {
        peerLanguages[peerKey]?.let { return it }
        val saved = lensPrefs.getString("lang_$peerKey", LensLanguage.OFF.code)
        return LensLanguage.entries.firstOrNull { it.code == saved } ?: LensLanguage.OFF
    }

    fun setPeerLanguage(peerKey: String, lang: LensLanguage) {
        peerLanguages = peerLanguages + (peerKey to lang)
        lensPrefs.edit().putString("lang_$peerKey", lang.code).apply()
    }

    fun translateMessageOnDemand(message: MessengerMessage, targetLang: LensLanguage) {
        if (targetLang == LensLanguage.OFF) return
        val cacheKey = "${message.localMessageId}:${targetLang.code}"
        val existing = lensCache[cacheKey]
        if (existing != null && (existing.loading || existing.translatedText != null)) return

        lensCache[cacheKey] = LensRenderState(loading = true, targetLang = targetLang)
        worker.execute {
            val result = runCatching { performPostDecryptionTranslation(message.body, targetLang.code) }
            handler.post {
                result.fold(
                    onSuccess = { translated ->
                        lensCache[cacheKey] = LensRenderState(
                            loading = false,
                            translatedText = translated,
                            targetLang = targetLang,
                        )
                    },
                    onFailure = {
                        lensCache[cacheKey] = LensRenderState(
                            loading = false,
                            targetLang = targetLang,
                            error = "Translation unavailable offline",
                        )
                    },
                )
            }
        }
    }

    fun speakText(messageId: String, text: String, lang: LensLanguage) {
        val tts = ttsEngine
        if (!ttsReady) {
            statusMessage = "Voice reader is still initializing on this phone."
            return
        }
        if (speakingMessageId == messageId) {
            tts.stop()
            speakingMessageId = null
            return
        }
        val locale = Locale.forLanguageTag(lang.localeTag)
        val availability = tts.isLanguageAvailable(locale)
        if (availability >= TextToSpeech.LANG_AVAILABLE) {
            tts.language = locale
        } else {
            tts.language = Locale.forLanguageTag("en-IN")
        }
        speakingMessageId = messageId
        tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, messageId)
    }

    fun loadLocalPeers(): List<MessengerPeer> {
        if (identity == null) return emptyList()
        return pins.listPinnedPeers().map { peer ->
            val messages = ArrayList<MessengerMessage>()
            val sessions = database.getSessionsForPeerDevice(peer.deviceId)
                .filter { it.peerAccountId.contentEquals(peer.accountId) }
            for (session in sessions) {
                val engine = PersistentMessagingEngine(
                    identityStore = identityStore,
                    crypto = crypto,
                    database = database,
                    localIdentity = identity,
                    localEpoch = session.localEpoch,
                    peerPrekeyVerifier = AlphaPeerPrekeyVerifier(pins, crypto),
                )
                for (stored in engine.listMessages(session.sessionId, 200)) {
                    val plaintext = engine.openStoredMessageBody(session.sessionId, stored.localMessageId)
                    try {
                        val outbox = if (stored.direction == StoredMessageDirection.OUTBOUND) {
                            database.getOutboxStatus(stored.localMessageId)?.state?.toUiStatus()
                        } else null
                        messages += MessengerMessage(
                            localMessageId = stored.localMessageId,
                            direction = stored.direction,
                            body = plaintext.toString(Charsets.UTF_8),
                            createdAtMillis = stored.createdAtMillis,
                            outboxStatus = outbox,
                        )
                    } finally {
                        plaintext.fill(0)
                    }
                }
            }
            val aliasKey = peer.aliasPreferenceKey()
            val nickname = aliases.getString(aliasKey, null)
                ?.takeIf { it.isNotBlank() }
                ?: "Contact ${peer.deviceId.take(2).joinToString("") { "%02X".format(it.toInt() and 0xff) }}"
            MessengerPeer(
                record = peer,
                nickname = nickname,
                messages = messages.sortedBy { it.createdAtMillis },
            )
        }.sortedByDescending { it.latestMessage?.createdAtMillis ?: 0L }
    }

    fun refreshLocalPeers(selectKey: String? = selectedPeerKey) {
        worker.execute {
            val result = runCatching { loadLocalPeers() }
            handler.post {
                result.fold(
                    onSuccess = { loaded ->
                        peers = loaded
                        if (selectKey != null && loaded.any { it.stableKey == selectKey }) {
                            selectedPeerKey = selectKey
                        } else if (selectedPeerKey != null && loaded.none { it.stableKey == selectedPeerKey }) {
                            selectedPeerKey = null
                            route = MessengerRoute.CHATS
                        }
                    },
                    onFailure = { failure ->
                        statusMessage = "Unable to load chats: ${failure.message ?: failure.javaClass.simpleName}"
                    },
                )
            }
        }
    }

    fun synchronizeForeground() {
        val activeIdentity = identity ?: return
        if (!gatewayConfigured) return
        val selectedKeyAtStart = selectedPeerKey
        val configuredOrigin = gatewayOrigin
        runCatching {
            val runtime = createAlphaMessagingRuntime(
                context = appContext,
                identityStore = identityStore,
                crypto = crypto,
                identity = activeIdentity,
                gatewayOrigin = configuredOrigin,
                database = database,
                pins = pins,
            )
            try {
                runtime.engine.processIncomingMessages(
                    runtime.client,
                    AlphaPinnedInboundPeerTrustVerifier(pins),
                    50,
                )
            } finally {
                runtime.client.close()
            }
            loadLocalPeers()
        }.fold(
            onSuccess = { loaded ->
                handler.post {
                    peers = loaded
                    val time = SimpleDateFormat("h:mm a", Locale.getDefault()).format(Date())
                    syncSubtitle = "Encrypted · Updated $time"
                    if (selectedKeyAtStart != null && loaded.any { it.stableKey == selectedKeyAtStart }) {
                        selectedPeerKey = selectedKeyAtStart
                    }
                }
            },
            onFailure = {
                handler.post {
                    syncSubtitle = "Waiting for connection…"
                }
            },
        )
    }

    LaunchedEffect(identity, route) {
        if (identity != null && route == MessengerRoute.CHATS) {
            refreshLocalPeers()
        }
    }

    DisposableEffect(worker, database) {
        onDispose {
            worker.shutdownNow()
            database.close()
        }
    }

    fun createOwnPairingCode() {
        val activeIdentity = identity
        if (activeIdentity == null || !gatewayConfigured) {
            statusMessage = "Connect your server in Settings first."
            return
        }
        busy = true
        statusMessage = null
        val configuredOrigin = gatewayOrigin
        worker.execute {
            val result = runCatching {
                val runtime = createAlphaMessagingRuntime(
                    context = appContext,
                    identityStore = identityStore,
                    crypto = crypto,
                    identity = activeIdentity,
                    gatewayOrigin = configuredOrigin,
                    database = database,
                    pins = pins,
                )
                try {
                    val signedPrekey = runtime.engine.getOrCreateAlphaSignedPrekey(1L)
                    try {
                        val record = AlphaPairingRecord(
                            accountId = activeIdentity.accountId.copyOf(),
                            deviceId = activeIdentity.deviceId.copyOf(),
                            epoch = runtime.epoch,
                            dskPublicKey = activeIdentity.dskPublicKey.copyOf(),
                            ddhkPublicKey = activeIdentity.ddhkPublicKey.copyOf(),
                            rawSignedPrekey = signedPrekey.copyOf(),
                        )
                        Triple(AlphaPairingCode.encode(record), record.fingerprint(), runtime.epoch)
                    } finally {
                        signedPrekey.fill(0)
                    }
                } finally {
                    runtime.client.close()
                }
            }
            handler.post {
                busy = false
                result.fold(
                    onSuccess = { (code, fingerprint, _) ->
                        myPairingCode = code
                        myFingerprint = fingerprint
                        statusMessage = "Your invite code is ready to share."
                    },
                    onFailure = { failure ->
                        statusMessage = "Could not create invite code: ${failure.message ?: failure.javaClass.simpleName}"
                    },
                )
            }
        }
    }

    fun pinImportedPeer(record: AlphaPairingRecord) {
        val nickname = localNickname.trim().ifEmpty {
            "Contact ${record.deviceId.take(2).joinToString("") { "%02X".format(it.toInt() and 0xff) }}"
        }
        busy = true
        worker.execute {
            val result = runCatching {
                pins.pin(record)
                aliases.edit().putString(record.aliasPreferenceKey(), nickname).commit().also {
                    check(it) { "Could not save contact name." }
                }
            }
            handler.post {
                busy = false
                result.fold(
                    onSuccess = {
                        val key = record.stableKey()
                        importCode = ""
                        localNickname = ""
                        previewRecord = null
                        fingerprintConfirmed = false
                        statusMessage = null
                        selectedPeerKey = key
                        route = MessengerRoute.CONVERSATION
                        refreshLocalPeers(key)
                    },
                    onFailure = { failure ->
                        statusMessage = "Could not save contact: ${failure.message ?: failure.javaClass.simpleName}"
                    },
                )
            }
        }
    }

    fun validateAndConnectCode(rawCode: String = importCode, autoStartChat: Boolean = true) {
        val code = extractInvitePayload(rawCode)
        if (code.isBlank() || busy) return
        importCode = code
        busy = true
        previewRecord = null
        fingerprintConfirmed = false
        worker.execute {
            val result = runCatching { pins.preview(code) }
            handler.post {
                busy = false
                result.fold(
                    onSuccess = { record ->
                        previewRecord = record
                        if (autoStartChat) {
                            pinImportedPeer(record)
                        } else {
                            statusMessage = "Code verified. Tap Start Chatting below."
                        }
                    },
                    onFailure = {
                        previewRecord = null
                        statusMessage = "That invite code isn't valid. Ask your contact to share it again."
                    },
                )
            }
        }
    }

    fun sendMessage(peer: MessengerPeer, text: String) {
        val activeIdentity = identity
        if (activeIdentity == null || !gatewayConfigured) {
            statusMessage = "Finish server setup in Settings before sending."
            return
        }
        val content = text.trim()
        if (content.isEmpty()) return
        busy = true
        draft = ""
        focusManager.clearFocus()
        worker.execute {
            var persistedMessageId: String? = null
            val result = runCatching {
                val runtime = createAlphaMessagingRuntime(
                    context = appContext,
                    identityStore = identityStore,
                    crypto = crypto,
                    identity = activeIdentity,
                    gatewayOrigin = gatewayOrigin,
                    database = database,
                    pins = pins,
                )
                try {
                    val session = runtime.engine.getOrCreateAlphaSession(
                        PeerPrekeyCandidate(peer.record.accountId, peer.record.deviceId),
                    )
                    val plaintext = content.toByteArray(Charsets.UTF_8)
                    try {
                        persistedMessageId = runtime.engine.encryptAndPersistOutgoing(session.sessionId, plaintext)
                    } finally {
                        plaintext.fill(0)
                    }
                    val submitAttempt = runCatching { runtime.engine.submitNextReadyOutbox(runtime.client) }
                    val outboxState = persistedMessageId?.let { database.getOutboxStatus(it)?.state }
                    val localPeers = loadLocalPeers()
                    Triple(localPeers, outboxState, submitAttempt.exceptionOrNull())
                } finally {
                    runtime.client.close()
                }
            }
            handler.post {
                busy = false
                result.fold(
                    onSuccess = { (loaded, outboxState, submitFailure) ->
                        peers = loaded
                        selectedPeerKey = peer.stableKey
                        statusMessage = when {
                            submitFailure != null -> "Saved locally; will send when server is reachable."
                            outboxState == OutboxState.DELIVERY_UNKNOWN -> "Send status uncertain — wait before resending."
                            else -> null
                        }
                    },
                    onFailure = {
                        if (persistedMessageId != null) {
                            refreshLocalPeers(peer.stableKey)
                            statusMessage = "Saved on this device, waiting to send."
                        } else {
                            draft = content
                            statusMessage = "Couldn't send message. Check your connection."
                        }
                    },
                )
            }
        }
    }


    val activeSim = simStatus
    val currentPeer = selectedPeer
    val userPhoneKey = (activeSim?.boundPhoneNumber ?: "default").filter { it.isDigit() }.ifEmpty { "default" }

    val suitePrefs = remember(appContext, userPhoneKey) {
        appContext.getSharedPreferences("pm-suite-state-$userPhoneKey", Context.MODE_PRIVATE)
    }
    var activeTab by remember { mutableStateOf(BottomNavTab.CHATS) }
    var currentScreen by remember { mutableStateOf(AppScreen.HOME) }
    var experienceConfig by remember(userPhoneKey) {
        mutableStateOf(loadAdaptiveExperienceConfig(suitePrefs))
    }
    fun updateExperienceConfig(next: AdaptiveUserExperienceConfig) {
        experienceConfig = next
        persistAdaptiveExperienceConfig(suitePrefs, next)
        if (next.simpleEasyMode && (activeTab == BottomNavTab.UPDATES || activeTab == BottomNavTab.COMMUNITIES)) {
            activeTab = BottomNavTab.CHATS
        }
    }

    DisposableEffect(currentScreen, selectedPeerKey, gatewayOrigin, identity, isActivityForeground) {
        val shouldPoll = (currentScreen == AppScreen.HOME || currentScreen == AppScreen.CONVERSATION) &&
            identity != null && gatewayConfigured && isActivityForeground
        val delaySeconds = if (currentScreen == AppScreen.CONVERSATION) 3L else 8L
        val task = if (shouldPoll) {
            worker.scheduleWithFixedDelay(
                { synchronizeForeground() },
                0L,
                delaySeconds,
                TimeUnit.SECONDS,
            )
        } else null
        onDispose { task?.cancel(true) }
    }

    var overflowMenuOpen by remember { mutableStateOf(false) }

    LaunchedEffect(route) {
        if (route == MessengerRoute.CONVERSATION && selectedPeerKey != null) {
            currentScreen = AppScreen.CONVERSATION
        }
    }

    // Individual Saved Notes per user account
    var selfNotes by remember(userPhoneKey) {
        mutableStateOf(
            listOf(
                MessengerMessage(
                    localMessageId = "welcome_note_$userPhoneKey",
                    direction = StoredMessageDirection.INBOUND,
                    body = "Your personal space for notes, links, and instant translation. Tap 'Read in:' above to read or listen in Telugu, Gujarati, Hindi, Tamil, or English.",
                    createdAtMillis = System.currentTimeMillis(),
                    outboxStatus = OutboxMessageStatus.SUBMITTED,
                ),
            ) + loadSavedSelfNotesForUser(suitePrefs, userPhoneKey),
        )
    }
    var isSelfNoteOpen by remember { mutableStateOf(false) }

    var richThreads by remember(userPhoneKey) {
        mutableStateOf(loadRichThreads(suitePrefs))
    }
    var activeRichThreadId by remember { mutableStateOf<String?>(null) }

    var starredMessageIds by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getStringSet("starred_ids", emptySet()).orEmpty())
    }

    fun toggleStarMessage(msgId: String) {
        val next = if (starredMessageIds.contains(msgId)) starredMessageIds - msgId else starredMessageIds + msgId
        starredMessageIds = next
        suitePrefs.edit().putStringSet("starred_ids", next).apply()
    }

    var selectedMemberNames by remember { mutableStateOf<Set<String>>(emptySet()) }
    var newGroupNameInput by remember { mutableStateOf("") }
    var newGroupDescInput by remember { mutableStateOf("") }
    var newCommunityNameInput by remember { mutableStateOf("") }
    var newCommunityDescInput by remember { mutableStateOf("") }

    var communities by remember(userPhoneKey) {
        mutableStateOf(loadCommunities(suitePrefs))
    }

    var statusStories by remember(userPhoneKey) {
        mutableStateOf(
            loadStatusStories(suitePrefs).ifEmpty {
                listOf(
                    StatusStoryItem(
                        id = "st_sample_1",
                        authorName = "Regional Trade Desk",
                        text = "Morning market rates updated in Telugu, Gujarati & Hindi.",
                        timestampMillis = System.currentTimeMillis() - 3600_000L,
                        bgColorHex = 0xFF283593,
                    ),
                )
            },
        )
    }
    var activeStatusStory by remember { mutableStateOf<StatusStoryItem?>(null) }
    var channels by remember(userPhoneKey) {
        mutableStateOf(
            loadChannels(suitePrefs).ifEmpty {
                listOf(
                    ChannelItem(
                        id = "ch_civic",
                        name = "AP & Telangana Civic Updates",
                        followersLabel = "48.2K followers",
                        verified = true,
                        followed = true,
                        posts = listOf(
                            "Monsoon readiness & municipal helpline numbers updated for Visakhapatnam and Hyderabad.",
                            "Digital citizen portal maintenance window scheduled tonight from 11:30 PM to 1:00 AM.",
                        ),
                    ),
                    ChannelItem(
                        id = "ch_agri",
                        name = "India Mandi & Commodity Pulse",
                        followersLabel = "92.5K followers",
                        verified = true,
                        followed = false,
                        posts = listOf(
                            "Turmeric, chilli, and cotton arrivals steady across Guntur, Rajkot, and Indore mandis.",
                        ),
                    ),
                    ChannelItem(
                        id = "ch_tech",
                        name = "Cyber Safety India",
                        followersLabel = "64.0K followers",
                        verified = true,
                        followed = false,
                        posts = listOf(
                            "Never share your 6-digit verification code or SIM slot PIN with anyone claiming to be support.",
                        ),
                    ),
                )
            },
        )
    }
    var activeChannelId by remember { mutableStateOf<String?>(null) }

    var callLogs by remember(userPhoneKey) {
        mutableStateOf(loadCallLogs(suitePrefs))
    }
    var activeCallPeerName by remember { mutableStateOf("") }
    var activeCallIsVideo by remember { mutableStateOf(false) }

    var linkedDevices by remember(userPhoneKey) {
        mutableStateOf(loadLinkedDevices(suitePrefs))
    }

    var profileName by remember(userPhoneKey) {
        mutableStateOf(simPrefs.getString("user_display_name", "").orEmpty().ifBlank { "My Profile" })
    }
    var profileAbout by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("profile_about", "Available").orEmpty())
    }
    var twoStepPin by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("two_step_pin", "").orEmpty())
    }
    var securityNotificationsEnabled by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("sec_notif", true))
    }
    var privacyLastSeen by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("priv_last_seen", "My contacts").orEmpty())
    }
    var privacyProfilePhoto by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("priv_photo", "Everyone").orEmpty())
    }
    var privacyAbout by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("priv_about", "Everyone").orEmpty())
    }
    var privacyReadReceipts by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("priv_read_receipts", true))
    }
    var privacyDefaultTimer by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("priv_timer", "Off").orEmpty())
    }
    var privacyAppLock by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("priv_app_lock", false))
    }
    var privacyOptionTarget by remember { mutableStateOf("Last seen and online") }

    var chatTheme by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("chat_theme", "System default").orEmpty())
    }
    var chatWallpaper by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("chat_wallpaper", "Clean Slate").orEmpty())
    }
    var enterIsSend by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("enter_is_send", false))
    }
    var mediaVisibility by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("media_visibility", true))
    }
    var lastBackupTime by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("last_backup", "Never").orEmpty())
    }

    var notifConversationTones by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("notif_tones", true))
    }
    var notifMessageTone by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("notif_msg_tone", "Default chime").orEmpty())
    }
    var notifGroupTone by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("notif_grp_tone", "Soft pulse").orEmpty())
    }
    var notifCallRingtone by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("notif_ringtone", "Classic ring").orEmpty())
    }

    var storageLessDataCalls by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getBoolean("storage_less_data", false))
    }
    var storageAutoDownloadWifi by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("storage_wifi", "Photos, Audio, Documents").orEmpty())
    }
    var storageAutoDownloadMobile by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("storage_mobile", "Photos").orEmpty())
    }
    var appLanguageLabel by remember(userPhoneKey) {
        mutableStateOf(suitePrefs.getString("app_language", "English").orEmpty())
    }
    var selectedFaqTopic by remember { mutableStateOf("End-to-end encryption & SIM binding") }

    fun openOrCreateRichThread(
        titleInput: String,
        subtitleInput: String = "Direct chat",
        kind: ThreadKind = ThreadKind.DIRECT,
        members: List<String> = emptyList(),
        initialBody: String? = null,
    ): RichThread {
        val cleanTitle = titleInput.trim().ifEmpty { subtitleInput.trim().ifEmpty { "New Chat" } }
        val slug = cleanTitle.lowercase(Locale.ROOT).replace(Regex("[^a-z0-9]+"), "_").take(24)
        val phoneSuffix = subtitleInput.filter { it.isDigit() }.takeLast(10)
        val threadId = "${kind.name.lowercase(Locale.ROOT)}_${slug}_$phoneSuffix"
        val existing = richThreads.firstOrNull { it.id == threadId }
        if (existing != null) {
            isSelfNoteOpen = false
            selectedPeerKey = null
            activeRichThreadId = existing.id
            currentScreen = AppScreen.CONVERSATION
            return existing
        }
        val starterText = initialBody ?: when (kind) {
            ThreadKind.DIRECT -> "Say hi to $cleanTitle! Switch 'Read in:' above to read or listen in Telugu, Gujarati, Hindi, or Tamil."
            ThreadKind.GROUP -> "You created group \"$cleanTitle\" with ${members.size} participants."
            ThreadKind.BROADCAST -> "Broadcast list created with ${members.size} recipients. Replies arrive privately."
        }
        val created = RichThread(
            id = threadId,
            title = cleanTitle,
            subtitle = if (kind == ThreadKind.DIRECT) subtitleInput.trim().ifEmpty { "Direct chat" }
            else "${members.size} participants",
            kind = kind,
            members = members,
            messages = listOf(
                MessengerMessage(
                    localMessageId = "init_$threadId",
                    direction = StoredMessageDirection.INBOUND,
                    body = starterText,
                    createdAtMillis = System.currentTimeMillis(),
                    outboxStatus = OutboxMessageStatus.SUBMITTED,
                ),
            ),
            disappearingTimer = privacyDefaultTimer,
        )
        val updated = listOf(created) + richThreads
        richThreads = updated
        persistRichThreads(suitePrefs, updated)
        isSelfNoteOpen = false
        selectedPeerKey = null
        activeRichThreadId = created.id
        currentScreen = AppScreen.CONVERSATION
        return created
    }

    fun startCallWith(peerName: String, isVideo: Boolean) {
        activeCallPeerName = peerName
        activeCallIsVideo = isVideo
        val entry = CallLogEntry(
            id = "call_${System.currentTimeMillis()}",
            peerName = peerName,
            isVideo = isVideo,
            isOutgoing = true,
            timestampMillis = System.currentTimeMillis(),
            durationLabel = "0:42",
        )
        val nextCalls = listOf(entry) + callLogs
        callLogs = nextCalls
        persistCallLogs(suitePrefs, nextCalls)
        currentScreen = AppScreen.IN_CALL
    }

    when {
        hidePrivateContent -> PrivacyMirrorNotice(onOpenSettings = onOpenSettings)
        activeSim == null -> QuickSimOnboardingScreen(
            context = appContext,
            simPrefs = simPrefs,
            onRequestPhonePermission = { phonePermLauncher.launch(Manifest.permission.READ_PHONE_STATE) },
            onCompleted = { simRefreshTick += 1 },
        )
        !activeSim.isSimPresentAndMatching -> SimBindingLockScreen(
            status = activeSim,
            onRequestPhonePermission = { phonePermLauncher.launch(Manifest.permission.READ_PHONE_STATE) },
            onReverifySim = { simRefreshTick += 1 },
            onRebindNewNumber = {
                simPrefs.edit().clear().apply()
                simRefreshTick += 1
            },
        )
        currentScreen == AppScreen.CONVERSATION && isSelfNoteOpen -> {
            val selfThread = RichThread(
                id = "self_notes_$userPhoneKey",
                title = "Saved Notes (You)",
                subtitle = "Message yourself · Private to ${activeSim.boundPhoneNumber}",
                kind = ThreadKind.DIRECT,
                messages = selfNotes,
            )
            val activeLang = getPeerLanguage(selfThread.id)
            LaunchedEffect(activeLang, selfNotes.size) {
                if (activeLang != LensLanguage.OFF) {
                    selfNotes.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, activeLang) }
                }
            }
            RichConversationScreen(
                thread = selfThread,
                activeLanguage = activeLang,
                onSelectLanguage = { lang ->
                    setPeerLanguage(selfThread.id, lang)
                    if (lang != LensLanguage.OFF) {
                        selfNotes.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, lang) }
                    }
                },
                getLensState = { msgId, lang -> lensCache["$msgId:${lang.code}"] },
                experienceConfig = experienceConfig,
                getSummaryState = { msgId, lang -> summaryCache["$msgId:${lang.code}"] },
                onSummarizeMessage = { msg, lang -> summarizeAttachmentOnDemand(msg, lang) },
                speakingMessageId = speakingMessageId,
                onSpeakMessage = { msgId, textToSpeak, lang -> speakText(msgId, textToSpeak, lang) },
                starredIds = starredMessageIds,
                onToggleStar = ::toggleStarMessage,
                draft = draft,
                onDraftChange = { draft = it },
                onBack = {
                    ttsEngine.stop()
                    speakingMessageId = null
                    isSelfNoteOpen = false
                    currentScreen = AppScreen.HOME
                },
                onOpenInfo = {},
                onStartVoiceCall = {},
                onStartVideoCall = {},
                onSend = {
                    val content = draft.trim()
                    if (content.isNotEmpty()) {
                        val newMsg = MessengerMessage(
                            localMessageId = "note_${userPhoneKey}_${System.currentTimeMillis()}",
                            direction = StoredMessageDirection.OUTBOUND,
                            body = content,
                            createdAtMillis = System.currentTimeMillis(),
                            outboxStatus = OutboxMessageStatus.SUBMITTED,
                        )
                        val updated = selfNotes + newMsg
                        selfNotes = updated
                        persistSelfNotesForUser(suitePrefs, userPhoneKey, updated)
                        draft = ""
                        focusManager.clearFocus()
                    }
                },
            )
        }
        currentScreen == AppScreen.CONVERSATION && activeRichThreadId != null -> {
            val thread = richThreads.firstOrNull { it.id == activeRichThreadId }
            if (thread == null) {
                activeRichThreadId = null
                currentScreen = AppScreen.HOME
            } else {
                val activeLang = getPeerLanguage(thread.id)
                LaunchedEffect(activeLang, thread.messages.size) {
                    if (activeLang != LensLanguage.OFF) {
                        thread.messages.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, activeLang) }
                    }
                }
                RichConversationScreen(
                    thread = thread,
                    activeLanguage = activeLang,
                    onSelectLanguage = { lang ->
                        setPeerLanguage(thread.id, lang)
                        if (lang != LensLanguage.OFF) {
                            thread.messages.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, lang) }
                        }
                    },
                    getLensState = { msgId, lang -> lensCache["$msgId:${lang.code}"] },
                experienceConfig = experienceConfig,
                getSummaryState = { msgId, lang -> summaryCache["$msgId:${lang.code}"] },
                onSummarizeMessage = { msg, lang -> summarizeAttachmentOnDemand(msg, lang) },
                    speakingMessageId = speakingMessageId,
                    onSpeakMessage = { msgId, textToSpeak, lang -> speakText(msgId, textToSpeak, lang) },
                    starredIds = starredMessageIds,
                    onToggleStar = ::toggleStarMessage,
                    draft = draft,
                    onDraftChange = { draft = it },
                    onBack = {
                        ttsEngine.stop()
                        speakingMessageId = null
                        activeRichThreadId = null
                        currentScreen = AppScreen.HOME
                    },
                    onOpenInfo = { currentScreen = AppScreen.CHAT_INFO },
                    onStartVoiceCall = { startCallWith(thread.title, isVideo = false) },
                    onStartVideoCall = { startCallWith(thread.title, isVideo = true) },
                    onSend = {
                        val content = draft.trim()
                        if (content.isNotEmpty()) {
                            val newMsg = MessengerMessage(
                                localMessageId = "rmsg_${System.currentTimeMillis()}",
                                direction = StoredMessageDirection.OUTBOUND,
                                body = content,
                                createdAtMillis = System.currentTimeMillis(),
                                outboxStatus = OutboxMessageStatus.SUBMITTED,
                            )
                            val nextThreads = richThreads.map { item ->
                                if (item.id == thread.id) item.copy(messages = item.messages + newMsg, unreadCount = 0) else item
                            }
                            richThreads = nextThreads
                            persistRichThreads(suitePrefs, nextThreads)
                            draft = ""
                            focusManager.clearFocus()
                        }
                    },
                )
            }
        }
        currentScreen == AppScreen.CONVERSATION && currentPeer != null -> {
            val activeLang = getPeerLanguage(currentPeer.stableKey)
            LaunchedEffect(currentPeer.stableKey, activeLang, currentPeer.messages.size) {
                if (activeLang != LensLanguage.OFF) {
                    currentPeer.messages.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, activeLang) }
                }
            }
            val bridgedThread = RichThread(
                id = currentPeer.stableKey,
                title = currentPeer.nickname,
                subtitle = syncSubtitle,
                kind = ThreadKind.DIRECT,
                messages = currentPeer.messages,
            )
            RichConversationScreen(
                thread = bridgedThread,
                activeLanguage = activeLang,
                onSelectLanguage = { lang ->
                    setPeerLanguage(currentPeer.stableKey, lang)
                    if (lang != LensLanguage.OFF) {
                        currentPeer.messages.takeLast(25).forEach { msg -> translateMessageOnDemand(msg, lang) }
                    }
                },
                getLensState = { msgId, lang -> lensCache["$msgId:${lang.code}"] },
                experienceConfig = experienceConfig,
                getSummaryState = { msgId, lang -> summaryCache["$msgId:${lang.code}"] },
                onSummarizeMessage = { msg, lang -> summarizeAttachmentOnDemand(msg, lang) },
                speakingMessageId = speakingMessageId,
                onSpeakMessage = { msgId, textToSpeak, lang -> speakText(msgId, textToSpeak, lang) },
                starredIds = starredMessageIds,
                onToggleStar = ::toggleStarMessage,
                draft = draft,
                onDraftChange = { draft = it },
                onBack = {
                    ttsEngine.stop()
                    speakingMessageId = null
                    selectedPeerKey = null
                    route = MessengerRoute.CHATS
                    currentScreen = AppScreen.HOME
                },
                onOpenInfo = {},
                onStartVoiceCall = { startCallWith(currentPeer.nickname, isVideo = false) },
                onStartVideoCall = { startCallWith(currentPeer.nickname, isVideo = true) },
                onSend = { sendMessage(currentPeer, draft) },
            )
        }
        currentScreen == AppScreen.CHAT_INFO && activeRichThreadId != null -> {
            val thread = richThreads.firstOrNull { it.id == activeRichThreadId }
            if (thread == null) {
                currentScreen = AppScreen.HOME
            } else {
                ChatInfoScreen(
                    thread = thread,
                    onBack = { currentScreen = AppScreen.CONVERSATION },
                    onToggleMute = {
                        val next = richThreads.map { if (it.id == thread.id) it.copy(isMuted = !it.isMuted) else it }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                    },
                    onToggleFavorite = {
                        val next = richThreads.map { if (it.id == thread.id) it.copy(isFavorite = !it.isFavorite) else it }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                    },
                    onCycleDisappearing = {
                        val order = listOf("Off", "24 hours", "7 days", "90 days")
                        val nextTimer = order[(order.indexOf(thread.disappearingTimer) + 1) % order.size]
                        val next = richThreads.map { if (it.id == thread.id) it.copy(disappearingTimer = nextTimer) else it }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                    },
                    onAddMember = { memberName ->
                        val next = richThreads.map { item ->
                            if (item.id == thread.id && !item.members.contains(memberName)) {
                                val updatedMembers = item.members + memberName
                                item.copy(
                                    members = updatedMembers,
                                    subtitle = if (item.kind == ThreadKind.GROUP) "${updatedMembers.size} participants" else item.subtitle,
                                )
                            } else item
                        }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                    },
                    onRemoveMember = { memberName ->
                        val next = richThreads.map { item ->
                            if (item.id == thread.id) {
                                val updatedMembers = item.members.filterNot { it == memberName }
                                item.copy(
                                    members = updatedMembers,
                                    subtitle = if (item.kind == ThreadKind.GROUP) "${updatedMembers.size} participants" else item.subtitle,
                                )
                            } else item
                        }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                    },
                    onClearChat = {
                        val next = richThreads.map { if (it.id == thread.id) it.copy(messages = emptyList()) else it }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                        currentScreen = AppScreen.CONVERSATION
                    },
                    onDeleteChat = {
                        val next = richThreads.filterNot { it.id == thread.id }
                        richThreads = next
                        persistRichThreads(suitePrefs, next)
                        activeRichThreadId = null
                        currentScreen = AppScreen.HOME
                    },
                )
            }
        }
        currentScreen == AppScreen.NEW_CHAT -> NewChatFullScreen(
            phonebookContacts = phonebookContacts,
            discoveredMatches = discoveredMatches,
            isDiscovering = isDiscoveringContacts,
            gatewayConfigured = gatewayConfigured,
            contactsPermissionGranted = contactsPermissionGranted,
            onSyncContacts = {
                if (contactsPermissionGranted) syncPhoneAndEmailContacts()
                else contactsPermLauncher.launch(Manifest.permission.READ_CONTACTS)
            },
            detectedClipboardInvite = detectedClipboardInvite,
            onUseClipboardInvite = {
                val clip = detectedClipboardInvite ?: return@NewChatFullScreen
                detectedClipboardInvite = null
                validateAndConnectCode(clip, autoStartChat = true)
            },
            onBack = { currentScreen = AppScreen.HOME },
            onOpenNewGroup = {
                selectedMemberNames = emptySet()
                currentScreen = AppScreen.NEW_GROUP_SELECT
            },
            onOpenNewCommunity = {
                newCommunityNameInput = ""
                newCommunityDescInput = ""
                currentScreen = AppScreen.NEW_COMMUNITY_INTRO
            },
            onOpenNewBroadcast = {
                selectedMemberNames = emptySet()
                currentScreen = AppScreen.NEW_BROADCAST_SELECT
            },
            onStartDirectChat = { name, phone -> openOrCreateRichThread(name, phone, ThreadKind.DIRECT) },
            onShareInvite = {
                val shareBody = "Let's chat privately in Telugu, Gujarati, Hindi, Tamil or English:\nhttps://sovereignpm.in/connect?invite=${URLEncoder.encode(myPairingCode.ifBlank { activeSim.boundPhoneNumber }, "UTF-8")}"
                val sendIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, shareBody)
                }
                appContext.startActivity(Intent.createChooser(sendIntent, "Invite a friend").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            },
            onConnectInviteCode = { nick, code ->
                localNickname = nick
                validateAndConnectCode(code, autoStartChat = true)
            },
        )
        currentScreen == AppScreen.NEW_GROUP_SELECT -> ParticipantPickerScreen(
            title = "New group",
            subtitle = if (selectedMemberNames.isEmpty()) "Add participants" else "${selectedMemberNames.size} selected",
            actionLabel = "Next",
            minRequired = 1,
            phonebookContacts = phonebookContacts,
            selectedNames = selectedMemberNames,
            onToggleName = { name ->
                selectedMemberNames = if (selectedMemberNames.contains(name)) selectedMemberNames - name else selectedMemberNames + name
            },
            onAddCustomName = { custom ->
                if (custom.isNotBlank()) selectedMemberNames = selectedMemberNames + custom.trim()
            },
            onBack = { currentScreen = AppScreen.HOME },
            onConfirm = {
                newGroupNameInput = ""
                newGroupDescInput = ""
                currentScreen = AppScreen.NEW_GROUP_DETAILS
            },
        )
        currentScreen == AppScreen.NEW_GROUP_DETAILS -> NewGroupDetailsScreen(
            members = selectedMemberNames.toList(),
            groupName = newGroupNameInput,
            onGroupNameChange = { newGroupNameInput = it },
            groupDesc = newGroupDescInput,
            onGroupDescChange = { newGroupDescInput = it },
            onBack = { currentScreen = AppScreen.NEW_GROUP_SELECT },
            onCreateGroup = {
                openOrCreateRichThread(
                    titleInput = newGroupNameInput.ifBlank { "New Group" },
                    subtitleInput = "${selectedMemberNames.size} participants",
                    kind = ThreadKind.GROUP,
                    members = selectedMemberNames.toList(),
                )
            },
        )
        currentScreen == AppScreen.NEW_BROADCAST_SELECT -> ParticipantPickerScreen(
            title = "New broadcast",
            subtitle = "${selectedMemberNames.size} recipients selected",
            actionLabel = "Create",
            minRequired = 1,
            phonebookContacts = phonebookContacts,
            selectedNames = selectedMemberNames,
            onToggleName = { name ->
                selectedMemberNames = if (selectedMemberNames.contains(name)) selectedMemberNames - name else selectedMemberNames + name
            },
            onAddCustomName = { custom ->
                if (custom.isNotBlank()) selectedMemberNames = selectedMemberNames + custom.trim()
            },
            onBack = { currentScreen = AppScreen.HOME },
            onConfirm = {
                val title = if (selectedMemberNames.size == 1) selectedMemberNames.first()
                else "${selectedMemberNames.size} recipients"
                openOrCreateRichThread(
                    titleInput = title,
                    subtitleInput = "Broadcast list",
                    kind = ThreadKind.BROADCAST,
                    members = selectedMemberNames.toList(),
                )
            },
        )
        currentScreen == AppScreen.NEW_COMMUNITY_INTRO -> NewCommunityIntroScreen(
            onBack = { currentScreen = AppScreen.HOME },
            onGetStarted = { currentScreen = AppScreen.NEW_COMMUNITY_DETAILS },
        )
        currentScreen == AppScreen.NEW_COMMUNITY_DETAILS -> NewCommunityDetailsScreen(
            name = newCommunityNameInput,
            onNameChange = { newCommunityNameInput = it },
            description = newCommunityDescInput,
            onDescriptionChange = { newCommunityDescInput = it },
            onBack = { currentScreen = AppScreen.NEW_COMMUNITY_INTRO },
            onCreateCommunity = {
                val cName = newCommunityNameInput.trim().ifEmpty { "Neighborhood Community" }
                val cDesc = newCommunityDescInput.trim().ifEmpty { "Announcements and member groups" }
                val annThread = openOrCreateRichThread(
                    titleInput = "$cName · Announcements",
                    subtitleInput = "Community announcements",
                    kind = ThreadKind.GROUP,
                    members = listOf(profileName),
                    initialBody = "Welcome to $cName! Admins post community-wide announcements here.",
                )
                val newComm = CommunityItem(
                    id = "comm_${System.currentTimeMillis()}",
                    name = cName,
                    description = cDesc,
                    announcementThreadId = annThread.id,
                    linkedGroupIds = listOf(annThread.id),
                )
                val nextComms = listOf(newComm) + communities
                communities = nextComms
                persistCommunities(suitePrefs, nextComms)
            },
        )
        currentScreen == AppScreen.LINKED_DEVICES -> LinkedDevicesScreen(
            devices = linkedDevices,
            onBack = { currentScreen = AppScreen.HOME },
            onLinkNewDevice = { label ->
                val added = LinkedDeviceSession(
                    id = "dev_${System.currentTimeMillis()}",
                    deviceName = label.ifBlank { "Desktop Browser" },
                    platform = "Web / Desktop Companion",
                    lastActive = "Active now",
                )
                val next = listOf(added) + linkedDevices
                linkedDevices = next
                persistLinkedDevices(suitePrefs, next)
            },
            onRemoveDevice = { devId ->
                val next = linkedDevices.filterNot { it.id == devId }
                linkedDevices = next
                persistLinkedDevices(suitePrefs, next)
            },
        )
        currentScreen == AppScreen.STARRED_MESSAGES -> StarredMessagesScreen(
            starredIds = starredMessageIds,
            selfNotes = selfNotes,
            richThreads = richThreads,
            onBack = { currentScreen = AppScreen.HOME },
            onUnstar = ::toggleStarMessage,
            onOpenSelfNotes = {
                isSelfNoteOpen = true
                activeRichThreadId = null
                currentScreen = AppScreen.CONVERSATION
            },
            onOpenThread = { tId ->
                isSelfNoteOpen = false
                activeRichThreadId = tId
                currentScreen = AppScreen.CONVERSATION
            },
        )
        currentScreen == AppScreen.CREATE_STATUS -> CreateStatusScreen(
            onBack = { currentScreen = AppScreen.HOME },
            onPublishStatus = { text, colorHex ->
                val story = StatusStoryItem(
                    id = "st_${System.currentTimeMillis()}",
                    authorName = "My status",
                    text = text,
                    timestampMillis = System.currentTimeMillis(),
                    bgColorHex = colorHex,
                    isMine = true,
                )
                val next = listOf(story) + statusStories
                statusStories = next
                persistStatusStories(suitePrefs, next)
                currentScreen = AppScreen.HOME
            },
        )
        currentScreen == AppScreen.STATUS_VIEWER && activeStatusStory != null -> StatusViewerScreen(
            story = activeStatusStory!!,
            onClose = {
                activeStatusStory = null
                currentScreen = AppScreen.HOME
            },
        )
        currentScreen == AppScreen.CHANNEL_FEED && activeChannelId != null -> {
            val ch = channels.firstOrNull { it.id == activeChannelId }
            if (ch == null) {
                currentScreen = AppScreen.HOME
            } else {
                ChannelFeedScreen(
                    channel = ch,
                    onBack = {
                        activeChannelId = null
                        currentScreen = AppScreen.HOME
                    },
                    onToggleFollow = {
                        val next = channels.map { if (it.id == ch.id) it.copy(followed = !it.followed) else it }
                        channels = next
                        persistChannels(suitePrefs, next)
                    },
                )
            }
        }
        currentScreen == AppScreen.NEW_CALL_PICKER -> NewCallPickerScreen(
            phonebookContacts = phonebookContacts,
            richThreads = richThreads,
            onBack = { currentScreen = AppScreen.HOME },
            onStartCall = { name, isVideo -> startCallWith(name, isVideo) },
        )
        currentScreen == AppScreen.IN_CALL -> InCallScreen(
            peerName = activeCallPeerName,
            isVideo = activeCallIsVideo,
            onEndCall = { currentScreen = AppScreen.HOME },
        )
        currentScreen == AppScreen.SETTINGS_HOME -> SettingsHomeScreen(
            experienceConfig = experienceConfig,
            onUpdateExperienceConfig = { updateExperienceConfig(it) },
            profileName = profileName,
            profileAbout = profileAbout,
            phoneNumber = activeSim.boundPhoneNumber,
            appLanguage = appLanguageLabel,
            onBack = { currentScreen = AppScreen.HOME },
            onOpenProfile = { currentScreen = AppScreen.SETTINGS_PROFILE },
            onOpenAccount = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
            onOpenPrivacy = { currentScreen = AppScreen.SETTINGS_PRIVACY },
            onOpenChats = { currentScreen = AppScreen.SETTINGS_CHATS },
            onOpenNotifications = { currentScreen = AppScreen.SETTINGS_NOTIFICATIONS },
            onOpenStorage = { currentScreen = AppScreen.SETTINGS_STORAGE },
            onOpenLanguage = { currentScreen = AppScreen.SETTINGS_LANGUAGE },
            onOpenHelp = { currentScreen = AppScreen.SETTINGS_HELP },
            onOpenAdvancedGateway = onOpenSettings,
        )
        currentScreen == AppScreen.SETTINGS_PROFILE -> SettingsProfileScreen(
            name = profileName,
            about = profileAbout,
            phone = activeSim.boundPhoneNumber,
            onSaveProfile = { newName, newAbout ->
                val cleanedName = newName.trim().ifBlank { "My Profile" }
                val cleanedAbout = newAbout.trim().ifBlank { "Available" }
                profileName = cleanedName
                profileAbout = cleanedAbout
                simPrefs.edit().putString("user_display_name", cleanedName).apply()
                suitePrefs.edit().putString("profile_about", cleanedAbout).apply()
                simRefreshTick += 1
                currentScreen = AppScreen.SETTINGS_HOME
            },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT -> SettingsAccountScreen(
            simStatus = activeSim,
            twoStepEnabled = twoStepPin.length == 6,
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
            onOpenSecurityNotifications = { currentScreen = AppScreen.SETTINGS_ACCOUNT_SECURITY },
            onOpenTwoStep = { currentScreen = AppScreen.SETTINGS_ACCOUNT_TWO_STEP },
            onOpenChangeNumber = { currentScreen = AppScreen.SETTINGS_ACCOUNT_CHANGE_NUMBER },
            onOpenRequestInfo = { currentScreen = AppScreen.SETTINGS_ACCOUNT_REQUEST_INFO },
            onOpenDeleteAccount = { currentScreen = AppScreen.SETTINGS_ACCOUNT_DELETE },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT_SECURITY -> SettingsAccountSecurityScreen(
            simStatus = activeSim,
            enabled = securityNotificationsEnabled,
            onToggle = {
                securityNotificationsEnabled = it
                suitePrefs.edit().putBoolean("sec_notif", it).apply()
            },
            onReverifySim = { simRefreshTick += 1 },
            onBack = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT_TWO_STEP -> SettingsTwoStepScreen(
            currentPin = twoStepPin,
            onSavePin = { pin ->
                twoStepPin = pin
                suitePrefs.edit().putString("two_step_pin", pin).apply()
                currentScreen = AppScreen.SETTINGS_ACCOUNT
            },
            onBack = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT_CHANGE_NUMBER -> SettingsChangeNumberScreen(
            currentPhone = activeSim.boundPhoneNumber,
            onBack = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
            onProceedRebind = {
                simPrefs.edit().clear().apply()
                currentScreen = AppScreen.HOME
                simRefreshTick += 1
            },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT_REQUEST_INFO -> SettingsRequestInfoScreen(
            phone = activeSim.boundPhoneNumber,
            name = profileName,
            notesCount = selfNotes.size,
            chatsCount = richThreads.size,
            onBack = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
        )
        currentScreen == AppScreen.SETTINGS_ACCOUNT_DELETE -> SettingsDeleteAccountScreen(
            phone = activeSim.boundPhoneNumber,
            onBack = { currentScreen = AppScreen.SETTINGS_ACCOUNT },
            onConfirmDelete = {
                suitePrefs.edit().clear().apply()
                simPrefs.edit().clear().apply()
                richThreads = emptyList()
                currentScreen = AppScreen.HOME
                simRefreshTick += 1
            },
        )
        currentScreen == AppScreen.SETTINGS_PRIVACY -> SettingsPrivacyScreen(
            lastSeen = privacyLastSeen,
            profilePhoto = privacyProfilePhoto,
            about = privacyAbout,
            readReceipts = privacyReadReceipts,
            defaultTimer = privacyDefaultTimer,
            appLock = privacyAppLock,
            onOpenAudienceOption = { target ->
                privacyOptionTarget = target
                currentScreen = AppScreen.SETTINGS_PRIVACY_OPTION
            },
            onToggleReadReceipts = {
                privacyReadReceipts = it
                suitePrefs.edit().putBoolean("priv_read_receipts", it).apply()
            },
            onCycleTimer = {
                val opts = listOf("Off", "24 hours", "7 days", "90 days")
                val next = opts[(opts.indexOf(privacyDefaultTimer) + 1) % opts.size]
                privacyDefaultTimer = next
                suitePrefs.edit().putString("priv_timer", next).apply()
            },
            onToggleAppLock = {
                privacyAppLock = it
                suitePrefs.edit().putBoolean("priv_app_lock", it).apply()
            },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_PRIVACY_OPTION -> {
            val currentVal = when (privacyOptionTarget) {
                "Last seen and online" -> privacyLastSeen
                "Profile photo" -> privacyProfilePhoto
                else -> privacyAbout
            }
            SettingsSingleChoiceScreen(
                title = privacyOptionTarget,
                options = listOf("Everyone", "My contacts", "Nobody"),
                selectedOption = currentVal,
                onSelect = { chosen ->
                    when (privacyOptionTarget) {
                        "Last seen and online" -> {
                            privacyLastSeen = chosen
                            suitePrefs.edit().putString("priv_last_seen", chosen).apply()
                        }
                        "Profile photo" -> {
                            privacyProfilePhoto = chosen
                            suitePrefs.edit().putString("priv_photo", chosen).apply()
                        }
                        else -> {
                            privacyAbout = chosen
                            suitePrefs.edit().putString("priv_about", chosen).apply()
                        }
                    }
                    currentScreen = AppScreen.SETTINGS_PRIVACY
                },
                onBack = { currentScreen = AppScreen.SETTINGS_PRIVACY },
            )
        }
        currentScreen == AppScreen.SETTINGS_CHATS -> SettingsChatsScreen(
            theme = chatTheme,
            wallpaper = chatWallpaper,
            enterIsSend = enterIsSend,
            mediaVisibility = mediaVisibility,
            lastBackup = lastBackupTime,
            onCycleTheme = {
                val opts = listOf("System default", "Light", "Dark")
                val next = opts[(opts.indexOf(chatTheme) + 1) % opts.size]
                chatTheme = next
                suitePrefs.edit().putString("chat_theme", next).apply()
            },
            onCycleWallpaper = {
                val opts = listOf("Clean Slate", "Soft Indigo", "Warm Sand", "Mint Mist")
                val next = opts[(opts.indexOf(chatWallpaper) + 1) % opts.size]
                chatWallpaper = next
                suitePrefs.edit().putString("chat_wallpaper", next).apply()
            },
            onToggleEnterIsSend = {
                enterIsSend = it
                suitePrefs.edit().putBoolean("enter_is_send", it).apply()
            },
            onToggleMediaVisibility = {
                mediaVisibility = it
                suitePrefs.edit().putBoolean("media_visibility", it).apply()
            },
            onRunBackup = {
                val stamp = SimpleDateFormat("dd MMM, h:mm a", Locale.getDefault()).format(Date())
                lastBackupTime = stamp
                suitePrefs.edit().putString("last_backup", stamp).apply()
            },
            onOpenChatHistory = { currentScreen = AppScreen.SETTINGS_CHATS_HISTORY },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_CHATS_HISTORY -> SettingsChatHistoryScreen(
            onClearAllChats = {
                val cleared = richThreads.map { it.copy(messages = emptyList()) }
                richThreads = cleared
                persistRichThreads(suitePrefs, cleared)
                currentScreen = AppScreen.SETTINGS_CHATS
            },
            onDeleteAllChats = {
                richThreads = emptyList()
                persistRichThreads(suitePrefs, emptyList())
                currentScreen = AppScreen.SETTINGS_CHATS
            },
            onBack = { currentScreen = AppScreen.SETTINGS_CHATS },
        )
        currentScreen == AppScreen.SETTINGS_NOTIFICATIONS -> SettingsNotificationsScreen(
            conversationTones = notifConversationTones,
            messageTone = notifMessageTone,
            groupTone = notifGroupTone,
            callRingtone = notifCallRingtone,
            onToggleConversationTones = {
                notifConversationTones = it
                suitePrefs.edit().putBoolean("notif_tones", it).apply()
            },
            onCycleMessageTone = {
                val opts = listOf("Default chime", "Crystal drop", "Soft bell", "Silent")
                val next = opts[(opts.indexOf(notifMessageTone) + 1) % opts.size]
                notifMessageTone = next
                suitePrefs.edit().putString("notif_msg_tone", next).apply()
            },
            onCycleGroupTone = {
                val opts = listOf("Soft pulse", "Chime", "Ripple", "Silent")
                val next = opts[(opts.indexOf(notifGroupTone) + 1) % opts.size]
                notifGroupTone = next
                suitePrefs.edit().putString("notif_grp_tone", next).apply()
            },
            onCycleRingtone = {
                val opts = listOf("Classic ring", "Horizon", "Marimba", "Vibrate only")
                val next = opts[(opts.indexOf(notifCallRingtone) + 1) % opts.size]
                notifCallRingtone = next
                suitePrefs.edit().putString("notif_ringtone", next).apply()
            },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_STORAGE -> SettingsStorageScreen(
            notesCount = selfNotes.size,
            chatsCount = richThreads.size,
            lessDataCalls = storageLessDataCalls,
            wifiAutoDownload = storageAutoDownloadWifi,
            mobileAutoDownload = storageAutoDownloadMobile,
            onToggleLessData = {
                storageLessDataCalls = it
                suitePrefs.edit().putBoolean("storage_less_data", it).apply()
            },
            onCycleWifi = {
                val opts = listOf("All media", "Photos, Audio, Documents", "Photos only", "Never")
                val next = opts[(opts.indexOf(storageAutoDownloadWifi) + 1) % opts.size]
                storageAutoDownloadWifi = next
                suitePrefs.edit().putString("storage_wifi", next).apply()
            },
            onCycleMobile = {
                val opts = listOf("Photos", "Photos, Audio", "Never")
                val next = opts[(opts.indexOf(storageAutoDownloadMobile) + 1) % opts.size]
                storageAutoDownloadMobile = next
                suitePrefs.edit().putString("storage_mobile", next).apply()
            },
            onClearCache = { lensCache.clear() },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_LANGUAGE -> SettingsSingleChoiceScreen(
            title = "App language",
            options = listOf("English", "తెలుగు (Telugu)", "ગુજરાતી (Gujarati)", "हिन्दी (Hindi)", "தமிழ் (Tamil)"),
            selectedOption = appLanguageLabel,
            onSelect = { chosen ->
                appLanguageLabel = chosen
                suitePrefs.edit().putString("app_language", chosen).apply()
                currentScreen = AppScreen.SETTINGS_HOME
            },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_HELP -> SettingsHelpScreen(
            onOpenFaq = { topic ->
                selectedFaqTopic = topic
                currentScreen = AppScreen.SETTINGS_HELP_FAQ
            },
            onOpenContactUs = { currentScreen = AppScreen.SETTINGS_HELP_CONTACT },
            onOpenAppInfo = { currentScreen = AppScreen.SETTINGS_HELP_APP_INFO },
            onBack = { currentScreen = AppScreen.SETTINGS_HOME },
        )
        currentScreen == AppScreen.SETTINGS_HELP_FAQ -> SettingsFaqDetailScreen(
            topic = selectedFaqTopic,
            onBack = { currentScreen = AppScreen.SETTINGS_HELP },
        )
        currentScreen == AppScreen.SETTINGS_HELP_CONTACT -> SettingsContactUsScreen(
            onBack = { currentScreen = AppScreen.SETTINGS_HELP },
        )
        currentScreen == AppScreen.SETTINGS_HELP_APP_INFO -> SettingsAppInfoScreen(
            onBack = { currentScreen = AppScreen.SETTINGS_HELP },
        )
        else -> MainFourTabHomeScreen(
            simpleEasyMode = experienceConfig.simpleEasyMode,
            activeTab = activeTab,
            onSelectTab = { activeTab = it; overflowMenuOpen = false },
            overflowMenuOpen = overflowMenuOpen,
            onToggleOverflowMenu = { overflowMenuOpen = !overflowMenuOpen },
            onDismissOverflowMenu = { overflowMenuOpen = false },
            onMenuNewGroup = {
                overflowMenuOpen = false
                selectedMemberNames = emptySet()
                currentScreen = AppScreen.NEW_GROUP_SELECT
            },
            onMenuNewCommunity = {
                overflowMenuOpen = false
                newCommunityNameInput = ""
                newCommunityDescInput = ""
                currentScreen = AppScreen.NEW_COMMUNITY_INTRO
            },
            onMenuNewBroadcast = {
                overflowMenuOpen = false
                selectedMemberNames = emptySet()
                currentScreen = AppScreen.NEW_BROADCAST_SELECT
            },
            onMenuLinkedDevices = {
                overflowMenuOpen = false
                currentScreen = AppScreen.LINKED_DEVICES
            },
            onMenuStarredMessages = {
                overflowMenuOpen = false
                currentScreen = AppScreen.STARRED_MESSAGES
            },
            onMenuSettings = {
                overflowMenuOpen = false
                currentScreen = AppScreen.SETTINGS_HOME
            },
            selfNotesLatest = selfNotes.lastOrNull(),
            onOpenSelfNotes = {
                isSelfNoteOpen = true
                activeRichThreadId = null
                selectedPeerKey = null
                currentScreen = AppScreen.CONVERSATION
            },
            richThreads = richThreads,
            peers = peers,
            getPeerLanguage = ::getPeerLanguage,
            onOpenRichThread = { tId ->
                isSelfNoteOpen = false
                selectedPeerKey = null
                activeRichThreadId = tId
                currentScreen = AppScreen.CONVERSATION
            },
            onOpenEncryptedPeer = { peer ->
                isSelfNoteOpen = false
                activeRichThreadId = null
                selectedPeerKey = peer.stableKey
                currentScreen = AppScreen.CONVERSATION
            },
            onOpenNewChat = {
                val clip = (appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager)
                    ?.primaryClip?.getItemAt(0)?.text?.toString()?.trim().orEmpty()
                detectedClipboardInvite = if (clip.startsWith("PM-") || clip.contains("invite=")) clip else null
                if (myPairingCode.isBlank() && identity != null && gatewayConfigured) {
                    createOwnPairingCode()
                }
                publishLocalDirectoryEntry(
                    context = appContext,
                    phoneNumber = activeSim.boundPhoneNumber,
                    displayName = profileName,
                    pairingCode = myPairingCode,
                )
                syncPhoneAndEmailContacts()
                currentScreen = AppScreen.NEW_CHAT
            },
            statusStories = statusStories,
            onOpenCreateStatus = { currentScreen = AppScreen.CREATE_STATUS },
            onOpenStatusStory = { story ->
                activeStatusStory = story
                currentScreen = AppScreen.STATUS_VIEWER
            },
            channels = channels,
            onToggleFollowChannel = { chId ->
                val next = channels.map { if (it.id == chId) it.copy(followed = !it.followed) else it }
                channels = next
                persistChannels(suitePrefs, next)
            },
            onOpenChannel = { chId ->
                activeChannelId = chId
                currentScreen = AppScreen.CHANNEL_FEED
            },
            communities = communities,
            onOpenCommunityThread = { tId ->
                isSelfNoteOpen = false
                activeRichThreadId = tId
                currentScreen = AppScreen.CONVERSATION
            },
            callLogs = callLogs,
            onOpenNewCallPicker = { currentScreen = AppScreen.NEW_CALL_PICKER },
            onStartCall = { name, isVideo -> startCallWith(name, isVideo) },
        )
    }
}

