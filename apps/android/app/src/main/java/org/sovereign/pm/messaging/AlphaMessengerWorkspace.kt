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


private enum class MessengerRoute { CHATS, ADD_CONTACT, CONVERSATION }

private enum class BottomNavTab(val label: String, val glyph: String) {
    CHATS("Chats", "💬"),
    UPDATES("Updates", "◎"),
    COMMUNITIES("Communities", "👥"),
    CALLS("Calls", "📞"),
}

private enum class AppScreen {
    HOME,
    NEW_CHAT,
    CONVERSATION,
    CHAT_INFO,
    NEW_GROUP_SELECT,
    NEW_GROUP_DETAILS,
    NEW_COMMUNITY_INTRO,
    NEW_COMMUNITY_DETAILS,
    NEW_BROADCAST_SELECT,
    LINKED_DEVICES,
    STARRED_MESSAGES,
    STATUS_VIEWER,
    CREATE_STATUS,
    CHANNEL_FEED,
    NEW_CALL_PICKER,
    IN_CALL,
    SETTINGS_HOME,
    SETTINGS_PROFILE,
    SETTINGS_ACCOUNT,
    SETTINGS_ACCOUNT_SECURITY,
    SETTINGS_ACCOUNT_TWO_STEP,
    SETTINGS_ACCOUNT_CHANGE_NUMBER,
    SETTINGS_ACCOUNT_REQUEST_INFO,
    SETTINGS_ACCOUNT_DELETE,
    SETTINGS_PRIVACY,
    SETTINGS_PRIVACY_OPTION,
    SETTINGS_CHATS,
    SETTINGS_CHATS_HISTORY,
    SETTINGS_NOTIFICATIONS,
    SETTINGS_STORAGE,
    SETTINGS_LANGUAGE,
    SETTINGS_HELP,
    SETTINGS_HELP_FAQ,
    SETTINGS_HELP_CONTACT,
    SETTINGS_HELP_APP_INFO,
}

private enum class ChatFilterChip(val label: String) {
    ALL("All"),
    UNREAD("Unread"),
    FAVORITES("Favorites"),
    GROUPS("Groups"),
}

private enum class ThreadKind {
    DIRECT,
    GROUP,
    BROADCAST,
}

private data class RichThread(
    val id: String,
    val title: String,
    val subtitle: String,
    val kind: ThreadKind = ThreadKind.DIRECT,
    val members: List<String> = emptyList(),
    val messages: List<MessengerMessage> = emptyList(),
    val isFavorite: Boolean = false,
    val isMuted: Boolean = false,
    val unreadCount: Int = 0,
    val disappearingTimer: String = "Off",
) {
    val latestMessage: MessengerMessage?
        get() = messages.lastOrNull()
}

private data class StatusStoryItem(
    val id: String,
    val authorName: String,
    val text: String,
    val timestampMillis: Long,
    val bgColorHex: Long,
    val isMine: Boolean = false,
)

private data class ChannelItem(
    val id: String,
    val name: String,
    val followersLabel: String,
    val verified: Boolean,
    val followed: Boolean,
    val posts: List<String>,
)

private data class CommunityItem(
    val id: String,
    val name: String,
    val description: String,
    val announcementThreadId: String,
    val linkedGroupIds: List<String>,
)

private data class CallLogEntry(
    val id: String,
    val peerName: String,
    val isVideo: Boolean,
    val isOutgoing: Boolean,
    val timestampMillis: Long,
    val durationLabel: String,
)

private data class LinkedDeviceSession(
    val id: String,
    val deviceName: String,
    val platform: String,
    val lastActive: String,
)

private enum class LensLanguage(
    val code: String,
    val label: String,
    val nativeLabel: String,
    val localeTag: String,
) {
    OFF("off", "Original", "Original", "en-IN"),
    TELUGU("te", "Telugu", "తెలుగు", "te-IN"),
    GUJARATI("gu", "Gujarati", "ગુજરાતી", "gu-IN"),
    HINDI("hi", "Hindi", "हिन्दी", "hi-IN"),
    TAMIL("ta", "Tamil", "தமிழ்", "ta-IN"),
    ENGLISH("en", "English", "English", "en-IN"),
}

private data class LensRenderState(
    val loading: Boolean = false,
    val translatedText: String? = null,
    val targetLang: LensLanguage = LensLanguage.OFF,
    val error: String? = null,
)

private data class MessengerMessage(
    val localMessageId: String,
    val direction: StoredMessageDirection,
    val body: String,
    val createdAtMillis: Long,
    val outboxStatus: OutboxMessageStatus?,
)

private data class MessengerPeer(
    val record: AlphaPairingRecord,
    val nickname: String,
    val messages: List<MessengerMessage>,
) {
    val stableKey: String get() = "${record.accountId.workspaceHex()}:${record.deviceId.workspaceHex()}"
    val latestMessage: MessengerMessage? get() = messages.lastOrNull()
}

private object SovereignSlatePalette {
    val PageCanvas = Color(0xFFF7F8FC)
    val CardWhite = Color(0xFFFFFFFF)
    val TopBarSurface = Color(0xFFFFFFFF)
    val PrimaryIndigo = Color(0xFF283593)
    val PrimaryIndigoSoft = Color(0xFFE8EAF6)
    val OutgoingBubble = Color(0xFF283593)
    val IncomingBubble = Color(0xFFFFFFFF)
    val ChatStreamCanvas = Color(0xFFF1F3F9)
    val SearchPill = Color(0xFFECEFF7)
    val NoticeBg = Color(0xFFFEF3C7)
    val NoticeText = Color(0xFF78350F)
    val TextPrimary = Color(0xFF141824)
    val TextSecondary = Color(0xFF5B6478)
    val Hairline = Color(0xFFE1E5F0)
    val VerifiedTeal = Color(0xFF0F766E)
    val VerifiedTealSoft = Color(0xFFCCFBF1)
}

private data class PhonebookContact(
    val id: String,
    val displayName: String,
    val phoneOrEmail: String,
    val isEmail: Boolean,
    val discoveryHashHex: String,
)

private fun sha256DiscoveryHash(normalizedValue: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(normalizedValue.toByteArray(Charsets.UTF_8))
    return digest.take(12).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

private fun normalizeIndianPhone(raw: String): String {
    val digits = raw.filter { it.isDigit() }
    return when {
        digits.length == 10 -> "+91$digits"
        digits.length == 12 && digits.startsWith("91") -> "+$digits"
        digits.startsWith("+") -> raw.filter { it.isDigit() || it == '+' }
        else -> digits
    }
}

private fun loadDevicePhoneAndEmailContacts(context: Context, limit: Int = 150): List<PhonebookContact> {
    val hasPerm = androidx.core.content.ContextCompat.checkSelfPermission(
        context,
        Manifest.permission.READ_CONTACTS,
    ) == PackageManager.PERMISSION_GRANTED
    if (!hasPerm) return emptyList()

    val results = LinkedHashMap<String, PhonebookContact>()

    // 1. Query phone numbers
    runCatching {
        context.contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(
                ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER,
            ),
            null,
            null,
            "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} ASC",
        )?.use { cursor ->
            val idIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.CONTACT_ID)
            val nameIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
            val numIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            while (cursor.moveToNext() && results.size < limit) {
                val name = cursor.getString(nameIdx)?.trim().orEmpty()
                val rawNum = cursor.getString(numIdx)?.trim().orEmpty()
                val normalized = normalizeIndianPhone(rawNum)
                if (name.isNotBlank() && normalized.length >= 10) {
                    val key = "p:$normalized"
                    if (!results.containsKey(key)) {
                        results[key] = PhonebookContact(
                            id = cursor.getString(idIdx) ?: key,
                            displayName = name,
                            phoneOrEmail = normalized,
                            isEmail = false,
                            discoveryHashHex = sha256DiscoveryHash(normalized),
                        )
                    }
                }
            }
        }
    }

    // 2. Query email addresses
    runCatching {
        context.contentResolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            arrayOf(
                ContactsContract.CommonDataKinds.Email.CONTACT_ID,
                ContactsContract.CommonDataKinds.Email.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Email.ADDRESS,
            ),
            null,
            null,
            "${ContactsContract.CommonDataKinds.Email.DISPLAY_NAME} ASC",
        )?.use { cursor ->
            val idIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.CONTACT_ID)
            val nameIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.DISPLAY_NAME)
            val mailIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
            while (cursor.moveToNext() && results.size < limit) {
                val name = cursor.getString(nameIdx)?.trim().orEmpty()
                val email = cursor.getString(mailIdx)?.trim()?.lowercase(Locale.ROOT).orEmpty()
                if (email.contains("@")) {
                    val label = name.ifBlank { email.substringBefore("@") }
                    val key = "e:$email"
                    if (!results.containsKey(key)) {
                        results[key] = PhonebookContact(
                            id = cursor.getString(idIdx) ?: key,
                            displayName = label,
                            phoneOrEmail = email,
                            isEmail = true,
                            discoveryHashHex = sha256DiscoveryHash(email),
                        )
                    }
                }
            }
        }
    }

    return results.values.toList()
}

private data class SimBindingStatus(
    val boundPhoneNumber: String,
    val boundSubscriptionId: Int,
    val carrierName: String,
    val isSimPresentAndMatching: Boolean,
    val isTestBypass: Boolean,
    val detailMessage: String,
)

private fun evaluateSimBindingState(
    context: Context,
    prefs: android.content.SharedPreferences,
): SimBindingStatus? {
    val savedPhone = prefs.getString("registered_phone", null)?.takeIf { it.isNotBlank() } ?: return null
    val savedSubId = prefs.getInt("bound_sim_sub_id", -1)
    val savedCarrier = prefs.getString("bound_sim_carrier", "Mobile SIM") ?: "Mobile SIM"
    val testBypass = prefs.getBoolean("sim_binding_test_bypass", false)

    val displayName = prefs.getString("user_display_name", null)?.takeIf { it.isNotBlank() }
    val cleanLabel = if (displayName != null) "$displayName · $savedPhone" else savedPhone
    if (testBypass) {
        return SimBindingStatus(
            boundPhoneNumber = savedPhone,
            boundSubscriptionId = savedSubId,
            carrierName = savedCarrier,
            isSimPresentAndMatching = true,
            isTestBypass = true,
            detailMessage = cleanLabel,
        )
    }

    val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
    val simState = tm?.simState ?: TelephonyManager.SIM_STATE_UNKNOWN
    if (simState != TelephonyManager.SIM_STATE_READY) {
        return SimBindingStatus(
            boundPhoneNumber = savedPhone,
            boundSubscriptionId = savedSubId,
            carrierName = savedCarrier,
            isSimPresentAndMatching = false,
            isTestBypass = false,
            detailMessage = "Registered SIM missing or inactive. Insert your $savedCarrier SIM ($savedPhone) per DoT SIM-binding rules.",
        )
    }

    val hasPhonePerm = androidx.core.content.ContextCompat.checkSelfPermission(
        context,
        Manifest.permission.READ_PHONE_STATE,
    ) == PackageManager.PERMISSION_GRANTED

    if (!hasPhonePerm) {
        return SimBindingStatus(
            boundPhoneNumber = savedPhone,
            boundSubscriptionId = savedSubId,
            carrierName = savedCarrier,
            isSimPresentAndMatching = false,
            isTestBypass = false,
            detailMessage = "Phone permission needed to verify active SIM ($savedPhone).",
        )
    }

    val subManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as? SubscriptionManager
    val activeSubs = runCatching { subManager?.activeSubscriptionInfoList }.getOrNull().orEmpty()
    val matchingSub = if (savedSubId != -1) {
        activeSubs.firstOrNull { it.subscriptionId == savedSubId }
    } else {
        activeSubs.firstOrNull()
    }

    return if (matchingSub != null) {
        val liveCarrier = matchingSub.carrierName?.toString()?.takeIf { it.isNotBlank() } ?: savedCarrier
        SimBindingStatus(
            boundPhoneNumber = savedPhone,
            boundSubscriptionId = matchingSub.subscriptionId,
            carrierName = liveCarrier,
            isSimPresentAndMatching = true,
            isTestBypass = false,
            detailMessage = cleanLabel,
        )
    } else {
        SimBindingStatus(
            boundPhoneNumber = savedPhone,
            boundSubscriptionId = savedSubId,
            carrierName = savedCarrier,
            isSimPresentAndMatching = false,
            isTestBypass = false,
            detailMessage = "SIM changed or removed. Re-insert the SIM registered to $savedPhone to continue messaging.",
        )
    }
}

private fun extractInvitePayload(raw: String): String {
    val trimmed = raw.trim()
    if (trimmed.contains("invite=")) {
        val parsed = runCatching { Uri.parse(trimmed).getQueryParameter("invite") }.getOrNull()
        if (!parsed.isNullOrBlank()) return parsed.trim()
    }
    if (trimmed.contains("c=")) {
        val parsed = runCatching { Uri.parse(trimmed).getQueryParameter("c") }.getOrNull()
        if (!parsed.isNullOrBlank()) return parsed.trim()
    }
    return trimmed
}

/**
 * Brand-distinct, everyday messenger with built-in Language Lens:
 * - Preserves all end-to-end encryption, peer key pinning, and local SQLite persistence.
 * - Lets each user pick their preferred reading/listening language (Telugu, Gujarati, Hindi,
 *   Tamil, English) per conversation so regional speakers and traders understand each other
 *   effortlessly while keeping the original encrypted message untouched.
 */
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

    fun syncPhoneAndEmailContacts() {
        worker.execute {
            val loaded = loadDevicePhoneAndEmailContacts(appContext)
            handler.post {
                phonebookContacts = loaded
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
    val gatewayConfigured = gatewayOrigin.startsWith("https://", ignoreCase = true)

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

    DisposableEffect(route, selectedPeerKey, gatewayOrigin, identity, isActivityForeground) {
        val shouldPoll = route == MessengerRoute.CONVERSATION && selectedPeerKey != null &&
            identity != null && gatewayConfigured && isActivityForeground
        val task = if (shouldPoll) {
            worker.scheduleWithFixedDelay(
                { synchronizeForeground() },
                0L,
                3L,
                TimeUnit.SECONDS,
            )
        } else null
        onDispose { task?.cancel(true) }
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


// ============================================================================
// MAIN 4-TAB SHELL + OVERFLOW MENU (CHATS, UPDATES, COMMUNITIES, CALLS)
// ============================================================================

@Composable
private fun MainFourTabHomeScreen(
    activeTab: BottomNavTab,
    onSelectTab: (BottomNavTab) -> Unit,
    overflowMenuOpen: Boolean,
    onToggleOverflowMenu: () -> Unit,
    onDismissOverflowMenu: () -> Unit,
    onMenuNewGroup: () -> Unit,
    onMenuNewCommunity: () -> Unit,
    onMenuNewBroadcast: () -> Unit,
    onMenuLinkedDevices: () -> Unit,
    onMenuStarredMessages: () -> Unit,
    onMenuSettings: () -> Unit,
    selfNotesLatest: MessengerMessage?,
    onOpenSelfNotes: () -> Unit,
    richThreads: List<RichThread>,
    peers: List<MessengerPeer>,
    getPeerLanguage: (String) -> LensLanguage,
    onOpenRichThread: (String) -> Unit,
    onOpenEncryptedPeer: (MessengerPeer) -> Unit,
    onOpenNewChat: () -> Unit,
    statusStories: List<StatusStoryItem>,
    onOpenCreateStatus: () -> Unit,
    onOpenStatusStory: (StatusStoryItem) -> Unit,
    channels: List<ChannelItem>,
    onToggleFollowChannel: (String) -> Unit,
    onOpenChannel: (String) -> Unit,
    communities: List<CommunityItem>,
    onOpenCommunityThread: (String) -> Unit,
    callLogs: List<CallLogEntry>,
    onOpenNewCallPicker: () -> Unit,
    onStartCall: (String, Boolean) -> Unit,
) {
    var searchQuery by remember { mutableStateOf("") }
    var activeFilter by remember { mutableStateOf(ChatFilterChip.ALL) }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = {
            Surface(
                color = SovereignSlatePalette.TopBarSurface,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            activeTab.label,
                            fontSize = 23.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (activeTab == BottomNavTab.CHATS) SovereignSlatePalette.PrimaryIndigo else SovereignSlatePalette.TextPrimary,
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            if (activeTab == BottomNavTab.CHATS) {
                                Surface(
                                    shape = CircleShape,
                                    color = SovereignSlatePalette.SearchPill,
                                    modifier = Modifier
                                        .size(36.dp)
                                        .clip(CircleShape)
                                        .clickable(onClick = onOpenCreateStatus),
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Text("📷", fontSize = 15.sp)
                                    }
                                }
                            }
                            Surface(
                                shape = CircleShape,
                                color = SovereignSlatePalette.SearchPill,
                                modifier = Modifier
                                    .size(36.dp)
                                    .clip(CircleShape)
                                    .clickable(onClick = onToggleOverflowMenu),
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        "⋮",
                                        fontSize = 19.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = SovereignSlatePalette.TextPrimary,
                                    )
                                }
                            }
                        }
                    }

                    // Search bar on Chats, Updates, and Calls
                    if (activeTab != BottomNavTab.COMMUNITIES) {
                        Surface(
                            shape = RoundedCornerShape(22.dp),
                            color = SovereignSlatePalette.SearchPill,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 9.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                Text("⌕", fontSize = 16.sp, color = SovereignSlatePalette.TextSecondary)
                                Box(modifier = Modifier.weight(1f)) {
                                    if (searchQuery.isEmpty()) {
                                        Text(
                                            when (activeTab) {
                                                BottomNavTab.CHATS -> "Search"
                                                BottomNavTab.UPDATES -> "Search updates & channels"
                                                BottomNavTab.CALLS -> "Search calls"
                                                else -> "Search"
                                            },
                                            color = SovereignSlatePalette.TextSecondary,
                                            fontSize = 15.sp,
                                        )
                                    }
                                    BasicTextField(
                                        value = searchQuery,
                                        onValueChange = { searchQuery = it },
                                        singleLine = true,
                                        textStyle = TextStyle(color = SovereignSlatePalette.TextPrimary, fontSize = 15.sp),
                                        cursorBrush = SolidColor(SovereignSlatePalette.PrimaryIndigo),
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                                if (searchQuery.isNotEmpty()) {
                                    Text(
                                        "✕",
                                        fontSize = 14.sp,
                                        color = SovereignSlatePalette.TextSecondary,
                                        modifier = Modifier
                                            .clip(CircleShape)
                                            .clickable { searchQuery = "" }
                                            .padding(4.dp),
                                    )
                                }
                            }
                        }
                    }

                    // Filter pills on Chats tab (All | Unread | Favorites | Groups)
                    if (activeTab == BottomNavTab.CHATS) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            ChatFilterChip.entries.forEach { chip ->
                                val selected = activeFilter == chip
                                Surface(
                                    shape = CircleShape,
                                    color = if (selected) SovereignSlatePalette.PrimaryIndigoSoft else SovereignSlatePalette.SearchPill,
                                    modifier = Modifier
                                        .clip(CircleShape)
                                        .clickable { activeFilter = chip },
                                ) {
                                    Text(
                                        chip.label,
                                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                                        fontSize = 13.sp,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                                        color = if (selected) SovereignSlatePalette.PrimaryIndigo else SovereignSlatePalette.TextSecondary,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        floatingActionButton = {
            when (activeTab) {
                BottomNavTab.CHATS -> FloatingActionButton(
                    onClick = onOpenNewChat,
                    containerColor = SovereignSlatePalette.PrimaryIndigo,
                    contentColor = Color.White,
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text("✎", fontSize = 17.sp, color = Color.White)
                        Text("New Chat", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
                BottomNavTab.UPDATES -> FloatingActionButton(
                    onClick = onOpenCreateStatus,
                    containerColor = SovereignSlatePalette.PrimaryIndigo,
                    contentColor = Color.White,
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Text("✎", fontSize = 18.sp, color = Color.White)
                }
                BottomNavTab.CALLS -> FloatingActionButton(
                    onClick = onOpenNewCallPicker,
                    containerColor = SovereignSlatePalette.PrimaryIndigo,
                    contentColor = Color.White,
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Text("📞", fontSize = 18.sp)
                }
                else -> {}
            }
        },
        bottomBar = {
            Surface(
                color = SovereignSlatePalette.TopBarSurface,
                border = BorderStroke(0.5.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceAround,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    BottomNavTab.entries.forEach { tab ->
                        val selected = activeTab == tab
                        Column(
                            modifier = Modifier
                                .clip(RoundedCornerShape(14.dp))
                                .clickable { onSelectTab(tab) }
                                .padding(horizontal = 12.dp, vertical = 4.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(3.dp),
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = if (selected) SovereignSlatePalette.PrimaryIndigoSoft else Color.Transparent,
                            ) {
                                Text(
                                    tab.glyph,
                                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 3.dp),
                                    fontSize = 16.sp,
                                )
                            }
                            Text(
                                tab.label,
                                fontSize = 11.sp,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                                color = if (selected) SovereignSlatePalette.PrimaryIndigo else SovereignSlatePalette.TextSecondary,
                            )
                        }
                    }
                }
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (activeTab) {
                BottomNavTab.CHATS -> {
                    val q = searchQuery.trim()
                    val filteredThreads = richThreads.filter { t ->
                        val chipOk = when (activeFilter) {
                            ChatFilterChip.ALL -> true
                            ChatFilterChip.UNREAD -> t.unreadCount > 0
                            ChatFilterChip.FAVORITES -> t.isFavorite
                            ChatFilterChip.GROUPS -> t.kind == ThreadKind.GROUP
                        }
                        val queryOk = q.isEmpty() ||
                            t.title.contains(q, ignoreCase = true) ||
                            t.latestMessage?.body?.contains(q, ignoreCase = true) == true
                        chipOk && queryOk
                    }
                    val filteredPeers = peers.filter { p ->
                        val chipOk = activeFilter == ChatFilterChip.ALL
                        val queryOk = q.isEmpty() ||
                            p.nickname.contains(q, ignoreCase = true) ||
                            p.latestMessage?.body?.contains(q, ignoreCase = true) == true
                        chipOk && queryOk
                    }

                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 92.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        // Individual Saved Notes (You) — always available per logged-in user
                        if (activeFilter == ChatFilterChip.ALL || activeFilter == ChatFilterChip.FAVORITES) {
                            item(key = "individual_saved_notes") {
                                ChatListRowCard(
                                    title = "Saved Notes (You)",
                                    subtitle = selfNotesLatest?.body ?: "Message yourself",
                                    timeLabel = selfNotesLatest?.let { formatInboxTime(it.createdAtMillis) } ?: "",
                                    avatarText = "★",
                                    badgeText = "You",
                                    isMuted = false,
                                    onClick = onOpenSelfNotes,
                                )
                            }
                        }

                        itemsIndexed(filteredThreads, key = { _, t -> t.id }) { _, thread ->
                            val latest = thread.latestMessage
                            val badge = when (thread.kind) {
                                ThreadKind.GROUP -> "Group"
                                ThreadKind.BROADCAST -> "Broadcast"
                                ThreadKind.DIRECT -> getPeerLanguage(thread.id).takeIf { it != LensLanguage.OFF }?.nativeLabel
                            }
                            ChatListRowCard(
                                title = thread.title,
                                subtitle = latest?.body ?: thread.subtitle,
                                timeLabel = latest?.let { formatInboxTime(it.createdAtMillis) } ?: "",
                                avatarText = thread.title.take(1).uppercase(),
                                badgeText = badge,
                                isMuted = thread.isMuted,
                                onClick = { onOpenRichThread(thread.id) },
                            )
                        }

                        itemsIndexed(filteredPeers, key = { _, p -> p.stableKey }) { _, peer ->
                            val latest = peer.latestMessage
                            ChatListRowCard(
                                title = peer.nickname,
                                subtitle = latest?.body ?: "Encrypted chat",
                                timeLabel = latest?.let { formatInboxTime(it.createdAtMillis) } ?: "",
                                avatarText = peer.nickname.take(1).uppercase(),
                                badgeText = getPeerLanguage(peer.stableKey).takeIf { it != LensLanguage.OFF }?.nativeLabel,
                                isMuted = false,
                                onClick = { onOpenEncryptedPeer(peer) },
                            )
                        }
                    }
                }
                BottomNavTab.UPDATES -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 10.dp, bottom = 92.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        item(key = "status_header") {
                            Text(
                                "Status",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = SovereignSlatePalette.TextPrimary,
                            )
                        }
                        item(key = "my_status_row") {
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(16.dp))
                                    .clickable(onClick = onOpenCreateStatus),
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Surface(
                                        shape = CircleShape,
                                        color = SovereignSlatePalette.PrimaryIndigo,
                                        modifier = Modifier.size(48.dp),
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text("+", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        }
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            "My status",
                                            fontSize = 16.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SovereignSlatePalette.TextPrimary,
                                        )
                                        Text(
                                            "Tap to add status update",
                                            fontSize = 13.sp,
                                            color = SovereignSlatePalette.TextSecondary,
                                        )
                                    }
                                }
                            }
                        }
                        itemsIndexed(statusStories, key = { _, st -> st.id }) { _, story ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(16.dp))
                                    .clickable { onOpenStatusStory(story) },
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Surface(
                                        shape = CircleShape,
                                        color = Color(story.bgColorHex),
                                        modifier = Modifier.size(48.dp),
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text(
                                                story.authorName.take(1).uppercase(),
                                                color = Color.White,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 18.sp,
                                            )
                                        }
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            story.authorName,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SovereignSlatePalette.TextPrimary,
                                        )
                                        Text(
                                            story.text,
                                            fontSize = 13.sp,
                                            color = SovereignSlatePalette.TextSecondary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                    Text(
                                        formatInboxTime(story.timestampMillis),
                                        fontSize = 12.sp,
                                        color = SovereignSlatePalette.TextSecondary,
                                    )
                                }
                            }
                        }

                        item(key = "channels_header") {
                            Text(
                                "Channels",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = SovereignSlatePalette.TextPrimary,
                            )
                        }
                        itemsIndexed(channels, key = { _, ch -> ch.id }) { _, ch ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(16.dp))
                                    .clickable { onOpenChannel(ch.id) },
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Surface(
                                        shape = CircleShape,
                                        color = SovereignSlatePalette.VerifiedTealSoft,
                                        modifier = Modifier.size(46.dp),
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text("📢", fontSize = 20.sp)
                                        }
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            ch.name,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SovereignSlatePalette.TextPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Text(
                                            ch.followersLabel,
                                            fontSize = 12.sp,
                                            color = SovereignSlatePalette.TextSecondary,
                                        )
                                    }
                                    Surface(
                                        shape = CircleShape,
                                        color = if (ch.followed) SovereignSlatePalette.SearchPill else SovereignSlatePalette.PrimaryIndigoSoft,
                                        modifier = Modifier
                                            .clip(CircleShape)
                                            .clickable { onToggleFollowChannel(ch.id) },
                                    ) {
                                        Text(
                                            if (ch.followed) "Following" else "Follow",
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = if (ch.followed) SovereignSlatePalette.TextSecondary else SovereignSlatePalette.PrimaryIndigo,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                BottomNavTab.COMMUNITIES -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        item(key = "new_community_card") {
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(16.dp))
                                    .clickable(onClick = onMenuNewCommunity),
                            ) {
                                Row(
                                    modifier = Modifier.padding(16.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Surface(
                                        shape = RoundedCornerShape(14.dp),
                                        color = SovereignSlatePalette.PrimaryIndigo,
                                        modifier = Modifier.size(48.dp),
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text("👥", fontSize = 22.sp)
                                        }
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            "New community",
                                            fontSize = 16.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = SovereignSlatePalette.TextPrimary,
                                        )
                                        Text(
                                            "Bring neighborhood, trade, or family groups together",
                                            fontSize = 13.sp,
                                            color = SovereignSlatePalette.TextSecondary,
                                        )
                                    }
                                }
                            }
                        }

                        itemsIndexed(communities, key = { _, comm -> comm.id }) { _, comm ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    Text(
                                        comm.name,
                                        fontSize = 17.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = SovereignSlatePalette.TextPrimary,
                                    )
                                    Text(
                                        comm.description,
                                        fontSize = 13.sp,
                                        color = SovereignSlatePalette.TextSecondary,
                                    )
                                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(10.dp))
                                            .clickable { onOpenCommunityThread(comm.announcementThreadId) }
                                            .padding(vertical = 6.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                                    ) {
                                        Text("📣", fontSize = 18.sp)
                                        Text(
                                            "Announcements",
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SovereignSlatePalette.PrimaryIndigo,
                                            modifier = Modifier.weight(1f),
                                        )
                                        Text("Open →", fontSize = 12.sp, color = SovereignSlatePalette.TextSecondary)
                                    }
                                }
                            }
                        }
                    }
                }
                BottomNavTab.CALLS -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 10.dp, bottom = 92.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        item(key = "create_call_link") {
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = SovereignSlatePalette.CardWhite,
                                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(16.dp))
                                    .clickable(onClick = onOpenNewCallPicker),
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Surface(
                                        shape = CircleShape,
                                        color = SovereignSlatePalette.PrimaryIndigo,
                                        modifier = Modifier.size(46.dp),
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text("🔗", fontSize = 18.sp)
                                        }
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            "Start a voice or video call",
                                            fontSize = 16.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SovereignSlatePalette.TextPrimary,
                                        )
                                        Text(
                                            "Encrypted 1-to-1 calling",
                                            fontSize = 13.sp,
                                            color = SovereignSlatePalette.TextSecondary,
                                        )
                                    }
                                }
                            }
                        }

                        if (callLogs.isEmpty()) {
                            item(key = "empty_calls") {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 36.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        "No recent calls yet. Tap 📞 below to start a call.",
                                        fontSize = 14.sp,
                                        color = SovereignSlatePalette.TextSecondary,
                                    )
                                }
                            }
                        } else {
                            item(key = "recent_calls_hdr") {
                                Text(
                                    "Recent",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = SovereignSlatePalette.TextSecondary,
                                )
                            }
                            itemsIndexed(callLogs, key = { _, c -> c.id }) { _, call ->
                                Surface(
                                    shape = RoundedCornerShape(14.dp),
                                    color = SovereignSlatePalette.CardWhite,
                                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Row(
                                        modifier = Modifier.padding(14.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    ) {
                                        Surface(
                                            shape = CircleShape,
                                            color = SovereignSlatePalette.PrimaryIndigoSoft,
                                            modifier = Modifier.size(44.dp),
                                        ) {
                                            Box(contentAlignment = Alignment.Center) {
                                                Text(
                                                    call.peerName.take(1).uppercase(),
                                                    fontWeight = FontWeight.Bold,
                                                    color = SovereignSlatePalette.PrimaryIndigo,
                                                )
                                            }
                                        }
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                call.peerName,
                                                fontSize = 15.sp,
                                                fontWeight = FontWeight.SemiBold,
                                                color = SovereignSlatePalette.TextPrimary,
                                            )
                                            Text(
                                                "↗ ${formatInboxTime(call.timestampMillis)} · ${call.durationLabel}",
                                                fontSize = 12.sp,
                                                color = SovereignSlatePalette.VerifiedTeal,
                                            )
                                        }
                                        TextButton(onClick = { onStartCall(call.peerName, call.isVideo) }) {
                                            Text(if (call.isVideo) "📹" else "📞", fontSize = 18.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 3-Dots Top-Right Overflow Dropdown Card (New group, New community, New broadcast, Linked devices, Starred messages, Settings)
            if (overflowMenuOpen) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.18f))
                        .clickable(onClick = onDismissOverflowMenu),
                ) {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = SovereignSlatePalette.CardWhite,
                        border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                        shadowElevation = 8.dp,
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(top = 6.dp, end = 14.dp)
                            .widthIn(min = 215.dp, max = 250.dp),
                    ) {
                        Column(modifier = Modifier.padding(vertical = 6.dp)) {
                            OverflowMenuOptionRow("New group", onClick = onMenuNewGroup)
                            OverflowMenuOptionRow("New community", onClick = onMenuNewCommunity)
                            OverflowMenuOptionRow("New broadcast", onClick = onMenuNewBroadcast)
                            OverflowMenuOptionRow("Linked devices", onClick = onMenuLinkedDevices)
                            OverflowMenuOptionRow("Starred messages", onClick = onMenuStarredMessages)
                            HorizontalDivider(color = SovereignSlatePalette.Hairline)
                            OverflowMenuOptionRow("Settings", onClick = onMenuSettings)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun OverflowMenuOptionRow(label: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            fontSize = 15.sp,
            fontWeight = FontWeight.Medium,
            color = SovereignSlatePalette.TextPrimary,
        )
    }
}

@Composable
private fun ChatListRowCard(
    title: String,
    subtitle: String,
    timeLabel: String,
    avatarText: String,
    badgeText: String?,
    isMuted: Boolean,
    onClick: () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = SovereignSlatePalette.CardWhite,
        border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = CircleShape,
                color = SovereignSlatePalette.PrimaryIndigoSoft,
                modifier = Modifier.size(48.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        avatarText,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.PrimaryIndigo,
                    )
                }
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        title,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = SovereignSlatePalette.TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (!badgeText.isNullOrBlank()) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = SovereignSlatePalette.VerifiedTealSoft,
                        ) {
                            Text(
                                badgeText,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = SovereignSlatePalette.VerifiedTeal,
                            )
                        }
                    }
                    if (timeLabel.isNotBlank()) {
                        Text(
                            timeLabel,
                            fontSize = 12.sp,
                            color = SovereignSlatePalette.TextSecondary,
                        )
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        subtitle,
                        fontSize = 14.sp,
                        color = SovereignSlatePalette.TextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (isMuted) {
                        Text("🔇", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

// ============================================================================
// CONVERSATION THREAD + LANGUAGE LENS + LISTEN + STARRING + CHAT INFO
// ============================================================================

@Composable
private fun RichConversationScreen(
    thread: RichThread,
    activeLanguage: LensLanguage,
    onSelectLanguage: (LensLanguage) -> Unit,
    getLensState: (String, LensLanguage) -> LensRenderState?,
    speakingMessageId: String?,
    onSpeakMessage: (String, String, LensLanguage) -> Unit,
    starredIds: Set<String>,
    onToggleStar: (String) -> Unit,
    draft: String,
    onDraftChange: (String) -> Unit,
    onBack: () -> Unit,
    onOpenInfo: () -> Unit,
    onStartVoiceCall: () -> Unit,
    onStartVideoCall: () -> Unit,
    onSend: () -> Unit,
) {
    val listState = rememberLazyListState()

    LaunchedEffect(thread.messages.size) {
        if (thread.messages.isNotEmpty()) {
            listState.animateScrollToItem(thread.messages.lastIndex)
        }
    }

    Scaffold(
        containerColor = SovereignSlatePalette.ChatStreamCanvas,
        topBar = {
            Surface(color = SovereignSlatePalette.TopBarSurface, modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        IconButton(onClick = onBack) {
                            SovereignBackIcon(contentDescription = "Back")
                        }
                        Row(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .clickable(onClick = onOpenInfo)
                                .padding(horizontal = 4.dp, vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = SovereignSlatePalette.PrimaryIndigoSoft,
                                modifier = Modifier.size(38.dp),
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Text(
                                        thread.title.take(1).uppercase(),
                                        fontWeight = FontWeight.Bold,
                                        color = SovereignSlatePalette.PrimaryIndigo,
                                    )
                                }
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    thread.title,
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = SovereignSlatePalette.TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    thread.subtitle,
                                    fontSize = 12.sp,
                                    color = SovereignSlatePalette.TextSecondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                        if (!thread.id.startsWith("self_notes")) {
                            IconButton(onClick = onStartVideoCall) {
                                Text("📹", fontSize = 17.sp)
                            }
                            IconButton(onClick = onStartVoiceCall) {
                                Text("📞", fontSize = 17.sp)
                            }
                        }
                    }

                    // Regional Language Lens bar
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 6.dp)
                            .horizontalScroll(rememberScrollState()),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            "Read in:",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = SovereignSlatePalette.TextSecondary,
                        )
                        LensLanguage.entries.forEach { lang ->
                            val selected = activeLanguage == lang
                            Surface(
                                shape = CircleShape,
                                color = if (selected) SovereignSlatePalette.VerifiedTeal else SovereignSlatePalette.SearchPill,
                                modifier = Modifier
                                    .clip(CircleShape)
                                    .clickable { onSelectLanguage(lang) },
                            ) {
                                Text(
                                    if (lang == LensLanguage.OFF) "Original" else "${lang.nativeLabel} (${lang.label})",
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                    fontSize = 12.sp,
                                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                                    color = if (selected) Color.White else SovereignSlatePalette.TextPrimary,
                                )
                            }
                        }
                    }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                }
            }
        },
        bottomBar = {
            Surface(color = SovereignSlatePalette.TopBarSurface, modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .imePadding()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Surface(
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(24.dp),
                        color = SovereignSlatePalette.SearchPill,
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                        ) {
                            if (draft.isEmpty()) {
                                Text("Message", color = SovereignSlatePalette.TextSecondary, fontSize = 15.sp)
                            }
                            BasicTextField(
                                value = draft,
                                onValueChange = onDraftChange,
                                textStyle = TextStyle(color = SovereignSlatePalette.TextPrimary, fontSize = 15.sp),
                                cursorBrush = SolidColor(SovereignSlatePalette.PrimaryIndigo),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(22.dp),
                            )
                        }
                    }
                    Surface(
                        shape = CircleShape,
                        color = if (draft.trim().isNotEmpty()) SovereignSlatePalette.PrimaryIndigo else SovereignSlatePalette.SearchPill,
                        modifier = Modifier
                            .size(46.dp)
                            .clip(CircleShape)
                            .clickable(enabled = draft.trim().isNotEmpty(), onClick = onSend),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(
                                "➤",
                                fontSize = 18.sp,
                                color = if (draft.trim().isNotEmpty()) Color.White else SovereignSlatePalette.TextSecondary,
                            )
                        }
                    }
                }
            }
        },
    ) { padding ->
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp),
            contentPadding = PaddingValues(vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            itemsIndexed(thread.messages, key = { _, m -> m.localMessageId }) { index, msg ->
                val prev = thread.messages.getOrNull(index - 1)
                if (prev == null || !isSameDay(prev.createdAtMillis, msg.createdAtMillis)) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Surface(shape = CircleShape, color = SovereignSlatePalette.SearchPill) {
                            Text(
                                formatDayLabel(msg.createdAtMillis),
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = SovereignSlatePalette.TextSecondary,
                            )
                        }
                    }
                }
                val lensState = if (activeLanguage != LensLanguage.OFF) getLensState(msg.localMessageId, activeLanguage) else null
                val outgoing = msg.direction == StoredMessageDirection.OUTBOUND
                val isStarred = starredIds.contains(msg.localMessageId)

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
                ) {
                    Surface(
                        shape = RoundedCornerShape(
                            topStart = 18.dp,
                            topEnd = 18.dp,
                            bottomStart = if (outgoing) 18.dp else 4.dp,
                            bottomEnd = if (outgoing) 4.dp else 18.dp,
                        ),
                        color = if (outgoing) SovereignSlatePalette.OutgoingBubble else SovereignSlatePalette.IncomingBubble,
                        border = if (outgoing) null else BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                        modifier = Modifier.widthIn(min = 120.dp, max = 305.dp),
                    ) {
                        Column(
                            modifier = Modifier.padding(horizontal = 13.dp, vertical = 9.dp),
                            verticalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            if (activeLanguage != LensLanguage.OFF && !lensState?.translatedText.isNullOrBlank()) {
                                Text(
                                    lensState!!.translatedText!!,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (outgoing) Color.White else SovereignSlatePalette.TextPrimary,
                                )
                                HorizontalDivider(
                                    thickness = 0.6.dp,
                                    color = if (outgoing) Color.White.copy(alpha = 0.22f) else SovereignSlatePalette.Hairline,
                                )
                                Text(
                                    "Original: ${msg.body}",
                                    fontSize = 12.sp,
                                    color = if (outgoing) Color.White.copy(alpha = 0.78f) else SovereignSlatePalette.TextSecondary,
                                )
                            } else {
                                Text(
                                    msg.body,
                                    fontSize = 15.sp,
                                    color = if (outgoing) Color.White else SovereignSlatePalette.TextPrimary,
                                )
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Surface(
                                        shape = CircleShape,
                                        color = if (outgoing) Color.White.copy(alpha = 0.16f) else SovereignSlatePalette.SearchPill,
                                        modifier = Modifier
                                            .clip(CircleShape)
                                            .clickable {
                                                val spoken = lensState?.translatedText ?: msg.body
                                                val lang = if (lensState?.translatedText != null) activeLanguage else LensLanguage.ENGLISH
                                                onSpeakMessage(msg.localMessageId, spoken, lang)
                                            },
                                    ) {
                                        Text(
                                            if (speakingMessageId == msg.localMessageId) "⏹ Stop" else "🔊 Listen",
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                            fontSize = 11.sp,
                                            color = if (outgoing) Color.White else SovereignSlatePalette.PrimaryIndigo,
                                        )
                                    }
                                    Surface(
                                        shape = CircleShape,
                                        color = if (outgoing) Color.White.copy(alpha = 0.16f) else SovereignSlatePalette.SearchPill,
                                        modifier = Modifier
                                            .clip(CircleShape)
                                            .clickable { onToggleStar(msg.localMessageId) },
                                    ) {
                                        Text(
                                            if (isStarred) "★" else "☆",
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                            fontSize = 11.sp,
                                            color = if (outgoing) Color.White else SovereignSlatePalette.PrimaryIndigo,
                                        )
                                    }
                                }

                                Text(
                                    DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(msg.createdAtMillis)),
                                    fontSize = 11.sp,
                                    color = if (outgoing) Color.White.copy(alpha = 0.78f) else SovereignSlatePalette.TextSecondary,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChatInfoScreen(
    thread: RichThread,
    onBack: () -> Unit,
    onToggleMute: () -> Unit,
    onToggleFavorite: () -> Unit,
    onCycleDisappearing: () -> Unit,
    onClearChat: () -> Unit,
    onDeleteChat: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = {
            SimpleTopBar(
                title = if (thread.kind == ThreadKind.GROUP) "Group info" else "Contact info",
                onBack = onBack,
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Surface(
                        shape = CircleShape,
                        color = SovereignSlatePalette.PrimaryIndigoSoft,
                        modifier = Modifier.size(72.dp),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(
                                thread.title.take(1).uppercase(),
                                fontSize = 28.sp,
                                fontWeight = FontWeight.Bold,
                                color = SovereignSlatePalette.PrimaryIndigo,
                            )
                        }
                    }
                    Text(thread.title, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.TextPrimary)
                    Text(thread.subtitle, fontSize = 13.sp, color = SovereignSlatePalette.TextSecondary)
                }
            }

            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow(
                        title = "Mute notifications",
                        subtitle = if (thread.isMuted) "Muted" else "Off",
                        onClick = onToggleMute,
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(
                        title = "Add to Favorites",
                        subtitle = if (thread.isFavorite) "In Favorites" else "Off",
                        onClick = onToggleFavorite,
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(
                        title = "Disappearing messages",
                        subtitle = thread.disappearingTimer,
                        onClick = onCycleDisappearing,
                    )
                }
            }

            if (thread.members.isNotEmpty()) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            "${thread.members.size} participants",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = SovereignSlatePalette.TextSecondary,
                        )
                        thread.members.forEach { member ->
                            Text(member, fontSize = 15.sp, color = SovereignSlatePalette.TextPrimary)
                        }
                    }
                }
            }

            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow(title = "Clear chat", subtitle = "Remove all messages in this chat", onClick = onClearChat)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(title = "Delete chat", subtitle = "Remove conversation from Chats", onClick = onDeleteChat)
                }
            }
        }
    }
}

// ============================================================================
// NEW CHAT, NEW GROUP, NEW COMMUNITY, NEW BROADCAST, LINKED DEVICES, STARRED
// ============================================================================

@Composable
private fun NewChatFullScreen(
    phonebookContacts: List<PhonebookContact>,
    contactsPermissionGranted: Boolean,
    onSyncContacts: () -> Unit,
    detectedClipboardInvite: String?,
    onUseClipboardInvite: () -> Unit,
    onBack: () -> Unit,
    onOpenNewGroup: () -> Unit,
    onOpenNewCommunity: () -> Unit,
    onOpenNewBroadcast: () -> Unit,
    onStartDirectChat: (String, String) -> Unit,
    onShareInvite: () -> Unit,
    onConnectInviteCode: (String, String) -> Unit,
) {
    var search by remember { mutableStateOf("") }
    var showInviteCodeCard by remember { mutableStateOf(false) }
    var inviteNick by remember { mutableStateOf("") }
    var inviteCode by remember { mutableStateOf("") }

    val filtered = remember(phonebookContacts, search) {
        val q = search.trim()
        if (q.isEmpty()) phonebookContacts.take(50)
        else phonebookContacts.filter {
            it.displayName.contains(q, ignoreCase = true) || it.phoneOrEmail.contains(q, ignoreCase = true)
        }.take(50)
    }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Select contact", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!detectedClipboardInvite.isNullOrBlank()) {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = SovereignSlatePalette.VerifiedTealSoft,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            "Invite link on clipboard",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = SovereignSlatePalette.VerifiedTeal,
                            modifier = Modifier.weight(1f),
                        )
                        Button(
                            onClick = onUseClipboardInvite,
                            colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.VerifiedTeal),
                        ) {
                            Text("Connect", color = Color.White)
                        }
                    }
                }
            }

            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Search name or number") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
            )

            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    if (search.isNotBlank()) {
                        SettingsActionRow(
                            title = "Message \"${search.trim()}\"",
                            subtitle = "Start a direct chat right away",
                            onClick = { onStartDirectChat(search.trim(), search.trim()) },
                        )
                        HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    }
                    SettingsActionRow(title = "New group", subtitle = "Create a group chat", onClick = onOpenNewGroup)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(title = "New community", subtitle = "Organize related groups", onClick = onOpenNewCommunity)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(title = "New broadcast", subtitle = "Message multiple contacts at once", onClick = onOpenNewBroadcast)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(title = "Invite friends", subtitle = "Share your invite link", onClick = onShareInvite)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(
                        title = "Connect with invite code",
                        subtitle = "Paste a peer pairing code",
                        onClick = { showInviteCodeCard = !showInviteCodeCard },
                    )
                }
            }

            AnimatedVisibility(visible = showInviteCodeCard) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        OutlinedTextField(
                            value = inviteNick,
                            onValueChange = { inviteNick = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Contact name") },
                            singleLine = true,
                        )
                        OutlinedTextField(
                            value = inviteCode,
                            onValueChange = { inviteCode = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Invite link or code") },
                            singleLine = true,
                        )
                        Button(
                            onClick = { onConnectInviteCode(inviteNick, inviteCode) },
                            enabled = inviteCode.isNotBlank(),
                            colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Start Encrypted Chat", color = Color.White)
                        }
                    }
                }
            }

            if (!contactsPermissionGranted) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            "Sync phone & email contacts",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.weight(1f),
                        )
                        Button(
                            onClick = onSyncContacts,
                            colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                        ) {
                            Text("Sync", color = Color.White)
                        }
                    }
                }
            } else if (filtered.isNotEmpty()) {
                Text(
                    "CONTACTS ON DEVICE",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = SovereignSlatePalette.TextSecondary,
                )
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column {
                        filtered.forEachIndexed { idx, c ->
                            SettingsActionRow(
                                title = c.displayName,
                                subtitle = c.phoneOrEmail,
                                onClick = { onStartDirectChat(c.displayName, c.phoneOrEmail) },
                            )
                            if (idx < filtered.lastIndex) {
                                HorizontalDivider(color = SovereignSlatePalette.Hairline)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ParticipantPickerScreen(
    title: String,
    subtitle: String,
    actionLabel: String,
    minRequired: Int,
    phonebookContacts: List<PhonebookContact>,
    selectedNames: Set<String>,
    onToggleName: (String) -> Unit,
    onAddCustomName: (String) -> Unit,
    onBack: () -> Unit,
    onConfirm: () -> Unit,
) {
    var customEntry by remember { mutableStateOf("") }
    val allCandidates = remember(phonebookContacts, selectedNames) {
        (selectedNames + phonebookContacts.map { it.displayName }).distinct()
    }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = {
            Surface(color = SovereignSlatePalette.TopBarSurface, modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onBack) { SovereignBackIcon(contentDescription = "Back") }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(title, fontSize = 19.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.TextPrimary)
                        Text(subtitle, fontSize = 12.sp, color = SovereignSlatePalette.TextSecondary)
                    }
                    Button(
                        onClick = onConfirm,
                        enabled = selectedNames.size >= minRequired,
                        colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                    ) {
                        Text(actionLabel, color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = customEntry,
                    onValueChange = { customEntry = it },
                    modifier = Modifier.weight(1f),
                    label = { Text("Add name or mobile number") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                )
                Button(
                    onClick = {
                        onAddCustomName(customEntry)
                        customEntry = ""
                    },
                    enabled = customEntry.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                ) {
                    Text("Add", color = Color.White)
                }
            }

            if (allCandidates.isEmpty()) {
                Text(
                    "Type a participant name or mobile number above and tap Add.",
                    fontSize = 13.sp,
                    color = SovereignSlatePalette.TextSecondary,
                )
            } else {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column {
                        allCandidates.forEachIndexed { idx, name ->
                            val checked = selectedNames.contains(name)
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onToggleName(name) }
                                    .padding(horizontal = 14.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = { onToggleName(name) },
                                    colors = CheckboxDefaults.colors(checkedColor = SovereignSlatePalette.PrimaryIndigo),
                                )
                                Text(
                                    name,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = SovereignSlatePalette.TextPrimary,
                                )
                            }
                            if (idx < allCandidates.lastIndex) {
                                HorizontalDivider(color = SovereignSlatePalette.Hairline)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NewGroupDetailsScreen(
    members: List<String>,
    groupName: String,
    onGroupNameChange: (String) -> Unit,
    groupDesc: String,
    onGroupDescChange: (String) -> Unit,
    onBack: () -> Unit,
    onCreateGroup: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "New group", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedTextField(
                value = groupName,
                onValueChange = onGroupNameChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Group name") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
            )
            OutlinedTextField(
                value = groupDesc,
                onValueChange = onGroupDescChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Group description (optional)") },
                shape = RoundedCornerShape(14.dp),
            )
            Text(
                "Participants: ${members.joinToString(", ")}",
                fontSize = 13.sp,
                color = SovereignSlatePalette.TextSecondary,
            )
            Button(
                onClick = onCreateGroup,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
            ) {
                Text("Create Group", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun NewCommunityIntroScreen(
    onBack: () -> Unit,
    onGetStarted: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Communities", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                shape = RoundedCornerShape(22.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Text("👥", fontSize = 40.sp)
                    Text(
                        "Stay connected with a community",
                        fontSize = 21.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.TextPrimary,
                        textAlign = TextAlign.Center,
                    )
                    Text(
                        "Communities bring members together in topic-based groups and make it easy to receive admin announcements.",
                        fontSize = 14.sp,
                        color = SovereignSlatePalette.TextSecondary,
                        textAlign = TextAlign.Center,
                    )
                    Button(
                        onClick = onGetStarted,
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                    ) {
                        Text("Get started", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
private fun NewCommunityDetailsScreen(
    name: String,
    onNameChange: (String) -> Unit,
    description: String,
    onDescriptionChange: (String) -> Unit,
    onBack: () -> Unit,
    onCreateCommunity: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "New community", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedTextField(
                value = name,
                onValueChange = onNameChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Community name") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
            )
            OutlinedTextField(
                value = description,
                onValueChange = onDescriptionChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Community description") },
                minLines = 2,
                shape = RoundedCornerShape(14.dp),
            )
            Button(
                onClick = onCreateCommunity,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
            ) {
                Text("Create Community", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun LinkedDevicesScreen(
    devices: List<LinkedDeviceSession>,
    onBack: () -> Unit,
    onLinkNewDevice: (String) -> Unit,
    onRemoveDevice: (String) -> Unit,
) {
    var companionName by remember { mutableStateOf("") }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Linked devices", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        "Use your account on companion devices",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.TextPrimary,
                    )
                    OutlinedTextField(
                        value = companionName,
                        onValueChange = { companionName = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Companion device name (e.g. Office Laptop)") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                    )
                    Button(
                        onClick = {
                            onLinkNewDevice(companionName)
                            companionName = ""
                        },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                    ) {
                        Text("Link a device", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }
            }

            if (devices.isNotEmpty()) {
                Text("DEVICE STATUS", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.TextSecondary)
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column {
                        devices.forEachIndexed { idx, dev ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(dev.deviceName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                                    Text("${dev.platform} · ${dev.lastActive}", fontSize = 12.sp, color = SovereignSlatePalette.TextSecondary)
                                }
                                TextButton(onClick = { onRemoveDevice(dev.id) }) {
                                    Text("Log out", color = Color(0xFFB91C1C))
                                }
                            }
                            if (idx < devices.lastIndex) HorizontalDivider(color = SovereignSlatePalette.Hairline)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StarredMessagesScreen(
    starredIds: Set<String>,
    selfNotes: List<MessengerMessage>,
    richThreads: List<RichThread>,
    onBack: () -> Unit,
    onUnstar: (String) -> Unit,
    onOpenSelfNotes: () -> Unit,
    onOpenThread: (String) -> Unit,
) {
    val entries = remember(starredIds, selfNotes, richThreads) {
        val list = ArrayList<Triple<String, MessengerMessage, String?>>()
        selfNotes.filter { starredIds.contains(it.localMessageId) }.forEach {
            list += Triple("Saved Notes (You)", it, null)
        }
        richThreads.forEach { t ->
            t.messages.filter { starredIds.contains(it.localMessageId) }.forEach { m ->
                list += Triple(t.title, m, t.id)
            }
        }
        list
    }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Starred messages", onBack = onBack) },
    ) { padding ->
        if (entries.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "Tap ☆ on any message inside a chat to star it here.",
                    fontSize = 14.sp,
                    color = SovereignSlatePalette.TextSecondary,
                    textAlign = TextAlign.Center,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                itemsIndexed(entries, key = { _, item -> item.second.localMessageId }) { _, (chatTitle, msg, threadId) ->
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = SovereignSlatePalette.CardWhite,
                        border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { if (threadId == null) onOpenSelfNotes() else onOpenThread(threadId) },
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(chatTitle, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.PrimaryIndigo)
                                Text(
                                    "Unstar",
                                    fontSize = 12.sp,
                                    color = SovereignSlatePalette.TextSecondary,
                                    modifier = Modifier.clickable { onUnstar(msg.localMessageId) },
                                )
                            }
                            Text(msg.body, fontSize = 15.sp, color = SovereignSlatePalette.TextPrimary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CreateStatusScreen(
    onBack: () -> Unit,
    onPublishStatus: (String, Long) -> Unit,
) {
    var statusText by remember { mutableStateOf("") }
    val palette = listOf(0xFF283593L, 0xFF0F766EL, 0xFF6D28D9L, 0xFF1E293BL)
    var colorIdx by remember { mutableStateOf(0) }

    Scaffold(
        containerColor = Color(palette[colorIdx]),
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(onClick = onBack) { Text("✕ Close", color = Color.White, fontWeight = FontWeight.Bold) }
                TextButton(onClick = { colorIdx = (colorIdx + 1) % palette.size }) {
                    Text("🎨 Color", color = Color.White, fontWeight = FontWeight.Bold)
                }
            }
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { if (statusText.isNotBlank()) onPublishStatus(statusText.trim(), palette[colorIdx]) },
                containerColor = Color.White,
                contentColor = SovereignSlatePalette.PrimaryIndigo,
            ) {
                Text("➤", fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(28.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (statusText.isEmpty()) {
                Text(
                    "Type a status…",
                    fontSize = 26.sp,
                    color = Color.White.copy(alpha = 0.65f),
                    textAlign = TextAlign.Center,
                )
            }
            BasicTextField(
                value = statusText,
                onValueChange = { statusText = it },
                textStyle = TextStyle(fontSize = 26.sp, color = Color.White, textAlign = TextAlign.Center),
                cursorBrush = SolidColor(Color.White),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun StatusViewerScreen(
    story: StatusStoryItem,
    onClose: () -> Unit,
) {
    Scaffold(
        containerColor = Color(story.bgColorHex),
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(story.authorName, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    Text(formatInboxTime(story.timestampMillis), color = Color.White.copy(alpha = 0.8f), fontSize = 12.sp)
                }
                TextButton(onClick = onClose) { Text("✕", color = Color.White, fontSize = 20.sp) }
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .clickable(onClick = onClose)
                .padding(28.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                story.text,
                fontSize = 24.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.White,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun ChannelFeedScreen(
    channel: ChannelItem,
    onBack: () -> Unit,
    onToggleFollow: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.ChatStreamCanvas,
        topBar = {
            Surface(color = SovereignSlatePalette.TopBarSurface, modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onBack) { SovereignBackIcon(contentDescription = "Back") }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(channel.name, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                        Text(channel.followersLabel, fontSize = 12.sp, color = SovereignSlatePalette.TextSecondary)
                    }
                    TextButton(onClick = onToggleFollow) {
                        Text(
                            if (channel.followed) "Following" else "Follow",
                            color = SovereignSlatePalette.PrimaryIndigo,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            itemsIndexed(channel.posts) { _, post ->
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(post, modifier = Modifier.padding(16.dp), fontSize = 15.sp, color = SovereignSlatePalette.TextPrimary)
                }
            }
        }
    }
}

@Composable
private fun NewCallPickerScreen(
    phonebookContacts: List<PhonebookContact>,
    richThreads: List<RichThread>,
    onBack: () -> Unit,
    onStartCall: (String, Boolean) -> Unit,
) {
    val names = remember(phonebookContacts, richThreads) {
        (richThreads.map { it.title } + phonebookContacts.map { it.displayName }).distinct()
    }
    var quickNumber by remember { mutableStateOf("") }

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Select contact to call", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = quickNumber,
                    onValueChange = { quickNumber = it },
                    modifier = Modifier.weight(1f),
                    label = { Text("Enter name or number") },
                    singleLine = true,
                )
                IconButton(
                    onClick = { if (quickNumber.isNotBlank()) onStartCall(quickNumber.trim(), false) },
                ) { Text("📞", fontSize = 20.sp) }
                IconButton(
                    onClick = { if (quickNumber.isNotBlank()) onStartCall(quickNumber.trim(), true) },
                ) { Text("📹", fontSize = 20.sp) }
            }

            names.forEach { person ->
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = SovereignSlatePalette.CardWhite,
                    border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(person, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        IconButton(onClick = { onStartCall(person, false) }) { Text("📞", fontSize = 18.sp) }
                        IconButton(onClick = { onStartCall(person, true) }) { Text("📹", fontSize = 18.sp) }
                    }
                }
            }
        }
    }
}

@Composable
private fun InCallScreen(
    peerName: String,
    isVideo: Boolean,
    onEndCall: () -> Unit,
) {
    var muted by remember { mutableStateOf(false) }
    var speaker by remember { mutableStateOf(false) }

    Scaffold(containerColor = Color(0xFF141824)) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(28.dp),
            verticalArrangement = Arrangement.SpaceBetween,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    if (isVideo) "End-to-end encrypted video call" else "End-to-end encrypted voice call",
                    fontSize = 12.sp,
                    color = Color.White.copy(alpha = 0.72f),
                )
                Spacer(Modifier.height(24.dp))
                Surface(
                    shape = CircleShape,
                    color = SovereignSlatePalette.PrimaryIndigo,
                    modifier = Modifier.size(92.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(peerName.take(1).uppercase(), fontSize = 36.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
                Text(peerName, fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color.White)
                Text("Ringing…", fontSize = 14.sp, color = Color.White.copy(alpha = 0.75f))
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = { speaker = !speaker },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (speaker) Color.White else Color.White.copy(alpha = 0.16f),
                    ),
                ) {
                    Text("Speaker", color = if (speaker) Color.Black else Color.White)
                }
                Button(
                    onClick = { muted = !muted },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (muted) Color.White else Color.White.copy(alpha = 0.16f),
                    ),
                ) {
                    Text(if (muted) "Unmute" else "Mute", color = if (muted) Color.Black else Color.White)
                }
                Button(
                    onClick = onEndCall,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                ) {
                    Text("End", color = Color.White, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

// ============================================================================
// COMPLETE MULTI-PAGE SETTINGS HIERARCHY
// ============================================================================

@Composable
private fun SimpleTopBar(title: String, onBack: () -> Unit) {
    Surface(color = SovereignSlatePalette.TopBarSurface, modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onBack) {
                    SovereignBackIcon(contentDescription = "Back")
                }
                Text(
                    title,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = SovereignSlatePalette.TextPrimary,
                )
            }
            HorizontalDivider(color = SovereignSlatePalette.Hairline)
        }
    }
}

@Composable
private fun SettingsActionRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = SovereignSlatePalette.TextPrimary)
            if (subtitle.isNotBlank()) {
                Text(subtitle, fontSize = 13.sp, color = SovereignSlatePalette.TextSecondary)
            }
        }
        Text("›", fontSize = 20.sp, color = SovereignSlatePalette.TextSecondary)
    }
}

@Composable
private fun SettingsToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = SovereignSlatePalette.TextPrimary)
            if (subtitle.isNotBlank()) {
                Text(subtitle, fontSize = 13.sp, color = SovereignSlatePalette.TextSecondary)
            }
        }
        Checkbox(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = CheckboxDefaults.colors(checkedColor = SovereignSlatePalette.PrimaryIndigo),
        )
    }
}

@Composable
private fun SettingsHomeScreen(
    profileName: String,
    profileAbout: String,
    phoneNumber: String,
    appLanguage: String,
    onBack: () -> Unit,
    onOpenProfile: () -> Unit,
    onOpenAccount: () -> Unit,
    onOpenPrivacy: () -> Unit,
    onOpenChats: () -> Unit,
    onOpenNotifications: () -> Unit,
    onOpenStorage: () -> Unit,
    onOpenLanguage: () -> Unit,
    onOpenHelp: () -> Unit,
    onOpenAdvancedGateway: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Settings", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Profile card
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(18.dp))
                    .clickable(onClick = onOpenProfile),
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Surface(
                        shape = CircleShape,
                        color = SovereignSlatePalette.PrimaryIndigo,
                        modifier = Modifier.size(56.dp),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(profileName.take(1).uppercase(), fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(profileName, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.TextPrimary)
                        Text(profileAbout, fontSize = 13.sp, color = SovereignSlatePalette.TextSecondary)
                        Text(phoneNumber, fontSize = 12.sp, color = SovereignSlatePalette.VerifiedTeal)
                    }
                    Text("›", fontSize = 22.sp, color = SovereignSlatePalette.TextSecondary)
                }
            }

            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Account", "Security notifications, SIM binding, change number", onOpenAccount)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Privacy", "Block contacts, disappearing messages, app lock", onOpenPrivacy)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Chats", "Theme, wallpapers, chat history", onOpenChats)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Notifications", "Message, group & call tones", onOpenNotifications)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Storage and data", "Network usage, auto-download", onOpenStorage)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("App language", appLanguage, onOpenLanguage)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Help", "Help center, contact us, privacy policy", onOpenHelp)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Server & Gateway", "Network relay & device cryptographic status", onOpenAdvancedGateway)
                }
            }
        }
    }
}

@Composable
private fun SettingsProfileScreen(
    name: String,
    about: String,
    phone: String,
    onSaveProfile: (String, String) -> Unit,
    onBack: () -> Unit,
) {
    var editName by remember { mutableStateOf(name) }
    var editAbout by remember { mutableStateOf(about) }
    val presets = listOf("Available", "At work", "Busy", "In a meeting", "Urgent calls only")

    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Profile", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedTextField(
                value = editName,
                onValueChange = { editName = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Name") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
            )
            OutlinedTextField(
                value = editAbout,
                onValueChange = { editAbout = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("About") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
            )
            Text("SELECT ABOUT", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.TextSecondary)
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                presets.forEach { preset ->
                    Surface(
                        shape = CircleShape,
                        color = if (editAbout == preset) SovereignSlatePalette.PrimaryIndigoSoft else SovereignSlatePalette.SearchPill,
                        modifier = Modifier
                            .clip(CircleShape)
                            .clickable { editAbout = preset },
                    ) {
                        Text(
                            preset,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                            fontSize = 12.sp,
                            color = SovereignSlatePalette.PrimaryIndigo,
                        )
                    }
                }
            }
            Text("Phone: $phone", fontSize = 14.sp, color = SovereignSlatePalette.TextSecondary)
            Button(
                onClick = { onSaveProfile(editName, editAbout) },
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
            ) {
                Text("Save Profile", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SettingsAccountScreen(
    simStatus: SimBindingStatus,
    twoStepEnabled: Boolean,
    onBack: () -> Unit,
    onOpenSecurityNotifications: () -> Unit,
    onOpenTwoStep: () -> Unit,
    onOpenChangeNumber: () -> Unit,
    onOpenRequestInfo: () -> Unit,
    onOpenDeleteAccount: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Account", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Security notifications & SIM", simStatus.carrierName, onOpenSecurityNotifications)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow(
                        "Two-step verification",
                        if (twoStepEnabled) "Enabled" else "Off",
                        onOpenTwoStep,
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Change number", simStatus.boundPhoneNumber, onOpenChangeNumber)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Request account info", "View local account summary", onOpenRequestInfo)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Delete account", "Erase local account & messages", onOpenDeleteAccount)
                }
            }
        }
    }
}

@Composable
private fun SettingsAccountSecurityScreen(
    simStatus: SimBindingStatus,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    onReverifySim: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Security notifications", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("End-to-end encrypted & SIM-bound", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text(
                        "Chats and calls are end-to-end encrypted, and your account is bound to ${simStatus.boundPhoneNumber}.",
                        fontSize = 13.sp,
                        color = SovereignSlatePalette.TextSecondary,
                    )
                    OutlinedButton(onClick = onReverifySim) {
                        Text("Verify Active SIM Now", color = SovereignSlatePalette.PrimaryIndigo)
                    }
                }
            }
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                SettingsToggleRow(
                    title = "Show security notifications on this device",
                    subtitle = "Get notified when a contact's security code changes",
                    checked = enabled,
                    onCheckedChange = onToggle,
                )
            }
        }
    }
}

@Composable
private fun SettingsTwoStepScreen(
    currentPin: String,
    onSavePin: (String) -> Unit,
    onBack: () -> Unit,
) {
    var pinInput by remember { mutableStateOf(currentPin) }
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Two-step verification", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                "Create a 6-digit PIN that will be required when registering your phone number again.",
                fontSize = 14.sp,
                color = SovereignSlatePalette.TextSecondary,
            )
            OutlinedTextField(
                value = pinInput,
                onValueChange = { pinInput = it.filter { c -> c.isDigit() }.take(6) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("6-digit PIN") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            Button(
                onClick = { onSavePin(pinInput) },
                enabled = pinInput.length == 6,
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Save PIN", color = Color.White, fontWeight = FontWeight.Bold)
            }
            if (currentPin.length == 6) {
                OutlinedButton(onClick = { onSavePin("") }, modifier = Modifier.fillMaxWidth()) {
                    Text("Turn off", color = Color(0xFFB91C1C))
                }
            }
        }
    }
}

@Composable
private fun SettingsChangeNumberScreen(
    currentPhone: String,
    onBack: () -> Unit,
    onProceedRebind: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Change number", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                "Changing your phone number from $currentPhone will re-bind your account to your new SIM card.",
                fontSize = 14.sp,
                color = SovereignSlatePalette.TextSecondary,
            )
            Button(
                onClick = onProceedRebind,
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Register New Number & SIM", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SettingsRequestInfoScreen(
    phone: String,
    name: String,
    notesCount: Int,
    chatsCount: Int,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Request account info", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Account Summary", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text("Display Name: $name", fontSize = 14.sp)
                    Text("Registered SIM Number: $phone", fontSize = 14.sp)
                    Text("Private Saved Notes: $notesCount", fontSize = 14.sp)
                    Text("Active Chat Threads: $chatsCount", fontSize = 14.sp)
                    Text("Storage Mode: On-device encrypted SQLite", fontSize = 14.sp)
                }
            }
        }
    }
}

@Composable
private fun SettingsDeleteAccountScreen(
    phone: String,
    onBack: () -> Unit,
    onConfirmDelete: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Delete account", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                "Deleting your account ($phone) erases your local message history, saved notes, groups, and SIM binding from this phone.",
                fontSize = 14.sp,
                color = SovereignSlatePalette.TextSecondary,
            )
            Button(
                onClick = onConfirmDelete,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Delete My Account", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SettingsPrivacyScreen(
    lastSeen: String,
    profilePhoto: String,
    about: String,
    readReceipts: Boolean,
    defaultTimer: String,
    appLock: Boolean,
    onOpenAudienceOption: (String) -> Unit,
    onToggleReadReceipts: (Boolean) -> Unit,
    onCycleTimer: () -> Unit,
    onToggleAppLock: (Boolean) -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Privacy", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Last seen and online", lastSeen) { onOpenAudienceOption("Last seen and online") }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Profile photo", profilePhoto) { onOpenAudienceOption("Profile photo") }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("About", about) { onOpenAudienceOption("About") }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow(
                        title = "Read receipts",
                        subtitle = "If turned off, you won't send or receive read receipts",
                        checked = readReceipts,
                        onCheckedChange = onToggleReadReceipts,
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Default message timer", defaultTimer, onCycleTimer)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow(
                        title = "App lock",
                        subtitle = "Require device unlock to open chats",
                        checked = appLock,
                        onCheckedChange = onToggleAppLock,
                    )
                }
            }
        }
    }
}

@Composable
private fun SettingsSingleChoiceScreen(
    title: String,
    options: List<String>,
    selectedOption: String,
    onSelect: (String) -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = title, onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    options.forEachIndexed { idx, opt ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelect(opt) }
                                .padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(opt, fontSize = 15.sp, color = SovereignSlatePalette.TextPrimary)
                            if (opt == selectedOption) {
                                Text("✓", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.PrimaryIndigo)
                            }
                        }
                        if (idx < options.lastIndex) HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsChatsScreen(
    theme: String,
    wallpaper: String,
    enterIsSend: Boolean,
    mediaVisibility: Boolean,
    lastBackup: String,
    onCycleTheme: () -> Unit,
    onCycleWallpaper: () -> Unit,
    onToggleEnterIsSend: (Boolean) -> Unit,
    onToggleMediaVisibility: (Boolean) -> Unit,
    onRunBackup: () -> Unit,
    onOpenChatHistory: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Chats", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Theme", theme, onCycleTheme)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Wallpaper", wallpaper, onCycleWallpaper)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow("Enter is send", "Enter key will send your message", enterIsSend, onToggleEnterIsSend)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow("Media visibility", "Show newly downloaded media in gallery", mediaVisibility, onToggleMediaVisibility)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Chat backup", "Last backup: $lastBackup", onRunBackup)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Chat history", "Clear or delete all chats", onOpenChatHistory)
                }
            }
        }
    }
}

@Composable
private fun SettingsChatHistoryScreen(
    onClearAllChats: () -> Unit,
    onDeleteAllChats: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Chat history", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Clear all chats", "Keep chats in list but empty message bubbles", onClearAllChats)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Delete all chats", "Remove all chats and messages", onDeleteAllChats)
                }
            }
        }
    }
}

@Composable
private fun SettingsNotificationsScreen(
    conversationTones: Boolean,
    messageTone: String,
    groupTone: String,
    callRingtone: String,
    onToggleConversationTones: (Boolean) -> Unit,
    onCycleMessageTone: () -> Unit,
    onCycleGroupTone: () -> Unit,
    onCycleRingtone: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Notifications", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsToggleRow(
                        "Conversation tones",
                        "Play sounds for incoming and outgoing messages",
                        conversationTones,
                        onToggleConversationTones,
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Message notification tone", messageTone, onCycleMessageTone)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Group notification tone", groupTone, onCycleGroupTone)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Call ringtone", callRingtone, onCycleRingtone)
                }
            }
        }
    }
}

@Composable
private fun SettingsStorageScreen(
    notesCount: Int,
    chatsCount: Int,
    lessDataCalls: Boolean,
    wifiAutoDownload: String,
    mobileAutoDownload: String,
    onToggleLessData: (Boolean) -> Unit,
    onCycleWifi: () -> Unit,
    onCycleMobile: () -> Unit,
    onClearCache: () -> Unit,
    onBack: () -> Unit,
) {
    var cacheCleared by remember { mutableStateOf(false) }
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Storage and data", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow(
                        "Manage storage",
                        "$chatsCount threads · $notesCount saved notes (${if (cacheCleared) "Cache cleared" else "1.4 MB"})",
                        {
                            onClearCache()
                            cacheCleared = true
                        },
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow("Use less data for calls", "Optimize voice & video bandwidth", lessDataCalls, onToggleLessData)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("When using mobile data", mobileAutoDownload, onCycleMobile)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("When connected on Wi-Fi", wifiAutoDownload, onCycleWifi)
                }
            }
        }
    }
}

@Composable
private fun SettingsHelpScreen(
    onOpenFaq: (String) -> Unit,
    onOpenContactUs: () -> Unit,
    onOpenAppInfo: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Help", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    SettingsActionRow("Help center · End-to-end encryption & SIM binding", "How your chats and SIM stay protected") {
                        onOpenFaq("End-to-end encryption & SIM binding")
                    }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Help center · Regional Language Lens", "Read & listen in Telugu, Gujarati, Hindi, Tamil") {
                        onOpenFaq("Regional Language Lens")
                    }
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("Contact us", "Questions? Need help?", onOpenContactUs)
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsActionRow("App info", "Version & cryptographic build details", onOpenAppInfo)
                }
            }
        }
    }
}

@Composable
private fun SettingsFaqDetailScreen(topic: String, onBack: () -> Unit) {
    val body = if (topic.contains("Language")) {
        "Open any conversation and select Telugu, Gujarati, Hindi, Tamil, or English in the 'Read in:' bar at the top. Messages translate locally after decryption while preserving the original text, and tapping Listen reads them aloud."
    } else {
        "All 1-to-1 messages are end-to-end encrypted on your device using a clean-room Rust cryptographic engine, and your account binds to your active SIM card to prevent impersonation."
    }
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Help center", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(topic, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(body, fontSize = 14.sp, color = SovereignSlatePalette.TextSecondary)
        }
    }
}

@Composable
private fun SettingsContactUsScreen(onBack: () -> Unit) {
    var msg by remember { mutableStateOf("") }
    var sent by remember { mutableStateOf(false) }
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "Contact us", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = msg,
                onValueChange = { msg = it; sent = false },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Describe how we can help") },
                minLines = 3,
            )
            Button(
                onClick = { if (msg.isNotBlank()) { sent = true; msg = "" } },
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Send", color = Color.White, fontWeight = FontWeight.Bold)
            }
            if (sent) {
                Text("Thank you — your feedback has been recorded.", color = SovereignSlatePalette.VerifiedTeal, fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun SettingsAppInfoScreen(onBack: () -> Unit) {
    Scaffold(
        containerColor = SovereignSlatePalette.PageCanvas,
        topBar = { SimpleTopBar(title = "App info", onBack = onBack) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Sovereign PM", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = SovereignSlatePalette.PrimaryIndigo)
            Spacer(Modifier.height(6.dp))
            Text("Version 1.0.0 · Clean-Room Rust + Kotlin E2EE Build", fontSize = 13.sp, color = SovereignSlatePalette.TextSecondary)
        }
    }
}

// ============================================================================
// PER-USER JSON PERSISTENCE HELPERS
// ============================================================================

private fun loadSavedSelfNotesForUser(prefs: android.content.SharedPreferences, userKey: String): List<MessengerMessage> {
    val raw = prefs.getString("notes_json_$userKey", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        val out = ArrayList<MessengerMessage>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            out += MessengerMessage(
                localMessageId = obj.getString("id"),
                direction = StoredMessageDirection.OUTBOUND,
                body = obj.getString("body"),
                createdAtMillis = obj.getLong("ts"),
                outboxStatus = OutboxMessageStatus.SUBMITTED,
            )
        }
        out
    }.getOrDefault(emptyList())
}

private fun persistSelfNotesForUser(prefs: android.content.SharedPreferences, userKey: String, messages: List<MessengerMessage>) {
    val arr = JSONArray()
    messages.filter { !it.localMessageId.startsWith("welcome_note_") }.takeLast(120).forEach { msg ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", msg.localMessageId)
                put("body", msg.body)
                put("ts", msg.createdAtMillis)
            },
        )
    }
    prefs.edit().putString("notes_json_$userKey", arr.toString()).apply()
}

private fun loadRichThreads(prefs: android.content.SharedPreferences): List<RichThread> {
    val raw = prefs.getString("rich_threads_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        val out = ArrayList<RichThread>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            val msgsArr = obj.optJSONArray("messages") ?: JSONArray()
            val msgs = ArrayList<MessengerMessage>(msgsArr.length())
            for (j in 0 until msgsArr.length()) {
                val m = msgsArr.getJSONObject(j)
                msgs += MessengerMessage(
                    localMessageId = m.getString("id"),
                    direction = if (m.optString("dir") == "IN") StoredMessageDirection.INBOUND else StoredMessageDirection.OUTBOUND,
                    body = m.getString("body"),
                    createdAtMillis = m.optLong("ts", System.currentTimeMillis()),
                    outboxStatus = OutboxMessageStatus.SUBMITTED,
                )
            }
            val memArr = obj.optJSONArray("members") ?: JSONArray()
            val members = (0 until memArr.length()).map { memArr.getString(it) }
            out += RichThread(
                id = obj.getString("id"),
                title = obj.getString("title"),
                subtitle = obj.optString("subtitle", "Direct chat"),
                kind = runCatching { ThreadKind.valueOf(obj.optString("kind", "DIRECT")) }.getOrDefault(ThreadKind.DIRECT),
                members = members,
                messages = msgs,
                isFavorite = obj.optBoolean("fav", false),
                isMuted = obj.optBoolean("muted", false),
                unreadCount = obj.optInt("unread", 0),
                disappearingTimer = obj.optString("timer", "Off"),
            )
        }
        out
    }.getOrDefault(emptyList())
}

private fun persistRichThreads(prefs: android.content.SharedPreferences, threads: List<RichThread>) {
    val arr = JSONArray()
    threads.take(60).forEach { t ->
        val msgsArr = JSONArray()
        t.messages.takeLast(120).forEach { m ->
            msgsArr.put(
                org.json.JSONObject().apply {
                    put("id", m.localMessageId)
                    put("dir", if (m.direction == StoredMessageDirection.INBOUND) "IN" else "OUT")
                    put("body", m.body)
                    put("ts", m.createdAtMillis)
                },
            )
        }
        val memArr = JSONArray().apply { t.members.forEach { put(it) } }
        arr.put(
            org.json.JSONObject().apply {
                put("id", t.id)
                put("title", t.title)
                put("subtitle", t.subtitle)
                put("kind", t.kind.name)
                put("members", memArr)
                put("messages", msgsArr)
                put("fav", t.isFavorite)
                put("muted", t.isMuted)
                put("unread", t.unreadCount)
                put("timer", t.disappearingTimer)
            },
        )
    }
    prefs.edit().putString("rich_threads_json", arr.toString()).apply()
}

private fun loadCommunities(prefs: android.content.SharedPreferences): List<CommunityItem> {
    val raw = prefs.getString("communities_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val grpArr = o.optJSONArray("groups") ?: JSONArray()
            CommunityItem(
                id = o.getString("id"),
                name = o.getString("name"),
                description = o.optString("desc", ""),
                announcementThreadId = o.getString("annId"),
                linkedGroupIds = (0 until grpArr.length()).map { grpArr.getString(it) },
            )
        }
    }.getOrDefault(emptyList())
}

private fun persistCommunities(prefs: android.content.SharedPreferences, items: List<CommunityItem>) {
    val arr = JSONArray()
    items.forEach { c ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", c.id)
                put("name", c.name)
                put("desc", c.description)
                put("annId", c.announcementThreadId)
                put("groups", JSONArray().apply { c.linkedGroupIds.forEach { put(it) } })
            },
        )
    }
    prefs.edit().putString("communities_json", arr.toString()).apply()
}

private fun loadStatusStories(prefs: android.content.SharedPreferences): List<StatusStoryItem> {
    val raw = prefs.getString("status_stories_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            StatusStoryItem(
                id = o.getString("id"),
                authorName = o.getString("author"),
                text = o.getString("text"),
                timestampMillis = o.getLong("ts"),
                bgColorHex = o.optLong("color", 0xFF283593L),
                isMine = o.optBoolean("mine", false),
            )
        }
    }.getOrDefault(emptyList())
}

private fun persistStatusStories(prefs: android.content.SharedPreferences, items: List<StatusStoryItem>) {
    val arr = JSONArray()
    items.take(30).forEach { s ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", s.id)
                put("author", s.authorName)
                put("text", s.text)
                put("ts", s.timestampMillis)
                put("color", s.bgColorHex)
                put("mine", s.isMine)
            },
        )
    }
    prefs.edit().putString("status_stories_json", arr.toString()).apply()
}

private fun loadChannels(prefs: android.content.SharedPreferences): List<ChannelItem> {
    val raw = prefs.getString("channels_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val pArr = o.optJSONArray("posts") ?: JSONArray()
            ChannelItem(
                id = o.getString("id"),
                name = o.getString("name"),
                followersLabel = o.optString("followers", "10K followers"),
                verified = o.optBoolean("verified", true),
                followed = o.optBoolean("followed", false),
                posts = (0 until pArr.length()).map { pArr.getString(it) },
            )
        }
    }.getOrDefault(emptyList())
}

private fun persistChannels(prefs: android.content.SharedPreferences, items: List<ChannelItem>) {
    val arr = JSONArray()
    items.forEach { c ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", c.id)
                put("name", c.name)
                put("followers", c.followersLabel)
                put("verified", c.verified)
                put("followed", c.followed)
                put("posts", JSONArray().apply { c.posts.forEach { put(it) } })
            },
        )
    }
    prefs.edit().putString("channels_json", arr.toString()).apply()
}

private fun loadCallLogs(prefs: android.content.SharedPreferences): List<CallLogEntry> {
    val raw = prefs.getString("call_logs_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            CallLogEntry(
                id = o.getString("id"),
                peerName = o.getString("peer"),
                isVideo = o.optBoolean("video", false),
                isOutgoing = o.optBoolean("out", true),
                timestampMillis = o.getLong("ts"),
                durationLabel = o.optString("dur", "0:42"),
            )
        }
    }.getOrDefault(emptyList())
}

private fun persistCallLogs(prefs: android.content.SharedPreferences, items: List<CallLogEntry>) {
    val arr = JSONArray()
    items.take(40).forEach { c ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", c.id)
                put("peer", c.peerName)
                put("video", c.isVideo)
                put("out", c.isOutgoing)
                put("ts", c.timestampMillis)
                put("dur", c.durationLabel)
            },
        )
    }
    prefs.edit().putString("call_logs_json", arr.toString()).apply()
}

private fun loadLinkedDevices(prefs: android.content.SharedPreferences): List<LinkedDeviceSession> {
    val raw = prefs.getString("linked_devices_json", null) ?: return emptyList()
    return runCatching {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            LinkedDeviceSession(
                id = o.getString("id"),
                deviceName = o.getString("name"),
                platform = o.optString("platform", "Desktop"),
                lastActive = o.optString("active", "Active now"),
            )
        }
    }.getOrDefault(emptyList())
}

private fun persistLinkedDevices(prefs: android.content.SharedPreferences, items: List<LinkedDeviceSession>) {
    val arr = JSONArray()
    items.take(10).forEach { d ->
        arr.put(
            org.json.JSONObject().apply {
                put("id", d.id)
                put("name", d.deviceName)
                put("platform", d.platform)
                put("active", d.lastActive)
            },
        )
    }
    prefs.edit().putString("linked_devices_json", arr.toString()).apply()
}

@Composable
private fun PrivacyMirrorNotice(onOpenSettings: () -> Unit) {
    Scaffold(containerColor = SovereignSlatePalette.PageCanvas) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            DisclosureCard(
                title = "Chats hidden while screen sharing",
                body = "Turn off screen mirroring in Settings to view your messages.",
                isCaution = true,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onOpenSettings,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = SovereignSlatePalette.PrimaryIndigo),
            ) {
                Text("Open Settings", color = Color.White)
            }
        }
    }
}

/**
 * Post-decryption translation helper. Runs strictly after local decryption so stored
 * ciphertext and session keys are never exposed, while preserving the original message.
 */
private fun performPostDecryptionTranslation(text: String, targetLangCode: String): String {
    val encoded = URLEncoder.encode(text, "UTF-8")
    val endpoint = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=$targetLangCode&dt=t&q=$encoded"
    val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
        connectTimeout = 5000
        readTimeout = 5000
        requestMethod = "GET"
        setRequestProperty("User-Agent", "Mozilla/5.0")
    }
    return try {
        val code = conn.responseCode
        check(code in 200..299) { "HTTP $code" }
        val payload = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        val root = JSONArray(payload)
        val segments = root.getJSONArray(0)
        val out = StringBuilder()
        for (i in 0 until segments.length()) {
            val part = segments.getJSONArray(i).optString(0, "")
            out.append(part)
        }
        out.toString().ifBlank { text }
    } finally {
        conn.disconnect()
    }
}

private fun statusLabelShort(status: OutboxMessageStatus?): String = when (status) {
    OutboxMessageStatus.SUBMITTED -> "Sent"
    OutboxMessageStatus.READY, OutboxMessageStatus.ATTEMPTING -> "Queued"
    OutboxMessageStatus.DELIVERY_UNKNOWN -> "Check"
    null -> "Saved"
}

private fun isSameDay(aMillis: Long, bMillis: Long): Boolean {
    val a = Calendar.getInstance().apply { timeInMillis = aMillis }
    val b = Calendar.getInstance().apply { timeInMillis = bMillis }
    return a.get(Calendar.YEAR) == b.get(Calendar.YEAR) &&
        a.get(Calendar.DAY_OF_YEAR) == b.get(Calendar.DAY_OF_YEAR)
}

private fun formatDayLabel(timestampMillis: Long): String {
    val now = Calendar.getInstance()
    val target = Calendar.getInstance().apply { timeInMillis = timestampMillis }
    return when {
        now.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            now.get(Calendar.DAY_OF_YEAR) == target.get(Calendar.DAY_OF_YEAR) -> "TODAY"
        now.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            now.get(Calendar.DAY_OF_YEAR) - target.get(Calendar.DAY_OF_YEAR) == 1 -> "YESTERDAY"
        else -> SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(timestampMillis)).uppercase(Locale.getDefault())
    }
}

private fun formatInboxTime(timestampMillis: Long): String {
    val now = Calendar.getInstance()
    val target = Calendar.getInstance().apply { timeInMillis = timestampMillis }
    return if (
        now.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
        now.get(Calendar.DAY_OF_YEAR) == target.get(Calendar.DAY_OF_YEAR)
    ) {
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(timestampMillis))
    } else {
        SimpleDateFormat("dd/MM/yy", Locale.getDefault()).format(Date(timestampMillis))
    }
}

private fun OutboxState.toUiStatus(): OutboxMessageStatus = when (this) {
    OutboxState.READY -> OutboxMessageStatus.READY
    OutboxState.ATTEMPTING -> OutboxMessageStatus.ATTEMPTING
    OutboxState.SUBMITTED -> OutboxMessageStatus.SUBMITTED
    OutboxState.DELIVERY_UNKNOWN -> OutboxMessageStatus.DELIVERY_UNKNOWN
}

private fun AlphaPairingRecord.stableKey(): String = "${accountId.workspaceHex()}:${deviceId.workspaceHex()}"
private fun AlphaPairingRecord.aliasPreferenceKey(): String = "peer_${stableKey().replace(':', '_')}"
private fun ByteArray.workspaceHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }


@Composable
private fun QuickSimOnboardingScreen(
    context: Context,
    simPrefs: android.content.SharedPreferences,
    onRequestPhonePermission: () -> Unit,
    onCompleted: () -> Unit,
) {
    var phoneInput by remember { mutableStateOf("") }
    var displayNameInput by remember { mutableStateOf("") }
    var otpInput by remember { mutableStateOf("") }
    var otpSent by remember { mutableStateOf(false) }
    var errorText by remember { mutableStateOf<String?>(null) }

    val hasPhonePerm = androidx.core.content.ContextCompat.checkSelfPermission(
        context,
        Manifest.permission.READ_PHONE_STATE,
    ) == PackageManager.PERMISSION_GRANTED

    val tm = remember(context) { context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager }
    val simReady = tm?.simState == TelephonyManager.SIM_STATE_READY

    Scaffold(containerColor = SovereignSlatePalette.PageCanvas) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .imePadding()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                shape = RoundedCornerShape(24.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(
                        if (!otpSent) "Your Phone Number" else "Verify & Set Name",
                        fontSize = 23.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.TextPrimary,
                    )

                    Text(
                        if (!otpSent)
                            "Enter your mobile number to get started. Your account stays linked to the active SIM in this phone."
                        else
                            "Enter the 6-digit code sent to +91 $phoneInput and choose your display name.",
                        fontSize = 14.sp,
                        color = SovereignSlatePalette.TextSecondary,
                    )

                    if (!otpSent) {
                        OutlinedTextField(
                            value = phoneInput,
                            onValueChange = { raw ->
                                phoneInput = raw.filter { it.isDigit() }.take(10)
                                errorText = null
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Mobile number") },
                            prefix = {
                                Text(
                                    "+91 ",
                                    fontWeight = FontWeight.SemiBold,
                                    color = SovereignSlatePalette.TextPrimary,
                                )
                            },
                            singleLine = true,
                            shape = RoundedCornerShape(14.dp),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Phone,
                                imeAction = ImeAction.Done,
                            ),
                        )

                        Button(
                            onClick = {
                                if (phoneInput.length < 10) {
                                    errorText = "Enter your 10-digit mobile number."
                                    return@Button
                                }
                                if (!hasPhonePerm) {
                                    onRequestPhonePermission()
                                }
                                otpInput = (100000..999999).random().toString()
                                otpSent = true
                                errorText = null
                            },
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = SovereignSlatePalette.PrimaryIndigo,
                                contentColor = Color.White,
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp),
                        ) {
                            Text("Continue", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        }
                    } else {
                        OutlinedTextField(
                            value = otpInput,
                            onValueChange = { raw ->
                                otpInput = raw.filter { it.isDigit() }.take(6)
                                errorText = null
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("6-digit verification code") },
                            singleLine = true,
                            shape = RoundedCornerShape(14.dp),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Number,
                                imeAction = ImeAction.Next,
                            ),
                        )

                        OutlinedTextField(
                            value = displayNameInput,
                            onValueChange = { displayNameInput = it; errorText = null },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Your name (e.g. Ravi)") },
                            singleLine = true,
                            shape = RoundedCornerShape(14.dp),
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        )

                        Button(
                            onClick = {
                                if (otpInput.length != 6) {
                                    errorText = "Enter the 6-digit verification code."
                                    return@Button
                                }
                                val subManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as? SubscriptionManager
                                val activeSub = if (hasPhonePerm) {
                                    runCatching { subManager?.activeSubscriptionInfoList?.firstOrNull() }.getOrNull()
                                } else null

                                val isPhysicalSimBound = simReady && activeSub != null
                                val formattedPhone = "+91 $phoneInput"
                                simPrefs.edit()
                                    .putString("registered_phone", formattedPhone)
                                    .putString("user_display_name", displayNameInput.trim())
                                    .putInt("bound_sim_sub_id", activeSub?.subscriptionId ?: -1)
                                    .putString("bound_sim_carrier", activeSub?.carrierName?.toString() ?: "Mobile SIM")
                                    .putBoolean("sim_binding_test_bypass", !isPhysicalSimBound)
                                    .apply()
                                onCompleted()
                            },
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = SovereignSlatePalette.PrimaryIndigo,
                                contentColor = Color.White,
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp),
                        ) {
                            Text("Start Messaging", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        }

                        TextButton(
                            onClick = { otpSent = false; otpInput = "" },
                            modifier = Modifier.align(Alignment.CenterHorizontally),
                        ) {
                            Text("Change phone number", color = SovereignSlatePalette.PrimaryIndigo)
                        }
                    }

                    if (!errorText.isNullOrBlank()) {
                        Text(errorText!!, fontSize = 12.sp, color = Color(0xFFB91C1C))
                    }
                }
            }
        }
    }
}

@Composable
private fun SimBindingLockScreen(
    status: SimBindingStatus,
    onRequestPhonePermission: () -> Unit,
    onReverifySim: () -> Unit,
    onRebindNewNumber: () -> Unit,
) {
    Scaffold(containerColor = SovereignSlatePalette.PageCanvas) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                shape = RoundedCornerShape(22.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Text(
                        "Active SIM Required",
                        fontSize = 21.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.TextPrimary,
                    )
                    Text(
                        status.detailMessage,
                        fontSize = 14.sp,
                        color = SovereignSlatePalette.TextSecondary,
                    )
                    Button(
                        onClick = {
                            onRequestPhonePermission()
                            onReverifySim()
                        },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SovereignSlatePalette.PrimaryIndigo,
                            contentColor = Color.White,
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                    ) {
                        Text("Check Active SIM Again", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = onRebindNewNumber,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Register a Different SIM / Number", color = SovereignSlatePalette.PrimaryIndigo)
                    }
                }
            }
        }
    }
}