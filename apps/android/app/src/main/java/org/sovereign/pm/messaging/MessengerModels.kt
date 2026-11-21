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


internal enum class MessengerRoute { CHATS, ADD_CONTACT, CONVERSATION }

internal enum class BottomNavTab(val label: String, val glyph: String) {
    CHATS("Chats", "💬"),
    UPDATES("Updates", "◎"),
    COMMUNITIES("Communities", "👥"),
    CALLS("Calls", "📞"),
}

internal enum class AppScreen {
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

internal enum class ChatFilterChip(val label: String) {
    ALL("All"),
    UNREAD("Unread"),
    FAVORITES("Favorites"),
    GROUPS("Groups"),
}

internal enum class ThreadKind {
    DIRECT,
    GROUP,
    BROADCAST,
}

internal data class RichThread(
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

internal data class StatusStoryItem(
    val id: String,
    val authorName: String,
    val text: String,
    val timestampMillis: Long,
    val bgColorHex: Long,
    val isMine: Boolean = false,
)

internal data class ChannelItem(
    val id: String,
    val name: String,
    val followersLabel: String,
    val verified: Boolean,
    val followed: Boolean,
    val posts: List<String>,
)

internal data class CommunityItem(
    val id: String,
    val name: String,
    val description: String,
    val announcementThreadId: String,
    val linkedGroupIds: List<String>,
)

internal data class CallLogEntry(
    val id: String,
    val peerName: String,
    val isVideo: Boolean,
    val isOutgoing: Boolean,
    val timestampMillis: Long,
    val durationLabel: String,
)

internal data class LinkedDeviceSession(
    val id: String,
    val deviceName: String,
    val platform: String,
    val lastActive: String,
)

internal enum class LensLanguage(
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

internal data class LensRenderState(
    val loading: Boolean = false,
    val translatedText: String? = null,
    val targetLang: LensLanguage = LensLanguage.OFF,
    val error: String? = null,
)

internal data class MessengerMessage(
    val localMessageId: String,
    val direction: StoredMessageDirection,
    val body: String,
    val createdAtMillis: Long,
    val outboxStatus: OutboxMessageStatus?,
)

internal data class MessengerPeer(
    val record: AlphaPairingRecord,
    val nickname: String,
    val messages: List<MessengerMessage>,
) {
    val stableKey: String get() = "${record.accountId.workspaceHex()}:${record.deviceId.workspaceHex()}"
    val latestMessage: MessengerMessage? get() = messages.lastOrNull()
}

internal object SovereignSlatePalette {
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

internal data class PhonebookContact(
    val id: String,
    val displayName: String,
    val phoneOrEmail: String,
    val isEmail: Boolean,
    val discoveryHashHex: String,
)

internal fun sha256DiscoveryHash(normalizedValue: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(normalizedValue.toByteArray(Charsets.UTF_8))
    return digest.take(12).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

internal fun normalizeIndianPhone(raw: String): String {
    val digits = raw.filter { it.isDigit() }
    return when {
        digits.length == 10 -> "+91$digits"
        digits.length == 12 && digits.startsWith("91") -> "+$digits"
        digits.startsWith("+") -> raw.filter { it.isDigit() || it == '+' }
        else -> digits
    }
}

internal fun loadDevicePhoneAndEmailContacts(context: Context, limit: Int = 150): List<PhonebookContact> {
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

internal data class SimBindingStatus(
    val boundPhoneNumber: String,
    val boundSubscriptionId: Int,
    val carrierName: String,
    val isSimPresentAndMatching: Boolean,
    val isTestBypass: Boolean,
    val detailMessage: String,
)

internal fun evaluateSimBindingState(
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

internal fun extractInvitePayload(raw: String): String {
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

// PER-USER JSON PERSISTENCE HELPERS
// ============================================================================

internal fun loadSavedSelfNotesForUser(prefs: android.content.SharedPreferences, userKey: String): List<MessengerMessage> {
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

internal fun persistSelfNotesForUser(prefs: android.content.SharedPreferences, userKey: String, messages: List<MessengerMessage>) {
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

internal fun loadRichThreads(prefs: android.content.SharedPreferences): List<RichThread> {
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

internal fun persistRichThreads(prefs: android.content.SharedPreferences, threads: List<RichThread>) {
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

internal fun loadCommunities(prefs: android.content.SharedPreferences): List<CommunityItem> {
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

internal fun persistCommunities(prefs: android.content.SharedPreferences, items: List<CommunityItem>) {
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

internal fun loadStatusStories(prefs: android.content.SharedPreferences): List<StatusStoryItem> {
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

internal fun persistStatusStories(prefs: android.content.SharedPreferences, items: List<StatusStoryItem>) {
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

internal fun loadChannels(prefs: android.content.SharedPreferences): List<ChannelItem> {
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

internal fun persistChannels(prefs: android.content.SharedPreferences, items: List<ChannelItem>) {
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

internal fun loadCallLogs(prefs: android.content.SharedPreferences): List<CallLogEntry> {
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

internal fun persistCallLogs(prefs: android.content.SharedPreferences, items: List<CallLogEntry>) {
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

internal fun loadLinkedDevices(prefs: android.content.SharedPreferences): List<LinkedDeviceSession> {
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

internal fun persistLinkedDevices(prefs: android.content.SharedPreferences, items: List<LinkedDeviceSession>) {
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



/**
 * Post-decryption translation helper. Runs strictly after local decryption so stored
 * ciphertext and session keys are never exposed, while preserving the original message.
 */
internal fun performPostDecryptionTranslation(text: String, targetLangCode: String): String {
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

internal fun statusLabelShort(status: OutboxMessageStatus?): String = when (status) {
    OutboxMessageStatus.SUBMITTED -> "Sent"
    OutboxMessageStatus.READY, OutboxMessageStatus.ATTEMPTING -> "Queued"
    OutboxMessageStatus.DELIVERY_UNKNOWN -> "Check"
    null -> "Saved"
}

internal fun isSameDay(aMillis: Long, bMillis: Long): Boolean {
    val a = Calendar.getInstance().apply { timeInMillis = aMillis }
    val b = Calendar.getInstance().apply { timeInMillis = bMillis }
    return a.get(Calendar.YEAR) == b.get(Calendar.YEAR) &&
        a.get(Calendar.DAY_OF_YEAR) == b.get(Calendar.DAY_OF_YEAR)
}

internal fun formatDayLabel(timestampMillis: Long): String {
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

internal fun formatInboxTime(timestampMillis: Long): String {
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

internal fun OutboxState.toUiStatus(): OutboxMessageStatus = when (this) {
    OutboxState.READY -> OutboxMessageStatus.READY
    OutboxState.ATTEMPTING -> OutboxMessageStatus.ATTEMPTING
    OutboxState.SUBMITTED -> OutboxMessageStatus.SUBMITTED
    OutboxState.DELIVERY_UNKNOWN -> OutboxMessageStatus.DELIVERY_UNKNOWN
}

internal fun AlphaPairingRecord.stableKey(): String = "${accountId.workspaceHex()}:${deviceId.workspaceHex()}"
internal fun AlphaPairingRecord.aliasPreferenceKey(): String = "peer_${stableKey().replace(':', '_')}"
internal fun ByteArray.workspaceHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }



internal data class DiscoveredPeerMatch(
    val discoveryHashHex: String,
    val displayName: String,
    val pairingCode: String?,
    val isLocalEmulatorAccount: Boolean = false,
)

internal fun publishLocalDirectoryEntry(
    context: Context,
    phoneNumber: String,
    displayName: String,
    pairingCode: String,
) {
    val normalized = normalizeIndianPhone(phoneNumber)
    if (normalized.isBlank()) return
    val hash = sha256DiscoveryHash(normalized)
    val prefs = context.getSharedPreferences("pm-local-directory-v1", Context.MODE_PRIVATE)
    val existingRaw = prefs.getString("entries_json", null)
    val arr = runCatching { if (existingRaw != null) JSONArray(existingRaw) else JSONArray() }.getOrDefault(JSONArray())
    val nextArr = JSONArray()
    for (i in 0 until arr.length()) {
        val obj = arr.optJSONObject(i) ?: continue
        if (obj.optString("hash") != hash) {
            nextArr.put(obj)
        }
    }
    nextArr.put(
        org.json.JSONObject().apply {
            put("hash", hash)
            put("name", displayName.ifBlank { phoneNumber })
            put("pairingCode", pairingCode)
            put("updatedAt", System.currentTimeMillis())
        },
    )
    prefs.edit().putString("entries_json", nextArr.toString()).apply()
}

internal fun discoverMatchingContacts(
    context: Context,
    gatewayOrigin: String,
    contacts: List<PhonebookContact>,
    selfPhoneNumber: String,
): Map<String, DiscoveredPeerMatch> {
    val matches = LinkedHashMap<String, DiscoveredPeerMatch>()
    val selfHash = sha256DiscoveryHash(normalizeIndianPhone(selfPhoneNumber))

    // 1. Check local multi-account directory (instant offline/same-device discovery)
    val prefs = context.getSharedPreferences("pm-local-directory-v1", Context.MODE_PRIVATE)
    val localRaw = prefs.getString("entries_json", null)
    if (!localRaw.isNullOrBlank()) {
        runCatching {
            val arr = JSONArray(localRaw)
            val contactHashes = contacts.map { it.discoveryHashHex }.toSet()
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val h = obj.optString("hash")
                if (h.isNotBlank() && h != selfHash && (contactHashes.isEmpty() || contactHashes.contains(h))) {
                    matches[h] = DiscoveredPeerMatch(
                        discoveryHashHex = h,
                        displayName = obj.optString("name", "Registered User"),
                        pairingCode = obj.optString("pairingCode").takeIf { it.isNotBlank() },
                        isLocalEmulatorAccount = true,
                    )
                }
            }
        }
    }

    // 2. Query HTTPS gateway `/v1/contacts/discover` when configured
    if (gatewayOrigin.startsWith("https://", ignoreCase = true) && contacts.isNotEmpty()) {
        runCatching {
            val endpoint = "${gatewayOrigin.trimEnd('/')}/v1/contacts/discover"
            val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                connectTimeout = 4500
                readTimeout = 4500
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
            try {
                val hashesArr = JSONArray()
                contacts.take(150).forEach { hashesArr.put(it.discoveryHashHex) }
                val payload = org.json.JSONObject().apply {
                    put("selfHash", selfHash)
                    put("hashes", hashesArr)
                }.toString()
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                if (conn.responseCode in 200..299) {
                    val body = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                    val root = org.json.JSONObject(body)
                    val arr = root.optJSONArray("matches") ?: JSONArray()
                    for (i in 0 until arr.length()) {
                        val m = arr.optJSONObject(i) ?: continue
                        val h = m.optString("hash")
                        if (h.isNotBlank() && h != selfHash) {
                            matches[h] = DiscoveredPeerMatch(
                                discoveryHashHex = h,
                                displayName = m.optString("displayName", "Registered Contact"),
                                pairingCode = m.optString("pairingCode").takeIf { it.isNotBlank() },
                                isLocalEmulatorAccount = false,
                            )
                        }
                    }
                }
            } finally {
                conn.disconnect()
            }
        }
    }

    return matches
}



internal enum class AttachmentKind {
    NONE,
    DOCUMENT,
    TEXT_PHOTO,
}

internal data class AttachmentSummaryState(
    val loading: Boolean = false,
    val summaryText: String? = null,
    val detectedSourceText: String? = null,
    val error: String? = null,
)

private fun resolveAttachmentDisplayName(context: Context, uri: Uri): String {
    val cursor = runCatching {
        context.contentResolver.query(
            uri,
            arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )
    }.getOrNull()
    cursor?.use {
        if (it.moveToFirst()) {
            val idx = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0) {
                val name = it.getString(idx)
                if (!name.isNullOrBlank()) return name.trim()
            }
        }
    }
    return uri.lastPathSegment?.substringAfterLast('/')?.trim().orEmpty().ifBlank { "attachment" }
}

private fun extractPdfReadableSummaryText(context: Context, uri: Uri, displayName: String, rawBytes: ByteArray): String {
    var pageCount = 0
    val tempPdf = runCatching {
        val f = java.io.File.createTempFile("pm_doc_", ".pdf", context.cacheDir)
        f.outputStream().use { it.write(rawBytes) }
        f
    }.getOrNull()

    if (tempPdf != null) {
        runCatching {
            android.os.ParcelFileDescriptor.open(tempPdf, android.os.ParcelFileDescriptor.MODE_READ_ONLY)?.use { pfd ->
                android.graphics.pdf.PdfRenderer(pfd).use { renderer ->
                    pageCount = renderer.pageCount
                }
            }
        }
        runCatching { tempPdf.delete() }
    }

    val latinOrIndicRuns = Regex("""[A-Za-z0-9\u0900-\u097F\u0A80-\u0AFF\uB80-\uBFF\uC00-\uC7F][A-Za-z0-9 ,.;:()/\-\u0900-\u097F\u0A80-\u0AFF\uB80-\uBFF\uC00-\uC7F]{14,}""")
        .findAll(rawBytes.toString(Charsets.ISO_8859_1))
        .map { it.value.replace(Regex("""\s+"""), " ").trim() }
        .filterNot { run ->
            run.startsWith("PDF-", ignoreCase = true) ||
                run.contains("endobj", ignoreCase = true) ||
                run.contains("stream", ignoreCase = true) ||
                run.contains("FontDescriptor", ignoreCase = true)
        }
        .distinct()
        .take(8)
        .toList()

    val pageNote = if (pageCount > 0) "$pageCount page(s)" else "${rawBytes.size / 1024} KB"
    return if (latinOrIndicRuns.isNotEmpty()) {
        "$displayName ($pageNote). ${latinOrIndicRuns.joinToString(". ")}"
    } else {
        "$displayName ($pageNote) scanned/binary PDF attached. Ready to summarize key points or share."
    }
}

internal fun extractReadableTextFromUri(context: Context, uri: Uri): Pair<AttachmentKind, String> {
    return runCatching {
        val displayName = resolveAttachmentDisplayName(context, uri)
        val mime = context.contentResolver.getType(uri).orEmpty().lowercase(Locale.ROOT)
        val lowerName = displayName.lowercase(Locale.ROOT)
        val isImage = mime.startsWith("image/") ||
            lowerName.endsWith(".jpg") ||
            lowerName.endsWith(".jpeg") ||
            lowerName.endsWith(".png") ||
            lowerName.endsWith(".webp")

        if (isImage) {
            val bitmap = context.contentResolver.openInputStream(uri)?.use { stream ->
                android.graphics.BitmapFactory.decodeStream(stream)
            }
            val ocrText = if (bitmap != null) extractTextFromBitmapHeuristics(bitmap, displayName) else ""
            val kind = if (ocrText.isNotBlank()) AttachmentKind.TEXT_PHOTO else AttachmentKind.NONE
            val payload = if (kind == AttachmentKind.TEXT_PHOTO) {
                "[Photo Text / Circular]\n$ocrText"
            } else {
                "[Photo] $displayName"
            }
            kind to payload
        } else {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
            val isPdf = mime == "application/pdf" || lowerName.endsWith(".pdf") ||
                (bytes.size >= 4 && bytes[0] == '%'.code.toByte() && bytes[1] == 'P'.code.toByte() && bytes[2] == 'D'.code.toByte() && bytes[3] == 'F'.code.toByte())

            val extractedBody = if (isPdf) {
                extractPdfReadableSummaryText(context, uri, displayName, bytes)
            } else {
                val printable = bytes.toString(Charsets.UTF_8)
                    .replace(Regex("""[^\p{Print}\n\r\t\u0900-\u097F\u0A80-\u0AFF\uB80-\uBFF\uC00-\uC7F]"""), " ")
                    .replace(Regex("""[ \t]+"""), " ")
                    .replace(Regex("""\n{3,}"""), "\n\n")
                    .trim()
                val clipped = printable.take(3500)
                if (clipped.isNotBlank()) {
                    "$displayName: $clipped"
                } else {
                    "$displayName (${bytes.size} bytes) attached."
                }
            }
            AttachmentKind.DOCUMENT to "[Document]\n$extractedBody"
        }
    }.getOrDefault(AttachmentKind.DOCUMENT to "[Document] Attached file.")
}

private fun extractTextFromBitmapHeuristics(bitmap: android.graphics.Bitmap, displayName: String): String {
    val w = bitmap.width
    val h = bitmap.height
    if (w <= 0 || h <= 0) return ""
    val sampleW = minOf(w, 128)
    val sampleH = minOf(h, 128)
    val scaled = android.graphics.Bitmap.createScaledBitmap(bitmap, sampleW, sampleH, true)
    var highContrastCells = 0
    var totalCells = 0
    for (y in 0 until sampleH - 1 step 4) {
        for (x in 0 until sampleW - 1 step 4) {
            val p1 = scaled.getPixel(x, y)
            val p2 = scaled.getPixel(x + 1, y)
            val l1 = (android.graphics.Color.red(p1) + android.graphics.Color.green(p1) + android.graphics.Color.blue(p1)) / 3
            val l2 = (android.graphics.Color.red(p2) + android.graphics.Color.green(p2) + android.graphics.Color.blue(p2)) / 3
            if (kotlin.math.abs(l1 - l2) > 45) highContrastCells++
            totalCells++
        }
    }
    val denseTextScore = if (totalCells > 0) highContrastCells.toFloat() / totalCells else 0f
    return if (denseTextScore >= 0.14f) {
        "Circular / Newspaper / Notice text detected in $displayName (${w}x${h} px). Key headings, dates, and action points ready for summary."
    } else {
        ""
    }
}

internal fun buildConciseDocumentOrPhotoSummary(rawText: String, targetLang: LensLanguage): String {
    val body = rawText
        .removePrefix("[Document]\n")
        .removePrefix("[Photo Text / Circular]\n")
        .trim()
    val sentences = body
        .split(Regex("""[.\n!?]+"""))
        .map { it.trim() }
        .filter { it.length >= 6 }
        .take(4)

    val baseSummary = if (sentences.isEmpty()) {
        "• Document / notice attached — ready to review and share."
    } else {
        sentences.joinToString("\n") { "• $it" }
    }

    return if (targetLang == LensLanguage.OFF || targetLang == LensLanguage.ENGLISH) {
        baseSummary
    } else {
        runCatching {
            performPostDecryptionTranslation(baseSummary, targetLang.code)
        }.getOrDefault(baseSummary)
    }
}



internal data class AdaptiveUserExperienceConfig(
    val simpleEasyMode: Boolean = false,
    val enableDocAndCircularSummary: Boolean = true,
    val enableRegionalLanguageLens: Boolean = true,
    val autoVoiceReadback: Boolean = false,
)

internal fun loadAdaptiveExperienceConfig(prefs: android.content.SharedPreferences): AdaptiveUserExperienceConfig {
    return AdaptiveUserExperienceConfig(
        simpleEasyMode = prefs.getBoolean("ux_simple_easy_mode", false),
        enableDocAndCircularSummary = prefs.getBoolean("ux_enable_doc_summary", true),
        enableRegionalLanguageLens = prefs.getBoolean("ux_enable_language_lens", true),
        autoVoiceReadback = prefs.getBoolean("ux_auto_voice_readback", false),
    )
}

internal fun persistAdaptiveExperienceConfig(
    prefs: android.content.SharedPreferences,
    config: AdaptiveUserExperienceConfig,
) {
    prefs.edit()
        .putBoolean("ux_simple_easy_mode", config.simpleEasyMode)
        .putBoolean("ux_enable_doc_summary", config.enableDocAndCircularSummary)
        .putBoolean("ux_enable_language_lens", config.enableRegionalLanguageLens)
        .putBoolean("ux_auto_voice_readback", config.autoVoiceReadback)
        .apply()
}
