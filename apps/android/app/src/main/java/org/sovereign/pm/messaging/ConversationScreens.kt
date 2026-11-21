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


// ============================================================================
// CONVERSATION THREAD + LANGUAGE LENS + LISTEN + STARRING + CHAT INFO
// ============================================================================

@Composable
internal fun RichConversationScreen(
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
internal fun ChatInfoScreen(
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
