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
// MAIN 4-TAB SHELL + OVERFLOW MENU (CHATS, UPDATES, COMMUNITIES, CALLS)
// ============================================================================

@Composable
internal fun MainFourTabHomeScreen(
    simpleEasyMode: Boolean = false,
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
                    val visibleTabs = if (simpleEasyMode) listOf(BottomNavTab.CHATS, BottomNavTab.CALLS) else BottomNavTab.entries
                    visibleTabs.forEach { tab ->
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
internal fun OverflowMenuOptionRow(label: String, onClick: () -> Unit) {
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
internal fun ChatListRowCard(
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
