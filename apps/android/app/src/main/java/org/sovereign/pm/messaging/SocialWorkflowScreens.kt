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
// NEW CHAT, NEW GROUP, NEW COMMUNITY, NEW BROADCAST, LINKED DEVICES, STARRED
// ============================================================================

@Composable
internal fun NewChatFullScreen(
    phonebookContacts: List<PhonebookContact>,
    discoveredMatches: Map<String, DiscoveredPeerMatch> = emptyMap(),
    isDiscovering: Boolean = false,
    gatewayConfigured: Boolean = false,
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
            } else {
                val matchedContacts = filtered.filter { discoveredMatches.containsKey(it.discoveryHashHex) }
                val unmatchedContacts = filtered.filterNot { discoveredMatches.containsKey(it.discoveryHashHex) }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        if (isDiscovering) "Checking registered contacts..."
                        else if (gatewayConfigured) "Gateway discovery active"
                        else "Offline discovery mode",
                        fontSize = 12.sp,
                        color = if (gatewayConfigured) SovereignSlatePalette.VerifiedTeal else SovereignSlatePalette.TextSecondary,
                        fontWeight = FontWeight.Medium,
                    )
                    TextButton(onClick = onSyncContacts) {
                        Text("Refresh", fontSize = 12.sp, color = SovereignSlatePalette.PrimaryIndigo)
                    }
                }

                if (matchedContacts.isNotEmpty()) {
                    Text(
                        "REGISTERED CONTACTS (E2EE READY)",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.VerifiedTeal,
                    )
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = SovereignSlatePalette.CardWhite,
                        border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column {
                            matchedContacts.forEachIndexed { idx, c ->
                                val match = discoveredMatches[c.discoveryHashHex]
                                SettingsActionRow(
                                    title = c.displayName,
                                    subtitle = if (!match?.pairingCode.isNullOrBlank()) "${c.phoneOrEmail} · Encrypted" else c.phoneOrEmail,
                                    onClick = {
                                        val code = match?.pairingCode
                                        if (!code.isNullOrBlank()) {
                                            onConnectInviteCode(c.displayName, code)
                                        } else {
                                            onStartDirectChat(c.displayName, c.phoneOrEmail)
                                        }
                                    },
                                )
                                if (idx < matchedContacts.lastIndex) {
                                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                                }
                            }
                        }
                    }
                }

                if (unmatchedContacts.isNotEmpty()) {
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
                            unmatchedContacts.forEachIndexed { idx, c ->
                                SettingsActionRow(
                                    title = c.displayName,
                                    subtitle = c.phoneOrEmail,
                                    onClick = { onStartDirectChat(c.displayName, c.phoneOrEmail) },
                                )
                                if (idx < unmatchedContacts.lastIndex) {
                                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun ParticipantPickerScreen(
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
internal fun NewGroupDetailsScreen(
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
internal fun NewCommunityIntroScreen(
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
internal fun NewCommunityDetailsScreen(
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
internal fun LinkedDevicesScreen(
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
internal fun StarredMessagesScreen(
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
internal fun CreateStatusScreen(
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
internal fun StatusViewerScreen(
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
internal fun ChannelFeedScreen(
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
internal fun NewCallPickerScreen(
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
internal fun InCallScreen(
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
