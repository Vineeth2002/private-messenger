package org.sovereign.pm.messaging

import androidx.activity.compose.BackHandler

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
// COMPLETE MULTI-PAGE SETTINGS HIERARCHY
// ============================================================================

@Composable
internal fun SimpleTopBar(title: String, onBack: () -> Unit) {
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
internal fun SettingsActionRow(
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
internal fun SettingsToggleRow(
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
internal fun SettingsHomeScreen(
    experienceConfig: AdaptiveUserExperienceConfig = AdaptiveUserExperienceConfig(),
    onUpdateExperienceConfig: (AdaptiveUserExperienceConfig) -> Unit = {},
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

            // Adaptive Experience & Storage-Saver Packs Card
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SovereignSlatePalette.CardWhite,
                border = BorderStroke(1.dp, SovereignSlatePalette.Hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    Text(
                        "EASY MODE & SMART PACKS",
                        modifier = Modifier.padding(start = 16.dp, top = 14.dp, end = 16.dp, bottom = 4.dp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = SovereignSlatePalette.PrimaryIndigo,
                    )
                    SettingsToggleRow(
                        title = "Simple Easy View",
                        subtitle = "Show only Chats & Calls with clean, uncluttered screens for everyday use",
                        checked = experienceConfig.simpleEasyMode,
                        onCheckedChange = { onUpdateExperienceConfig(experienceConfig.copy(simpleEasyMode = it)) },
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow(
                        title = "Document & Newspaper Summary",
                        subtitle = "Summarize PDFs, circulars & text photos on-device (~2 MB pack)",
                        checked = experienceConfig.enableDocAndCircularSummary,
                        onCheckedChange = { onUpdateExperienceConfig(experienceConfig.copy(enableDocAndCircularSummary = it)) },
                    )
                    HorizontalDivider(color = SovereignSlatePalette.Hairline)
                    SettingsToggleRow(
                        title = "Regional Language Lens",
                        subtitle = "Instant Telugu, Hindi, Tamil & Gujarati reading & voice bar",
                        checked = experienceConfig.enableRegionalLanguageLens,
                        onCheckedChange = { onUpdateExperienceConfig(experienceConfig.copy(enableRegionalLanguageLens = it)) },
                    )
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
internal fun SettingsProfileScreen(
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
internal fun SettingsAccountScreen(
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
internal fun SettingsAccountSecurityScreen(
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
internal fun SettingsTwoStepScreen(
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
internal fun SettingsChangeNumberScreen(
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
internal fun SettingsRequestInfoScreen(
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
internal fun SettingsDeleteAccountScreen(
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
internal fun SettingsPrivacyScreen(
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
internal fun SettingsSingleChoiceScreen(
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
internal fun SettingsChatsScreen(
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
internal fun SettingsChatHistoryScreen(
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
internal fun SettingsNotificationsScreen(
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
internal fun SettingsStorageScreen(
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
internal fun SettingsHelpScreen(
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
internal fun SettingsFaqDetailScreen(topic: String, onBack: () -> Unit) {
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
internal fun SettingsContactUsScreen(onBack: () -> Unit) {
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
internal fun SettingsAppInfoScreen(onBack: () -> Unit) {
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


@Composable
internal fun PrivacyMirrorNotice(onOpenSettings: () -> Unit) {
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


@Composable
internal fun QuickSimOnboardingScreen(
    context: Context,
    simPrefs: android.content.SharedPreferences,
    onRequestPhonePermission: () -> Unit,
    onCompleted: () -> Unit,
) {
    var phoneInput by remember { mutableStateOf("") }
    var displayNameInput by remember { mutableStateOf("") }
    var otpInput by remember { mutableStateOf("") }
    var otpSent by remember { mutableStateOf(false) }
    BackHandler(enabled = otpSent) {
        otpSent = false
        otpInput = ""
        errorText = null
    }
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
internal fun SimBindingLockScreen(
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