package org.sovereign.pm.ui.screens.home

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.sovereign.pm.ui.components.DisclosureCard
import org.sovereign.pm.ui.components.GeometricIdenticon
import org.sovereign.pm.ui.components.SovereignHomeTopBar
import org.sovereign.pm.ui.components.SovereignShieldIcon
import org.sovereign.pm.ui.state.ConversationsUiState
import org.sovereign.pm.ui.state.PinnedPeerConversationSummary
import org.sovereign.pm.ui.theme.SovereignDimens
import org.sovereign.pm.ui.theme.SovereignThemeTokens

@Composable
fun ConversationsHomeScreen(uiState: ConversationsUiState, onOpenSettings: () -> Unit,
    onOpenIdentitySheet: (() -> Unit)? = null, onNewConnectionClick: (() -> Unit)? = null,
    onConversationClick: ((PinnedPeerConversationSummary) -> Unit)? = null, modifier: Modifier = Modifier) {
    Scaffold(modifier.fillMaxSize(),containerColor=MaterialTheme.colorScheme.background,
        topBar={ SovereignHomeTopBar(uiState.localProfileLabel,uiState.registrationRecord,uiState.liveConnectivity,
            uiState.isPreviewMode,onOpenIdentitySheet,onOpenSettings) }) { padding ->
        if(uiState.pinnedConversations.isEmpty()) {
            EmptyConversationsContent(uiState.isPreviewMode,Modifier.fillMaxSize().padding(padding)
                .verticalScroll(rememberScrollState()).padding(horizontal=SovereignDimens.ScreenHorizontalPadding,vertical=24.dp))
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding),contentPadding=PaddingValues(
                start=SovereignDimens.ScreenHorizontalPadding,end=SovereignDimens.ScreenHorizontalPadding,top=8.dp,bottom=24.dp),
                verticalArrangement=Arrangement.spacedBy(10.dp)) {
                items(uiState.pinnedConversations,key={"${it.peerAccountId}:${it.peerDeviceId}"}) { item ->
                    PinnedConversationRow(item,onConversationClick?.let { handler -> { handler(item) } })
                }
            }
        }
    }
}

@Composable
private fun EmptyConversationsContent(isPreviewMode: Boolean,modifier: Modifier=Modifier) {
    Box(modifier,contentAlignment=Alignment.Center) {
        Column(horizontalAlignment=Alignment.CenterHorizontally,verticalArrangement=Arrangement.spacedBy(12.dp)) {
            Surface(shape=MaterialTheme.shapes.large,color=MaterialTheme.colorScheme.surfaceContainerLow,
                border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant),modifier=Modifier.size(64.dp)) {
                SovereignShieldIcon(size=28.dp,tint=MaterialTheme.colorScheme.primary,modifier=Modifier.padding(18.dp))
            }
            Text("No pinned conversations yet",style=MaterialTheme.typography.titleLarge,color=MaterialTheme.colorScheme.onBackground,textAlign=TextAlign.Center)
            Text("Nobody can reach this device until you import a PM-ALPHA1 pairing code, verify their fingerprint, and pin them locally.",
                style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurfaceVariant,textAlign=TextAlign.Center)
            if(isPreviewMode) DisclosureCard("Phase 3A Foundation Preview",
                "No fake contacts, simulated messages or unimplemented pairing actions are displayed. Real pinned peers bind in later phases.",Modifier.padding(top=8.dp))
        }
    }
}

@Composable
private fun PinnedConversationRow(summary: PinnedPeerConversationSummary,onClick: (() -> Unit)?) {
    val sem=SovereignThemeTokens.semanticColors
    val rowModifier=if(onClick!=null) Modifier.fillMaxWidth().clickable(onClick=onClick) else Modifier.fillMaxWidth()
    Surface(rowModifier,shape=MaterialTheme.shapes.medium,color=MaterialTheme.colorScheme.surfaceContainerLow,
        border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant)) {
        Row(Modifier.padding(SovereignDimens.CardPadding),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)) {
            GeometricIdenticon("${summary.peerAccountId}:${summary.peerDeviceId}",size=44.dp)
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(6.dp)) {
                    Text(summary.localNickname,style=MaterialTheme.typography.titleMedium,color=MaterialTheme.colorScheme.onSurface,maxLines=1,overflow=TextOverflow.Ellipsis)
                    if(summary.isManuallyPinned) SovereignShieldIcon(size=15.dp,tint=sem.verifiedBadge,contentDescription="Manually pinned peer")
                }
                Text(summary.lastMessagePreview ?: "Pinned peer · No local messages yet",style=MaterialTheme.typography.bodyMedium,
                    color=MaterialTheme.colorScheme.onSurfaceVariant,maxLines=1,overflow=TextOverflow.Ellipsis)
            }
            if(!summary.lastActivityLabel.isNullOrBlank()) Text(summary.lastActivityLabel,style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
