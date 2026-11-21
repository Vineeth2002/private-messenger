package org.sovereign.pm.app

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.sovereign.pm.ui.components.DisclosureCard
import org.sovereign.pm.ui.components.FoundationPreviewBanner
import org.sovereign.pm.ui.components.SovereignBackIcon
import org.sovereign.pm.ui.screens.home.ConversationsHomeScreen
import org.sovereign.pm.ui.screens.onboarding.WelcomeScreen
import org.sovereign.pm.ui.state.AppShellUiState
import org.sovereign.pm.ui.state.ConversationsUiState
import org.sovereign.pm.ui.state.GatewayRegistrationRecord
import org.sovereign.pm.ui.state.GatewayRegistrationState
import org.sovereign.pm.ui.state.LiveConnectivityState
import org.sovereign.pm.ui.state.LocalIdentityState
import org.sovereign.pm.ui.state.WelcomeUiState
import org.sovereign.pm.ui.theme.SovereignDimens
import org.sovereign.pm.ui.theme.SovereignTheme

@Composable
fun SovereignAppRoot(shellState: AppShellUiState, conversationsState: ConversationsUiState,
    navigator: SovereignNavigator? = null,onCloseReviewActivity: (() -> Unit)? = null) {
    val activeNavigator = navigator ?: rememberSovereignNavigator(
        if(shellState.isPreviewMode) SovereignDestination.WelcomePreview else SovereignDestination.ConversationsHome)
    SovereignTheme {
        BackHandler(enabled=activeNavigator.canNavigateBack) { activeNavigator.popBack() }
        when(val destination=activeNavigator.currentDestination) {
            SovereignDestination.WelcomePreview -> WelcomeScreen(
                uiState=WelcomeUiState(shellState.registrationRecord.gatewayOrigin,isPreviewMode=shellState.isPreviewMode),
                onPrimaryActionClick={ activeNavigator.navigateTo(SovereignDestination.ConversationsHome) })
            SovereignDestination.ConversationsHome -> ConversationsHomeScreen(
                uiState=conversationsState,onOpenSettings={ activeNavigator.navigateTo(SovereignDestination.SettingsOverview) })
            SovereignDestination.SettingsOverview -> SettingsPreviewScreen(shellState,
                onBack={ activeNavigator.popBack() },onWelcome={ activeNavigator.navigateTo(SovereignDestination.WelcomePreview) },
                onClose=onCloseReviewActivity)
            is SovereignDestination.IntegrityError -> IntegrityErrorPreviewScreen(shellState.localIdentityState,destination.reasonCode)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsPreviewScreen(shellState: AppShellUiState,onBack: () -> Unit,onWelcome: () -> Unit,onClose: (() -> Unit)?) {
    Scaffold(topBar={
        Column {
            if(shellState.isPreviewMode) FoundationPreviewBanner()
            TopAppBar(title={ Text("Settings & Architecture Status") },navigationIcon={
                IconButton(onClick=onBack) { SovereignBackIcon(contentDescription="Back") }
            })
        }
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
            .padding(horizontal=SovereignDimens.ScreenHorizontalPadding,vertical=16.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
            DisclosureCard("Local Identity State Contract",
                "Static Phase 3A preview value: ${shellState.localIdentityState.name}. Live startup Keystore and storage inspection is deferred to Phase 3B.")
            DisclosureCard("Gateway Registration & Connectivity Contracts",
                "Registration model: ${shellState.registrationRecord.state.name} · Live connectivity model: ${shellState.liveConnectivity.displayLabel}. No persistence or reconciliation is implemented in this preview.")
            OutlinedButton(onClick=onWelcome,modifier=Modifier.fillMaxWidth()) { Text("Return to Welcome Preview") }
            if(onClose!=null) OutlinedButton(onClick=onClose,modifier=Modifier.fillMaxWidth()) { Text("Close Phase 3A Review Activity") }
        }
    }
}

@Composable
private fun IntegrityErrorPreviewScreen(identityState: LocalIdentityState,reasonCode: String) {
    Surface(Modifier.fillMaxSize(),color=MaterialTheme.colorScheme.background) {
        Column(Modifier.fillMaxSize().padding(SovereignDimens.ScreenHorizontalPadding),verticalArrangement=Arrangement.Center) {
            DisclosureCard("Local Identity Integrity Hold (${identityState.name})",
                "Reason: $reasonCode. Preserve app data and do not uninstall. Destructive reset is intentionally omitted.",isCaution=true)
        }
    }
}

@Composable
fun Phase3APreviewHost(onCloseReviewActivity: (() -> Unit)? = null) {
    val shell=remember {
        AppShellUiState(localIdentityState=LocalIdentityState.CLEAN_INSTALL,localProfileLabel="Preview Device",
            registrationRecord=GatewayRegistrationRecord(state=GatewayRegistrationState.NOT_ATTEMPTED),
            liveConnectivity=LiveConnectivityState.DISCONNECTED,isPreviewMode=true)
    }
    val conversations=remember {
        ConversationsUiState(localProfileLabel=shell.localProfileLabel,registrationRecord=shell.registrationRecord,
            liveConnectivity=shell.liveConnectivity,pinnedConversations=emptyList(),isPreviewMode=true)
    }
    SovereignAppRoot(shell,conversations,onCloseReviewActivity=onCloseReviewActivity)
}
