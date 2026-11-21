package org.sovereign.pm.ui.screens.onboarding

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.sovereign.pm.ui.components.DisclosureCard
import org.sovereign.pm.ui.components.FoundationPreviewBanner
import org.sovereign.pm.ui.components.SovereignLockIcon
import org.sovereign.pm.ui.state.WelcomeUiState
import org.sovereign.pm.ui.theme.SovereignDimens

@Composable
fun WelcomeScreen(uiState: WelcomeUiState, onPrimaryActionClick: () -> Unit,
    onEnrollAdditionalDeviceClick: (() -> Unit)? = null, onConfigureGatewayClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier) {
    Scaffold(modifier.fillMaxSize(),containerColor=MaterialTheme.colorScheme.background,
        topBar={ if(uiState.isPreviewMode) FoundationPreviewBanner() },
        bottomBar={
            Surface(color=MaterialTheme.colorScheme.background,border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant)) {
                Column(Modifier.fillMaxWidth().padding(horizontal=SovereignDimens.ScreenHorizontalPadding,vertical=14.dp),
                    verticalArrangement=Arrangement.spacedBy(8.dp)) {
                    Button(onClick=onPrimaryActionClick,shape=MaterialTheme.shapes.medium,modifier=Modifier.fillMaxWidth().height(50.dp)) {
                        Text(if(uiState.isPreviewMode) "Preview Conversations" else "Create Local Identity",style=MaterialTheme.typography.labelLarge)
                    }
                    if(!uiState.isPreviewMode && onEnrollAdditionalDeviceClick!=null) {
                        OutlinedButton(onClick=onEnrollAdditionalDeviceClick,modifier=Modifier.fillMaxWidth().height(46.dp)) {
                            Text("Enroll Additional Device")
                        }
                    }
                }
            }
        }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
            .padding(horizontal=SovereignDimens.ScreenHorizontalPadding,vertical=20.dp),
            verticalArrangement=Arrangement.spacedBy(16.dp)) {
            Surface(shape=MaterialTheme.shapes.medium,color=MaterialTheme.colorScheme.primaryContainer,modifier=Modifier.size(52.dp)) {
                SovereignLockIcon(size=24.dp,tint=MaterialTheme.colorScheme.onPrimaryContainer,modifier=Modifier.padding(14.dp))
            }
            Text("Sovereign PM",style=MaterialTheme.typography.labelLarge,color=MaterialTheme.colorScheme.primary)
            Text("Private conversations.\nNo phone number or email required.",style=MaterialTheme.typography.headlineMedium,color=MaterialTheme.colorScheme.onBackground)
            Text("Your cryptographic identity is generated locally on this device. Only peers whose pairing fingerprint you manually verify and pin can exchange messages with you.",
                style=MaterialTheme.typography.bodyLarge,color=MaterialTheme.colorScheme.onSurfaceVariant)
            DisclosureCard(
                title=if(uiState.isPreviewMode) "Phase 3A Foundation Preview" else "Experimental Alpha Notice",
                body=if(uiState.isPreviewMode) "Identity creation, recovery phrase generation, additional-device enrollment and gateway registration are inactive in this visual preview."
                    else "Sovereign PM is under active engineering development. Gateway connectivity and explicit peer pinning are required; independent cryptographic auditing is pending.")
            if(!uiState.isPreviewMode && onConfigureGatewayClick!=null) {
                OutlinedButton(onClick=onConfigureGatewayClick,modifier=Modifier.fillMaxWidth()) {
                    Text(if(uiState.configuredGatewayOrigin.isNullOrBlank()) "Gateway: Not Configured" else "Gateway: ${uiState.configuredGatewayOrigin}")
                }
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}
