package org.sovereign.pm.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.sovereign.pm.ui.state.GatewayRegistrationRecord
import org.sovereign.pm.ui.state.GatewayRegistrationState
import org.sovereign.pm.ui.state.LiveConnectivityState
import org.sovereign.pm.ui.state.OutboxMessageStatus
import org.sovereign.pm.ui.theme.SovereignDimens
import org.sovereign.pm.ui.theme.SovereignMonospaceBody
import org.sovereign.pm.ui.theme.SovereignThemeTokens

@Composable
fun FoundationPreviewBanner(modifier: Modifier = Modifier) {
    Surface(modifier.fillMaxWidth(), color=MaterialTheme.colorScheme.secondaryContainer,
        border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant)) {
        Text("FOUNDATION PREVIEW — Static UI shell; live identity and messaging remain in alpha console",
            style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSecondaryContainer,
            modifier=Modifier.padding(horizontal=SovereignDimens.ScreenHorizontalPadding,vertical=6.dp))
    }
}

@Composable
fun GeometricIdenticon(seed: String, modifier: Modifier = Modifier, size: Dp = 44.dp) {
    val fg=MaterialTheme.colorScheme.primary; val bg=MaterialTheme.colorScheme.primaryContainer
    val matrix=remember(seed) { IdenticonPattern.generateMatrix(seed) }
    Box(modifier.size(size).clip(CircleShape).background(bg)
        .semantics { contentDescription="Decorative contact identicon" },contentAlignment=Alignment.Center) {
        Canvas(Modifier.size(size*.56f)) {
            val cw=this.size.width/5f; val ch=this.size.height/5f
            for(r in 0 until 5) for(c in 0 until 5) if(matrix[r][c])
                drawRect(fg,Offset(c*cw,r*ch),Size(cw+.5f,ch+.5f))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SovereignHomeTopBar(localProfileLabel: String, registrationRecord: GatewayRegistrationRecord,
    liveConnectivity: LiveConnectivityState, isPreviewMode: Boolean, onOpenIdentitySheet: (() -> Unit)?,
    onOpenSettings: () -> Unit, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth()) {
        if(isPreviewMode) FoundationPreviewBanner()
        TopAppBar(colors=TopAppBarDefaults.topAppBarColors(containerColor=MaterialTheme.colorScheme.background),
            title={
                Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                    val clickMod=if(onOpenIdentitySheet!=null) Modifier.clickable(onClick=onOpenIdentitySheet) else Modifier
                    Surface(shape=CircleShape,color=MaterialTheme.colorScheme.surfaceContainerLow,
                        border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant),modifier=clickMod) {
                        Row(Modifier.padding(horizontal=12.dp,vertical=7.dp),verticalAlignment=Alignment.CenterVertically,
                            horizontalArrangement=Arrangement.spacedBy(7.dp)) {
                            ConnectivityIndicator(liveConnectivity)
                            Text(localProfileLabel.ifBlank { "Local Device" },style=MaterialTheme.typography.titleMedium,
                                maxLines=1,overflow=TextOverflow.Ellipsis)
                        }
                    }
                    RegistrationStatusPill(registrationRecord.state)
                }
            },
            actions={ IconButton(onClick=onOpenSettings) { SovereignSettingsIcon(tint=MaterialTheme.colorScheme.onBackground) } })
    }
}

@Composable
fun ConnectivityIndicator(liveConnectivity: LiveConnectivityState, modifier: Modifier = Modifier) {
    val sem=SovereignThemeTokens.semanticColors
    val color=when(liveConnectivity) {
        LiveConnectivityState.CONNECTED -> sem.connectedDot
        LiveConnectivityState.CONNECTING -> sem.verifiedBadge
        LiveConnectivityState.DISCONNECTED,LiveConnectivityState.UNREACHABLE -> sem.offlineDot
    }
    Row(modifier.semantics(mergeDescendants=true) { contentDescription="Gateway connectivity: ${liveConnectivity.displayLabel}" },
        verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(5.dp)) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        Text(liveConnectivity.displayLabel,style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun RegistrationStatusPill(registrationState: GatewayRegistrationState, modifier: Modifier = Modifier) {
    val sem=SovereignThemeTokens.semanticColors
    val (label,bg,fg)=when(registrationState) {
        GatewayRegistrationState.ACTIVE_CONFIRMED -> Triple("Registered",MaterialTheme.colorScheme.primaryContainer,MaterialTheme.colorScheme.onPrimaryContainer)
        GatewayRegistrationState.NOT_ATTEMPTED -> Triple("Unregistered",MaterialTheme.colorScheme.surfaceVariant,MaterialTheme.colorScheme.onSurfaceVariant)
        GatewayRegistrationState.CHALLENGE_PENDING,GatewayRegistrationState.ACTIVATION_IN_PROGRESS -> Triple("Enrolling",MaterialTheme.colorScheme.secondaryContainer,MaterialTheme.colorScheme.onSecondaryContainer)
        GatewayRegistrationState.REGISTRATION_OUTCOME_UNKNOWN,GatewayRegistrationState.RECONCILIATION_REQUIRED -> Triple("Check Status",sem.unknownOutcomeContainer,sem.unknownOutcome)
    }
    Surface(modifier,shape=CircleShape,color=bg) {
        Text(label,style=MaterialTheme.typography.labelSmall,color=fg,modifier=Modifier.padding(horizontal=8.dp,vertical=4.dp))
    }
}

@Composable
fun FingerprintBlock(title: String, rawFingerprint: String, modifier: Modifier = Modifier) {
    val grouped=remember(rawFingerprint) { rawFingerprint.replace("\\s+".toRegex(),"").chunked(4).chunked(4).joinToString("\n") { it.joinToString("  ") } }
    Surface(modifier.fillMaxWidth(),shape=MaterialTheme.shapes.medium,color=MaterialTheme.colorScheme.surfaceContainerLow,
        border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant)) {
        Column(Modifier.padding(SovereignDimens.CardPadding),verticalArrangement=Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(6.dp)) {
                SovereignShieldIcon(size=16.dp,tint=MaterialTheme.colorScheme.primary)
                Text(title,style=MaterialTheme.typography.labelMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(grouped.ifBlank { "Unavailable" },style=SovereignMonospaceBody,color=MaterialTheme.colorScheme.onSurface)
        }
    }
}

@Composable
fun OutboxStatusBadge(status: OutboxMessageStatus, modifier: Modifier = Modifier) {
    val sem=SovereignThemeTokens.semanticColors
    val (label,color)=when(status) {
        OutboxMessageStatus.READY -> "Queued locally" to MaterialTheme.colorScheme.onSurfaceVariant
        OutboxMessageStatus.ATTEMPTING -> "Submitting…" to MaterialTheme.colorScheme.primary
        OutboxMessageStatus.SUBMITTED -> "Submitted to gateway" to MaterialTheme.colorScheme.onSurfaceVariant
        OutboxMessageStatus.DELIVERY_UNKNOWN -> "Outcome unknown" to sem.unknownOutcome
    }
    Text(label,modifier,style=MaterialTheme.typography.labelSmall,color=color)
}

@Composable
fun DisclosureCard(title: String, body: String, modifier: Modifier = Modifier, isCaution: Boolean = false) {
    val sem=SovereignThemeTokens.semanticColors
    val bg=if(isCaution) sem.unknownOutcomeContainer else MaterialTheme.colorScheme.surfaceContainerLow
    val accent=if(isCaution) sem.unknownOutcome else MaterialTheme.colorScheme.primary
    Surface(modifier.fillMaxWidth(),shape=MaterialTheme.shapes.medium,color=bg,
        border=BorderStroke(SovereignDimens.HairlineStroke,MaterialTheme.colorScheme.outlineVariant)) {
        Row(Modifier.padding(SovereignDimens.CardPadding),verticalAlignment=Alignment.Top) {
            SovereignInfoIcon(size=18.dp,tint=accent,modifier=Modifier.padding(top=2.dp))
            Spacer(Modifier.width(10.dp))
            Column(verticalArrangement=Arrangement.spacedBy(4.dp)) {
                Text(title,style=MaterialTheme.typography.labelLarge,color=MaterialTheme.colorScheme.onSurface)
                Text(body,style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
