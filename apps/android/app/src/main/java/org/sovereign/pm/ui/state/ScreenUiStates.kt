package org.sovereign.pm.ui.state

import androidx.compose.runtime.Immutable

enum class OutboxMessageStatus { READY, ATTEMPTING, SUBMITTED, DELIVERY_UNKNOWN }

@Immutable
data class PinnedPeerConversationSummary(
    val peerAccountId: String,
    val peerDeviceId: String,
    val localNickname: String,
    val lastMessagePreview: String?,
    val lastActivityLabel: String?,
    val isManuallyPinned: Boolean = true,
)

// Deliberately not annotated @Immutable: List is a read-only interface, not a guarantee
// that the backing collection cannot be mutated. State producers must publish fresh snapshots.
data class ConversationsUiState(
    val localProfileLabel: String,
    val registrationRecord: GatewayRegistrationRecord,
    val liveConnectivity: LiveConnectivityState,
    val pinnedConversations: List<PinnedPeerConversationSummary> = emptyList(),
    val isPreviewMode: Boolean = false,
)

@Immutable
data class WelcomeUiState(val configuredGatewayOrigin: String?, val isPreviewMode: Boolean = false)

@Immutable
data class IntegrityDiagnosticUiState(
    val identityState: LocalIdentityState,
    val storageArtifactPresent: Boolean,
    val keystoreAliasPresent: Boolean,
    val diagnosticSummary: String,
)

@Immutable
data class SettingsPreviewUiState(
    val gatewayOrigin: String?,
    val registrationRecord: GatewayRegistrationRecord,
    val liveConnectivity: LiveConnectivityState,
    val screenCaptureProtectionEnabled: Boolean = true,
)
