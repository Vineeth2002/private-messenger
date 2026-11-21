package org.sovereign.pm.ui.state

import androidx.compose.runtime.Immutable

enum class LocalIdentityState {
    CLEAN_INSTALL,
    LOCAL_IDENTITY_AVAILABLE,
    STORAGE_RECORD_INVALID,
    ORPHANED_KEYSTORE_KEY,
    KEY_UNAVAILABLE,
}

enum class GatewayRegistrationState {
    NOT_ATTEMPTED,
    CHALLENGE_PENDING,
    ACTIVATION_IN_PROGRESS,
    ACTIVE_CONFIRMED,
    REGISTRATION_OUTCOME_UNKNOWN,
    RECONCILIATION_REQUIRED,
}

enum class LiveConnectivityState(val displayLabel: String) {
    DISCONNECTED("Offline"), CONNECTING("Connecting"), CONNECTED("Connected"), UNREACHABLE("Unreachable")
}

/** Phase 3A UI/data contract only. It is not backed by disk persistence yet. */
@Immutable
data class GatewayRegistrationRecord(
    val state: GatewayRegistrationState = GatewayRegistrationState.NOT_ATTEMPTED,
    val gatewayOrigin: String? = null,
    val lastConfirmedEpochMillis: Long? = null,
    val unresolvedOutcomeDetail: String? = null,
)

@Immutable
data class AppShellUiState(
    val localIdentityState: LocalIdentityState,
    val localProfileLabel: String,
    val registrationRecord: GatewayRegistrationRecord = GatewayRegistrationRecord(),
    val liveConnectivity: LiveConnectivityState = LiveConnectivityState.DISCONNECTED,
    val isPreviewMode: Boolean = false,
)
