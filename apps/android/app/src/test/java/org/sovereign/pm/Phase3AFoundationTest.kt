package org.sovereign.pm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.sovereign.pm.app.SovereignDestination
import org.sovereign.pm.app.SovereignNavigator
import org.sovereign.pm.ui.components.IdenticonPattern
import org.sovereign.pm.ui.state.AppShellUiState
import org.sovereign.pm.ui.state.GatewayRegistrationRecord
import org.sovereign.pm.ui.state.GatewayRegistrationState
import org.sovereign.pm.ui.state.LiveConnectivityState
import org.sovereign.pm.ui.state.LocalIdentityState

class Phase3AFoundationTest {
    @Test fun navigator_supports_push_pop_and_root_replacement() {
        val nav=SovereignNavigator(SovereignDestination.WelcomePreview)
        assertFalse(nav.canNavigateBack)
        nav.navigateTo(SovereignDestination.ConversationsHome)
        assertTrue(nav.canNavigateBack)
        assertEquals(SovereignDestination.ConversationsHome,nav.currentDestination)
        nav.navigateTo(SovereignDestination.ConversationsHome)
        assertTrue(nav.popBack())
        assertEquals(SovereignDestination.WelcomePreview,nav.currentDestination)
        assertFalse(nav.popBack())
        nav.navigateTo(SovereignDestination.SettingsOverview)
        nav.replaceRoot(SovereignDestination.IntegrityError("ORPHANED_KEYSTORE_KEY"))
        assertFalse(nav.canNavigateBack)
        assertEquals(SovereignDestination.IntegrityError("ORPHANED_KEYSTORE_KEY"),nav.currentDestination)
    }

    @Test fun identicon_is_deterministic_and_horizontally_symmetrical() {
        val first=IdenticonPattern.generateMatrix("acct_123:dev_456")
        val repeat=IdenticonPattern.generateMatrix("acct_123:dev_456")
        val other=IdenticonPattern.generateMatrix("acct_999:dev_000")
        assertEquals(5,first.size)
        assertTrue(first.all { it.size==5 })
        assertEquals(first,repeat)
        assertNotEquals(first,other)
        first.forEach { row -> assertEquals(row[0],row[4]); assertEquals(row[1],row[3]) }
    }

    @Test fun shell_contract_keeps_identity_registration_and_connectivity_independent() {
        val state=AppShellUiState(LocalIdentityState.LOCAL_IDENTITY_AVAILABLE,"Test Device",
            GatewayRegistrationRecord(GatewayRegistrationState.ACTIVE_CONFIRMED,"https://gateway.example",1_700_000_000_000L),
            LiveConnectivityState.UNREACHABLE,true)
        assertEquals(LocalIdentityState.LOCAL_IDENTITY_AVAILABLE,state.localIdentityState)
        assertEquals(GatewayRegistrationState.ACTIVE_CONFIRMED,state.registrationRecord.state)
        assertEquals("Unreachable",state.liveConnectivity.displayLabel)
        assertTrue(state.isPreviewMode)
    }
}
