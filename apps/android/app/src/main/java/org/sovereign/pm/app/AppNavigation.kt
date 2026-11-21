package org.sovereign.pm.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember

sealed interface SovereignDestination {
    data object WelcomePreview : SovereignDestination
    data object ConversationsHome : SovereignDestination
    data object SettingsOverview : SovereignDestination
    data class IntegrityError(val reasonCode: String) : SovereignDestination
}

@Stable
class SovereignNavigator(initialDestination: SovereignDestination) {
    private val backStack = mutableStateListOf(initialDestination)
    val currentDestination: SovereignDestination get() = backStack.last()
    val canNavigateBack: Boolean get() = backStack.size > 1

    fun navigateTo(destination: SovereignDestination) {
        if (backStack.lastOrNull() != destination) backStack.add(destination)
    }

    fun replaceRoot(destination: SovereignDestination) {
        backStack.clear()
        backStack.add(destination)
    }

    fun popBack(): Boolean {
        if (backStack.size <= 1) return false
        backStack.removeAt(backStack.lastIndex)
        return true
    }
}

@Composable
fun rememberSovereignNavigator(initialDestination: SovereignDestination): SovereignNavigator =
    remember(initialDestination) { SovereignNavigator(initialDestination) }
