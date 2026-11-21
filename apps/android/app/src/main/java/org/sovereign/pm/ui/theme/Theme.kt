package org.sovereign.pm.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable

@Composable
fun SovereignTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) SovereignDarkColorScheme else SovereignLightColorScheme
    val semantic = if (darkTheme) {
        SovereignSemanticColors(VerifiedAmberDark, VerifiedAmberContainerDark, VerifiedAmberDark,
            VerifiedAmberContainerDark, SagePineDark, MistSecondary)
    } else {
        SovereignSemanticColors(VerifiedAmberLight, VerifiedAmberContainerLight, VerifiedAmberLight,
            VerifiedAmberContainerLight, ForestPineLight, InkSecondary)
    }
    CompositionLocalProvider(LocalSovereignSemanticColors provides semantic) {
        MaterialTheme(colorScheme = colors, typography = SovereignTypography, shapes = SovereignShapes, content = content)
    }
}

object SovereignThemeTokens {
    val semanticColors: SovereignSemanticColors
        @Composable @ReadOnlyComposable get() = LocalSovereignSemanticColors.current
}
