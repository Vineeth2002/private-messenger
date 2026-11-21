package org.sovereign.pm.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

// Tactile Sovereignty: warm paper-like light surfaces and restrained slate/pine dark surfaces.
val AlabasterCanvas = Color(0xFFF7F6F2)
val AlabasterSurface = Color(0xFFFFFFFF)
val AlabasterSurfaceVariant = Color(0xFFECEAE2)
val InkPrimary = Color(0xFF161917)
val InkSecondary = Color(0xFF4B524E)
val HairlineLight = Color(0xFFD5D3C9)
val ForestPineLight = Color(0xFF1E4D3B)
val OnForestPineLight = Color(0xFFFFFFFF)
val ForestContainerLight = Color(0xFFD6E8DF)
val OnForestContainerLight = Color(0xFF0C281D)
val SlateAccentLight = Color(0xFF3E524A)
val SlateContainerLight = Color(0xFFDFE6E2)

val ObsidianCanvas = Color(0xFF121417)
val ObsidianSurface = Color(0xFF191C20)
val ObsidianSurfaceVariant = Color(0xFF23282E)
val MistPrimary = Color(0xFFECEEEB)
val MistSecondary = Color(0xFFA7B0AB)
val HairlineDark = Color(0xFF2F353C)
val SagePineDark = Color(0xFF69C59B)
val OnSagePineDark = Color(0xFF08291B)
val ForestContainerDark = Color(0xFF173D2E)
val OnForestContainerDark = Color(0xFFCBE7D9)
val SlateAccentDark = Color(0xFF9FB3A9)
val SlateContainerDark = Color(0xFF26302C)

val VerifiedAmberLight = Color(0xFF9A5B13)
val VerifiedAmberContainerLight = Color(0xFFFAECD8)
val VerifiedAmberDark = Color(0xFFF2B66D)
val VerifiedAmberContainerDark = Color(0xFF3D2810)
val ErrorLight = Color(0xFF9E2A2B)
val ErrorContainerLight = Color(0xFFF9DEDC)
val ErrorDark = Color(0xFFF28B82)
val ErrorContainerDark = Color(0xFF4A1818)

val SovereignLightColorScheme = lightColorScheme(
    primary = ForestPineLight, onPrimary = OnForestPineLight,
    primaryContainer = ForestContainerLight, onPrimaryContainer = OnForestContainerLight,
    secondary = SlateAccentLight, onSecondary = Color.White,
    secondaryContainer = SlateContainerLight, onSecondaryContainer = InkPrimary,
    background = AlabasterCanvas, onBackground = InkPrimary,
    surface = AlabasterCanvas, onSurface = InkPrimary,
    surfaceVariant = AlabasterSurfaceVariant, onSurfaceVariant = InkSecondary,
    surfaceContainerLow = AlabasterSurface, surfaceContainer = AlabasterSurfaceVariant,
    outline = InkSecondary, outlineVariant = HairlineLight,
    error = ErrorLight, onError = Color.White,
    errorContainer = ErrorContainerLight, onErrorContainer = ErrorLight,
)

val SovereignDarkColorScheme = darkColorScheme(
    primary = SagePineDark, onPrimary = OnSagePineDark,
    primaryContainer = ForestContainerDark, onPrimaryContainer = OnForestContainerDark,
    secondary = SlateAccentDark, onSecondary = ObsidianCanvas,
    secondaryContainer = SlateContainerDark, onSecondaryContainer = MistPrimary,
    background = ObsidianCanvas, onBackground = MistPrimary,
    surface = ObsidianCanvas, onSurface = MistPrimary,
    surfaceVariant = ObsidianSurfaceVariant, onSurfaceVariant = MistSecondary,
    surfaceContainerLow = ObsidianSurface, surfaceContainer = ObsidianSurfaceVariant,
    outline = MistSecondary, outlineVariant = HairlineDark,
    error = ErrorDark, onError = ObsidianCanvas,
    errorContainer = ErrorContainerDark, onErrorContainer = ErrorDark,
)

@Immutable
data class SovereignSemanticColors(
    val verifiedBadge: Color,
    val verifiedContainer: Color,
    val unknownOutcome: Color,
    val unknownOutcomeContainer: Color,
    val connectedDot: Color,
    val offlineDot: Color,
)

val LocalSovereignSemanticColors = staticCompositionLocalOf {
    SovereignSemanticColors(
        verifiedBadge = VerifiedAmberLight,
        verifiedContainer = VerifiedAmberContainerLight,
        unknownOutcome = VerifiedAmberLight,
        unknownOutcomeContainer = VerifiedAmberContainerLight,
        connectedDot = ForestPineLight,
        offlineDot = InkSecondary,
    )
}
