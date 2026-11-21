package org.sovereign.pm.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

val SovereignShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

object SovereignDimens {
    val HairlineStroke = 1.dp
    val ScreenHorizontalPadding = 20.dp
    val SectionSpacing = 20.dp
    val CardPadding = 16.dp
    val CompactSpacing = 8.dp
}
