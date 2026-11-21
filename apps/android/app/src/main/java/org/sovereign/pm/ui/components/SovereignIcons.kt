package org.sovereign.pm.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun SovereignShieldIcon(modifier: Modifier = Modifier, size: Dp = 20.dp,
    tint: Color = LocalContentColor.current, contentDescription: String? = null) {
    val m = if (contentDescription != null) modifier.semantics { this.contentDescription = contentDescription } else modifier
    Canvas(m.size(size)) {
        val w = this.size.width; val h = this.size.height
        val path = Path().apply {
            moveTo(w*.5f,h*.1f); lineTo(w*.84f,h*.24f); lineTo(w*.84f,h*.5f)
            cubicTo(w*.84f,h*.72f,w*.68f,h*.84f,w*.5f,h*.91f)
            cubicTo(w*.32f,h*.84f,w*.16f,h*.72f,w*.16f,h*.5f); lineTo(w*.16f,h*.24f); close()
        }
        drawPath(path,tint,style=Stroke(w*.085f,join=StrokeJoin.Round))
    }
}

@Composable
fun SovereignLockIcon(modifier: Modifier = Modifier, size: Dp = 24.dp,
    tint: Color = LocalContentColor.current, contentDescription: String? = null) {
    val m = if (contentDescription != null) modifier.semantics { this.contentDescription = contentDescription } else modifier
    Canvas(m.size(size)) {
        val w=this.size.width; val h=this.size.height; val sw=w*.085f
        val shackle=Path().apply {
            moveTo(w*.32f,h*.44f); lineTo(w*.32f,h*.30f)
            cubicTo(w*.32f,h*.15f,w*.68f,h*.15f,w*.68f,h*.30f); lineTo(w*.68f,h*.44f)
        }
        drawPath(shackle,tint,style=Stroke(sw,cap=StrokeCap.Round))
        drawRoundRect(tint,Offset(w*.2f,h*.44f),Size(w*.6f,h*.44f),CornerRadius(w*.1f),style=Stroke(sw))
        drawCircle(tint,w*.055f,Offset(w*.5f,h*.66f))
    }
}

@Composable
fun SovereignSettingsIcon(modifier: Modifier = Modifier, size: Dp = 22.dp,
    tint: Color = LocalContentColor.current, contentDescription: String? = "Settings") {
    val m = if (contentDescription != null) modifier.semantics { this.contentDescription = contentDescription } else modifier
    Canvas(m.size(size)) {
        val w=this.size.width; val h=this.size.height; val c=Offset(w*.5f,h*.5f)
        val inner=w*.14f; val outer=w*.30f; val tip=w*.41f; val sw=w*.08f
        drawCircle(tint,inner,c,style=Stroke(sw)); drawCircle(tint,outer,c,style=Stroke(sw))
        repeat(8) { i -> val a=i*45.0*(PI/180.0)
            drawLine(tint,Offset(c.x+(outer*cos(a)).toFloat(),c.y+(outer*sin(a)).toFloat()),
                Offset(c.x+(tip*cos(a)).toFloat(),c.y+(tip*sin(a)).toFloat()),sw,cap=StrokeCap.Round)
        }
    }
}

@Composable
fun SovereignInfoIcon(modifier: Modifier = Modifier, size: Dp = 18.dp,
    tint: Color = LocalContentColor.current, contentDescription: String? = null) {
    val m = if (contentDescription != null) modifier.semantics { this.contentDescription = contentDescription } else modifier
    Canvas(m.size(size)) {
        val w=this.size.width; val h=this.size.height; val c=Offset(w*.5f,h*.5f); val sw=w*.085f
        drawCircle(tint,w*.4f,c,style=Stroke(sw)); drawCircle(tint,w*.05f,Offset(w*.5f,h*.32f))
        drawLine(tint,Offset(w*.5f,h*.46f),Offset(w*.5f,h*.7f),sw,cap=StrokeCap.Round)
    }
}

@Composable
fun SovereignBackIcon(modifier: Modifier = Modifier, size: Dp = 22.dp,
    tint: Color = LocalContentColor.current, contentDescription: String? = "Back") {
    val m = if (contentDescription != null) modifier.semantics { this.contentDescription = contentDescription } else modifier
    Canvas(m.size(size)) {
        val w=this.size.width; val h=this.size.height; val sw=w*.09f
        val path=Path().apply { moveTo(w*.56f,h*.22f); lineTo(w*.28f,h*.5f); lineTo(w*.56f,h*.78f) }
        drawPath(path,tint,style=Stroke(sw,cap=StrokeCap.Round,join=StrokeJoin.Round))
        drawLine(tint,Offset(w*.3f,h*.5f),Offset(w*.78f,h*.5f),sw,cap=StrokeCap.Round)
    }
}
