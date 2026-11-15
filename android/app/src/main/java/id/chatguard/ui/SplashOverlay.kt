package id.chatguard.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import id.chatguard.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun ChatGuardSplashOverlay(
    onFinished: () -> Unit,
    modifier: Modifier = Modifier
) {
    val logoAlpha = remember { Animatable(0f) }
    val logoScale = remember { Animatable(0.74f) }
    val barWidthFraction = remember { Animatable(0f) }
    val sloganAlpha = remember { Animatable(0f) }
    val sloganOffsetY = remember { Animatable(28f) }

    val infiniteTransition = rememberInfiniteTransition(label = "splash_glow")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.94f,
        targetValue = 1.12f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_scale"
    )
    val ringRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 6000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "ring_rotation"
    )

    LaunchedEffect(Unit) {
        launch {
            logoAlpha.animateTo(1f, animationSpec = tween(520, easing = FastOutSlowInEasing))
        }
        launch {
            logoScale.animateTo(1f, animationSpec = tween(720, easing = FastOutSlowInEasing))
        }
        delay(280L)
        launch {
            barWidthFraction.animateTo(1f, animationSpec = tween(480, easing = FastOutSlowInEasing))
        }
        launch {
            sloganAlpha.animateTo(1f, animationSpec = tween(560, easing = FastOutSlowInEasing))
        }
        launch {
            sloganOffsetY.animateTo(0f, animationSpec = tween(560, easing = FastOutSlowInEasing))
        }
        delay(1750L)
        onFinished()
    }

    val bgBrush = Brush.verticalGradient(
        colors = listOf(
            Color(0xFF0C141E),
            Color(0xFF121C28),
            Color(0xFF0B1119)
        )
    )

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(bgBrush)
            .padding(horizontal = 32.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(236.dp)
            ) {
                Canvas(
                    modifier = Modifier
                        .size(230.dp)
                        .graphicsLayer {
                            scaleX = pulseScale
                            scaleY = pulseScale
                            rotationZ = ringRotation
                            alpha = logoAlpha.value * 0.65f
                        }
                ) {
                    val glowBrush = Brush.sweepGradient(
                        colors = listOf(
                            Color(0x0038BDF8),
                            Color(0xAA38BDF8),
                            Color(0xCCF5C451),
                            Color(0x00F5C451)
                        )
                    )
                    drawCircle(
                        brush = glowBrush,
                        style = Stroke(width = 3.dp.toPx())
                    )
                }

                Image(
                    painter = painterResource(id = R.drawable.chatguard_logo),
                    contentDescription = "ChatGuard Logo",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .size(196.dp)
                        .graphicsLayer {
                            alpha = logoAlpha.value
                            scaleX = logoScale.value
                            scaleY = logoScale.value
                        }
                        .clip(RoundedCornerShape(36.dp))
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Box(
                modifier = Modifier
                    .width((64f * barWidthFraction.value).dp)
                    .height(3.dp)
                    .clip(RoundedCornerShape(50))
                    .background(
                        Brush.horizontalGradient(
                            listOf(Color(0xFF38BDF8), Color(0xFFF5C451))
                        )
                    )
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(id = R.string.app_slogan),
                color = Color(0xFFE2E8F0),
                style = MaterialTheme.typography.bodyLarge.copy(
                    fontSize = 15.sp,
                    lineHeight = 22.sp,
                    fontWeight = FontWeight.Medium
                ),
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .graphicsLayer {
                        alpha = sloganAlpha.value
                        translationY = sloganOffsetY.value
                    }
                    .padding(horizontal = 8.dp)
            )
        }
    }
}
