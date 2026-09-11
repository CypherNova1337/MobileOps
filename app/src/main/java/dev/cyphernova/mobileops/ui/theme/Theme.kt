package dev.cyphernova.mobileops.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Sky = Color(0xFF38BDF8)
private val Slate = Color(0xFF0B1120)
private val SlateSurface = Color(0xFF111827)

private val DarkScheme = darkColorScheme(
    primary = Sky,
    onPrimary = Slate,
    background = Slate,
    surface = SlateSurface,
    surfaceVariant = Color(0xFF1E293B),
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0369A1),
    background = Color(0xFFF8FAFC),
    surface = Color(0xFFFFFFFF),
)

@Composable
fun MobileOpsTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkScheme else LightScheme,
        content = content,
    )
}
