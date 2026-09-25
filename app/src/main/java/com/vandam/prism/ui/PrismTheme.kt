package com.vandam.prism.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.MaterialTheme
import androidx.compose.material.darkColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.PlatformTextStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vandam.prism.R

@Immutable
data class PrismTypography(
    val title: TextStyle,
    val statusLabel: TextStyle,
    val statusValue: TextStyle,
    val log: TextStyle,
    val action: TextStyle,
)

private val LocalPrismTypography =
    staticCompositionLocalOf {
        PrismTypography(
            title = TextStyle.Default,
            statusLabel = TextStyle.Default,
            statusValue = TextStyle.Default,
            log = TextStyle.Default,
            action = TextStyle.Default,
        )
    }

private val LocalPrismBackground = staticCompositionLocalOf { Color.Unspecified }

@OptIn(ExperimentalTextApi::class)
@Composable
fun PrismTheme(
    content: @Composable () -> Unit,
) {
    val textColour = Color.White
    val font = FontFamily(Font(R.font.public_sans))
    val logFont = FontFamily(Font(R.font.jetbrains_mono_regular))
    val typography =
        PrismTypography(
            title = TextStyle(fontFamily = font, fontSize = 20.sp, color = textColour),
            statusLabel =
                TextStyle(
                    fontFamily = font,
                    fontWeight = FontWeight.Light,
                    fontSize = 16.sp,
                    color = textColour,
                ),
            statusValue =
                TextStyle(
                    fontFamily = font,
                    fontWeight = FontWeight.Light,
                    fontSize = 30.sp,
                    color = textColour,
                ),
            log =
                TextStyle(
                    fontFamily = logFont,
                    fontWeight = FontWeight.Normal,
                    fontSize = 11.sp,
                    color = textColour,
                    platformStyle = PlatformTextStyle(includeFontPadding = false),
                ),
            action =
                TextStyle(
                    fontFamily = font,
                    fontSize = 32.sp,
                    color = textColour,
                    platformStyle = PlatformTextStyle(includeFontPadding = false),
                ),
        )

    CompositionLocalProvider(
        LocalPrismTypography provides typography,
        LocalPrismBackground provides Color.Black,
    ) {
        MaterialTheme(colors = darkColors(), shapes = MaterialTheme.shapes.copy(medium = RoundedCornerShape(10.dp)), content = content)
    }
}

object PrismTheme {
    val typography: PrismTypography
        @Composable get() = LocalPrismTypography.current

    val background: Color
        @Composable get() = LocalPrismBackground.current
}
