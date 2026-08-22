package com.vandam.prism.ui

import android.content.Context
import android.os.VibrationEffect
import android.os.VibratorManager
import android.os.SystemClock
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vandam.prism.ActivationPhase
import com.vandam.prism.ActivationState
import com.vandam.prism.PrismState
import com.vandam.prism.R
import com.vandam.prism.RootStatus
import java.util.Locale
import kotlinx.coroutines.delay

@Composable
fun PrismScreen(
    state: PrismState,
    onPrimaryAction: () -> Unit,
    onActivationAction: () -> Unit,
    onActivationBack: () -> Unit,
    onActivationShare: () -> Unit,
) {
    state.activation?.takeIf { state.activationVisible }?.let { activation ->
        val canLeaveActivation = activation.phase != ActivationPhase.Working
        BackHandler {
            if (canLeaveActivation) onActivationBack()
        }
        ActivationScreen(activation, onActivationAction, onActivationBack, onActivationShare)
        return
    }
    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .background(PrismTheme.background),
    ) {
        PrismHeader()
        Box(
            modifier =
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(bottom = 28.dp),
        ) {
            if (state.rootStatus != RootStatus.Checking) {
                Column(
                    modifier = Modifier.align(Alignment.TopStart).padding(start = 26.dp),
                    verticalArrangement = Arrangement.spacedBy(33.5.dp),
                ) {
                    StatusItem(label = "Root Status", value = state.rootStatus.displayName)
                    StatusItem(label = "Shizuku Status", value = state.shizukuStatus.displayName)
                    StatusItem(label = "ReSukiSU Status", value = state.reSukiSUStatus.displayName)
                }
            }
        }
        state.actionLabel?.let { label ->
            Box(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(bottom = 14.dp),
                contentAlignment = Alignment.BottomCenter,
            ) {
                PrismAction(
                    label = label,
                    enabled = state.actionEnabled,
                    onClick = onPrimaryAction,
                )
            }
        }
    }
}

@Composable
private fun ActivationScreen(
    state: ActivationState,
    onAction: () -> Unit,
    onBack: () -> Unit,
    onShare: () -> Unit,
) {
    val listState = rememberLazyListState()
    var elapsedSeconds by remember(state.startedAtElapsedMillis) {
        mutableLongStateOf(elapsedSecondsSince(state.startedAtElapsedMillis))
    }
    LaunchedEffect(state.startedAtElapsedMillis, state.phase) {
        while (state.phase == ActivationPhase.Working) {
            elapsedSeconds = elapsedSecondsSince(state.startedAtElapsedMillis)
            delay(1_000L)
        }
    }
    LaunchedEffect(state.lines.size) {
        if (state.lines.isNotEmpty()) listState.animateScrollToItem(state.lines.lastIndex)
    }
    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .background(PrismTheme.background),
    ) {
        PrismHeader(
            onBack = onBack.takeIf { state.phase != ActivationPhase.Working },
            onShare = onShare.takeIf { state.phase != ActivationPhase.Working },
            title =
                if (state.phase == ActivationPhase.Working) {
                    "Prism • ${formatElapsed(elapsedSeconds)}"
                } else {
                    "Prism"
                },
        )
        LazyColumn(
            state = listState,
            modifier =
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 26.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            items(state.lines) { line ->
                Text(text = line, style = PrismTheme.typography.log)
            }
        }
        Box(
            modifier = Modifier.fillMaxWidth().padding(bottom = 14.dp),
            contentAlignment = Alignment.BottomCenter,
        ) {
            PrismAction(
                label =
                    when (state.phase) {
                        ActivationPhase.Working -> "Working..."
                        ActivationPhase.Succeeded -> "Rooted"
                        ActivationPhase.Failed -> "Retry"
                    },
                enabled = state.phase == ActivationPhase.Failed,
                onClick = onAction,
            )
        }
    }
}

@Composable
private fun StatusItem(
    label: String,
    value: String,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.Start,
    ) {
        Text(
            text = label,
            style = PrismTheme.typography.statusLabel,
            modifier = Modifier.padding(top = 4.dp),
        )
        Text(text = value, style = PrismTheme.typography.statusValue)
    }
}

@Composable
private fun PrismHeader(
    onBack: (() -> Unit)? = null,
    onShare: (() -> Unit)? = null,
    title: String = "Prism",
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 6.dp),
    ) {
        if (onBack == null) {
            Spacer(modifier = Modifier.size(32.dp))
        } else {
            HeaderButton(R.drawable.arrow_back_ios_new_24px, "Back", onBack)
        }
        Spacer(modifier = Modifier.width(16.dp))
        Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.Center) {
            Text(
                text = title,
                style = PrismTheme.typography.title,
                modifier = Modifier.padding(top = 9.dp, bottom = 24.dp),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(modifier = Modifier.width(16.dp))
        if (onShare == null) {
            Spacer(modifier = Modifier.size(32.dp))
        } else {
            HeaderButton(R.drawable.content_copy_24px, "Share activation report", onShare)
        }
    }
}

private fun elapsedSecondsSince(startedAtElapsedMillis: Long): Long =
    ((SystemClock.elapsedRealtime() - startedAtElapsedMillis).coerceAtLeast(0L)) / 1_000L

private fun formatElapsed(totalSeconds: Long): String =
    String.format(
        Locale.ROOT,
        "%02d:%02d",
        totalSeconds / 60L,
        totalSeconds % 60L,
    )

@Composable
private fun HeaderButton(
    icon: Int,
    contentDescription: String,
    onClick: () -> Unit,
) {
    val context = LocalContext.current
    val interactionSource = remember { MutableInteractionSource() }
    Image(
        painter = painterResource(icon),
        contentDescription = contentDescription,
        colorFilter = ColorFilter.tint(PrismTheme.typography.title.color),
        modifier =
            Modifier
                .size(32.dp)
                .padding(top = 9.dp)
                .clickable(
                    interactionSource = interactionSource,
                    indication = null,
                ) {
                    vibrate(context)
                    onClick()
                },
    )
}

@Composable
private fun PrismAction(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val context = LocalContext.current
    val interactionSource = remember { MutableInteractionSource() }
    Text(
        text = label.uppercase(Locale.ROOT),
        style = PrismTheme.typography.action,
        color = if (enabled) PrismTheme.typography.action.color else Color.Gray,
        modifier =
            Modifier
                .padding(top = 8.dp)
                .clickable(
                    interactionSource = interactionSource,
                    indication = null,
                    enabled = enabled,
                ) {
                    vibrate(context)
                    onClick()
                },
    )
}

private fun vibrate(context: Context) {
    runCatching {
        val vibrator = context.getSystemService(VibratorManager::class.java).defaultVibrator
        vibrator.vibrate(VibrationEffect.createOneShot(42L, VibrationEffect.DEFAULT_AMPLITUDE))
    }
}
