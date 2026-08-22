package com.vandam.prism

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import java.time.Instant
import java.util.Locale
import java.util.UUID

object ActivationDiagnostics {
    private val asciiArt =
        """
               /\
              / PRISM
             /____\
        """.trimIndent()

    fun newReportId(): String =
        UUID.randomUUID().toString().take(8).uppercase(Locale.ROOT)

    fun introduction(
        context: Context,
        reportId: String,
    ): List<String> =
        listOf(
            asciiArt,
            "",
            "Prism: ${packageVersion(context, context.packageName)}",
            "Report: $reportId",
            "Device: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})",
            "Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}, ${Build.DISPLAY})",
            "Kernel: ${System.getProperty("os.version") ?: "Unknown"}",
            "Shizuku: ${packageVersion(context, PrismViewModel.SHIZUKU_PACKAGE)}",
            "ReSukiSU: ${packageVersion(context, PrismViewModel.RESUKISU_PACKAGE)}",
            "",
        )

    fun report(
        activation: ActivationState,
    ): String =
        buildString {
            appendLine("Prism activation report")
            appendLine("Result: ${activation.phase.reportName}")
            appendLine("Duration: ${formatDuration(elapsedSeconds(activation))}")
            appendLine("Generated: ${Instant.now()}")
            appendLine()
            activation.lines.forEach(::appendLine)
        }

    private fun packageVersion(
        context: Context,
        packageName: String,
    ): String =
        try {
            val info = context.packageManager.getPackageInfo(packageName, 0)
            "${info.versionName ?: "Unknown"} (${info.longVersionCode})"
        } catch (_: PackageManager.NameNotFoundException) {
            "Not installed"
        }

    private fun elapsedSeconds(activation: ActivationState): Long =
        ((SystemClock.elapsedRealtime() - activation.startedAtElapsedMillis)
            .coerceAtLeast(0L)) / 1_000L

    private fun formatDuration(totalSeconds: Long): String =
        String.format(
            Locale.ROOT,
            "%02d:%02d",
            totalSeconds / 60L,
            totalSeconds % 60L,
        )

    private val ActivationPhase.reportName: String
        get() =
            when (this) {
                ActivationPhase.Working -> "In progress"
                ActivationPhase.Succeeded -> "Succeeded"
                ActivationPhase.Failed -> "Failed"
            }
}
