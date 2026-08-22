package com.vandam.prism

import android.app.Application
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PrismViewModel(application: Application) : AndroidViewModel(application) {
    private val bridge = ShizukuBridge(application)
    private val mutableState = MutableStateFlow(PrismState.Checking)
    private var refreshJob: Job? = null
    private var activationJob: Job? = null

    val state: StateFlow<PrismState> = mutableState.asStateFlow()

    fun refresh() {
        if (refreshJob?.isActive == true ||
            activationJob?.isActive == true ||
            mutableState.value.activationVisible
        ) {
            return
        }
        bridge.pendingActivation()?.let { handle ->
            resumeActivation(handle)
            return
        }
        refreshJob =
            viewModelScope.launch {
                mutableState.value = withContext(Dispatchers.IO) { inspect() }
            }
    }

    fun requestShizukuPermission() {
        runCatching { bridge.requestPermission() }
            .onFailure {
                mutableState.value =
                    mutableState.value.copy(
                        shizukuStatus = ShizukuStatus.Stopped,
                        action = PrismAction.OpenShizuku,
                        actionLabel = "Shizuku",
                    )
            }
    }

    fun downloadStarted() {
        mutableState.value =
            mutableState.value.copy(
                actionLabel = "Downloading",
                actionEnabled = false,
            )
    }

    fun activate() {
        if (mutableState.value.action != PrismAction.Activate && mutableState.value.action != PrismAction.Retry) {
            return
        }
        if (activationJob?.isActive == true) return
        activationJob = viewModelScope.launch {
            val current = mutableState.value
            val reportId = ActivationDiagnostics.newReportId()
            mutableState.value =
                current.copy(
                    rootStatus = RootStatus.Activating,
                    actionLabel = "Rooting",
                    actionEnabled = false,
                    activation =
                        ActivationState(
                            lines = activationLines(reportId, listOf("[*] Preparing activation")),
                            reportId = reportId,
                            startedAtElapsedMillis = SystemClock.elapsedRealtime(),
                        ),
                    activationVisible = true,
                )
            val managerUid = installedUid(RESUKISU_PACKAGE)
            if (managerUid == null) {
                showActivationFailure("ReSukiSU is not installed.")
                return@launch
            }
            val handle =
                withContext(Dispatchers.IO) {
                    runCatching { bridge.startReSukiSuActivation(managerUid) }.getOrNull()
                }
            if (handle == null || !handle.startResult.startsWith("status=working ")) {
                showActivationFailure("Could not start the Shizuku activation service.")
                return@launch
            }
            pollActivation(handle)
        }
    }

    private fun resumeActivation(handle: ShizukuBridge.ActivationHandle) {
        if (activationJob?.isActive == true) return
        refreshJob?.cancel()
        activationJob =
            viewModelScope.launch {
                val reportId = handle.nonce.take(8).uppercase()
                mutableState.value =
                    mutableState.value.copy(
                        rootStatus = RootStatus.Activating,
                        actionLabel = "Rooting",
                        actionEnabled = false,
                        activation =
                            ActivationState(
                                lines = activationLines(reportId, listOf("[*] Recovering activation")),
                                reportId = reportId,
                                startedAtElapsedMillis = handle.startedAtElapsedMillis,
                            ),
                        activationVisible = true,
                    )
                pollActivation(handle)
            }
    }

    private suspend fun pollActivation(handle: ShizukuBridge.ActivationHandle) {
        while (true) {
            val snapshot =
                withContext(Dispatchers.IO) {
                    runCatching { bridge.getActivationSnapshot(handle) }.getOrNull()
                }
            if (snapshot == null) {
                delay(ACTIVATION_POLL_MILLIS)
                continue
            }
            val parsed = parseActivationSnapshot(snapshot)
            if (parsed == null) {
                showActivationFailure("The activation service returned an invalid status.")
                return
            }
            val currentActivation = mutableState.value.activation ?: return
            if (parsed.terminal) activationJob = null
            mutableState.value =
                mutableState.value.copy(
                    rootStatus =
                        when (parsed.phase) {
                            ActivationPhase.Working -> RootStatus.Activating
                            ActivationPhase.Succeeded -> RootStatus.Active
                            ActivationPhase.Failed -> RootStatus.Inactive
                        },
                    activation =
                        ActivationState(
                            lines = activationLines(currentActivation.reportId, parsed.lines),
                            reportId = currentActivation.reportId,
                            phase = parsed.phase,
                            startedAtElapsedMillis = currentActivation.startedAtElapsedMillis,
                        ),
                    activationVisible = parsed.phase != ActivationPhase.Succeeded,
                    action =
                        when (parsed.phase) {
                            ActivationPhase.Working -> mutableState.value.action
                            ActivationPhase.Succeeded -> PrismAction.OpenReSukiSU
                            ActivationPhase.Failed -> PrismAction.Retry
                        },
                    actionLabel =
                        when (parsed.phase) {
                            ActivationPhase.Working -> mutableState.value.actionLabel
                            ActivationPhase.Succeeded -> "Open ReSukiSU"
                            ActivationPhase.Failed -> "Retry"
                        },
                    actionEnabled = parsed.phase != ActivationPhase.Working,
                )
            if (parsed.terminal) return
            delay(ACTIVATION_POLL_MILLIS)
        }
    }

    fun closeActivationLog() {
        val current = mutableState.value
        val activation = current.activation ?: return
        val (action, label) =
            when (activation.phase) {
                ActivationPhase.Working -> return
                ActivationPhase.Succeeded -> PrismAction.OpenReSukiSU to "Open ReSukiSU"
                ActivationPhase.Failed -> PrismAction.Retry to "Retry"
            }
        mutableState.value =
            current.copy(
                activationVisible = false,
                action = action,
                actionLabel = label,
                actionEnabled = true,
            )
    }

    fun showDebugFailure() {
        refreshJob?.cancel()
        activationJob?.cancel()
        val reportId = ActivationDiagnostics.newReportId()
        mutableState.value =
            mutableState.value.copy(
                rootStatus = RootStatus.Inactive,
                shizukuStatus = ShizukuStatus.Running,
                reSukiSUStatus = ReSukiSUStatus.Installed,
                action = PrismAction.Retry,
                actionLabel = "Retry",
                actionEnabled = true,
                activation =
                    ActivationState(
                        lines =
                            activationLines(
                                reportId,
                                listOf(
                                    "[*] Starting diagnostic preview",
                                    "[+] Device profile verified",
                                    "[-] Simulated activation failure",
                                ),
                            ),
                        reportId = reportId,
                        phase = ActivationPhase.Failed,
                        startedAtElapsedMillis = SystemClock.elapsedRealtime() - 12_000L,
                    ),
                activationVisible = true,
            )
    }

    private fun showActivationFailure(message: String) {
        val previous = mutableState.value.activation ?: return
        activationJob = null
        mutableState.value =
            mutableState.value.copy(
                rootStatus = RootStatus.Inactive,
                action = PrismAction.Retry,
                actionLabel = "Retry",
                actionEnabled = true,
                activation =
                    ActivationState(
                        lines = previous.lines + "[-] $message",
                        reportId = previous.reportId,
                        phase = ActivationPhase.Failed,
                        startedAtElapsedMillis = previous.startedAtElapsedMillis,
                    ),
            )
    }

    private fun activationLines(
        reportId: String,
        lines: List<String>,
    ): List<String> =
        ActivationDiagnostics.introduction(getApplication(), reportId) + lines

    private fun parseActivationSnapshot(snapshot: String): ParsedActivation? {
        val lines = snapshot.lineSequence().toList()
        val fields =
            lines.firstOrNull()
                ?.split(' ')
                ?.mapNotNull { token ->
                    val separator = token.indexOf('=')
                    if (separator <= 0) null else token.substring(0, separator) to token.substring(separator + 1)
                }?.toMap()
                ?: return null
        val status = fields["status"] ?: return null
        val terminal = fields["terminal"] == "1"
        val phase =
            when {
                !terminal -> ActivationPhase.Working
                status == "pass" -> ActivationPhase.Succeeded
                else -> ActivationPhase.Failed
            }
        val logLines =
            lines.drop(1).map { line ->
                if (line.length > 5 && line.take(4).all(Char::isDigit) && line[4] == ' ') {
                    line.drop(5)
                } else {
                    line
                }
            }
        return ParsedActivation(
            lines = logLines.ifEmpty { listOf("Preparing activation…") },
            phase = phase,
            terminal = terminal,
        )
    }

    private suspend fun inspect(): PrismState {
        val supported = DeviceGate.verify(getApplication()).startsWith("status=pass")
        val reSukiSUInstalled = packageInstalled(RESUKISU_PACKAGE)
        val shizukuInstalled = packageInstalled(SHIZUKU_PACKAGE)
        val shizukuInspection = inspectShizuku(shizukuInstalled)
        val reSukiSUStatus =
            if (reSukiSUInstalled) ReSukiSUStatus.Installed else ReSukiSUStatus.NotInstalled
        val action =
            when {
                !supported -> null
                !shizukuInstalled -> PrismAction.GetShizuku
                !reSukiSUInstalled -> PrismAction.GetReSukiSU
                shizukuInspection.action != null -> shizukuInspection.action
                shizukuInspection.rootActive -> PrismAction.OpenReSukiSU
                shizukuInspection.status == ShizukuStatus.Running -> PrismAction.Activate
                else -> null
            }
        return PrismState(
            rootStatus =
                when {
                    !supported -> RootStatus.Unsupported
                    shizukuInspection.rootActive -> RootStatus.Active
                    shizukuInspection.status == ShizukuStatus.Running -> RootStatus.Inactive
                    else -> RootStatus.Unknown
                },
            shizukuStatus = shizukuInspection.status,
            reSukiSUStatus = reSukiSUStatus,
            action = action,
            actionLabel = actionLabel(action),
        )
    }

    private suspend fun inspectShizuku(installed: Boolean): ShizukuInspection {
        if (!installed) return ShizukuInspection(ShizukuStatus.NotInstalled, PrismAction.GetShizuku)
        if (!bridge.isAvailable()) return ShizukuInspection(ShizukuStatus.Stopped, PrismAction.OpenShizuku)
        if (!bridge.hasPermission()) {
            val action = if (bridge.permissionWasDenied()) PrismAction.OpenShizuku else PrismAction.AllowShizuku
            return ShizukuInspection(ShizukuStatus.PermissionNeeded, action)
        }
        val preflight = runCatching { bridge.preflight() }.getOrNull()
        return if (preflight?.startsWith("status=pass uid=2000") == true) {
            ShizukuInspection(
                status = ShizukuStatus.Running,
                rootActive = preflight.split(' ').contains("resukisu_active=1"),
            )
        } else {
            ShizukuInspection(ShizukuStatus.Stopped, PrismAction.OpenShizuku)
        }
    }

    private fun actionLabel(action: PrismAction?): String? =
        when (action) {
            PrismAction.GetShizuku -> "Install Shizuku"
            PrismAction.GetReSukiSU -> "Install ReSukiSU"
            PrismAction.OpenReSukiSU -> "Open ReSukiSU"
            PrismAction.OpenShizuku -> "Open Shizuku"
            PrismAction.AllowShizuku -> "Allow Shizuku"
            PrismAction.Activate -> "Root"
            else -> null
        }

    private fun packageInstalled(packageName: String): Boolean =
        try {
            getApplication<Application>().packageManager.getApplicationInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }

    private fun installedUid(packageName: String): Int? =
        try {
            getApplication<Application>().packageManager.getApplicationInfo(packageName, 0).uid
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }

    companion object {
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        const val RESUKISU_PACKAGE = "com.resukisu.resukisu"
        private const val ACTIVATION_POLL_MILLIS = 350L
    }

    private data class ShizukuInspection(
        val status: ShizukuStatus,
        val action: PrismAction? = null,
        val rootActive: Boolean = false,
    )

    private data class ParsedActivation(
        val lines: List<String>,
        val phase: ActivationPhase,
        val terminal: Boolean,
    )
}
