package com.vandam.prism

enum class PrismAction {
    GetShizuku,
    OpenShizuku,
    AllowShizuku,
    GetReSukiSU,
    Activate,
    OpenReSukiSU,
    Retry,
}

enum class RootStatus(val displayName: String) {
    Checking("Checking"),
    Unknown("Unknown"),
    Inactive("Inactive"),
    Activating("Activating"),
    Active("Active"),
    Unsupported("Unsupported"),
}

enum class ShizukuStatus(val displayName: String) {
    Checking("Checking"),
    NotInstalled("Not installed"),
    Stopped("Stopped"),
    PermissionNeeded("Permission needed"),
    Running("Running"),
}

enum class ReSukiSUStatus(val displayName: String) {
    Checking("Checking"),
    NotInstalled("Not installed"),
    Installed("Installed"),
}

data class PrismState(
    val rootStatus: RootStatus,
    val shizukuStatus: ShizukuStatus,
    val reSukiSUStatus: ReSukiSUStatus,
    val action: PrismAction? = null,
    val actionLabel: String? = null,
    val actionEnabled: Boolean = true,
    val activation: ActivationState? = null,
    val activationVisible: Boolean = false,
) {
    companion object {
        val Checking =
            PrismState(
                rootStatus = RootStatus.Checking,
                shizukuStatus = ShizukuStatus.Checking,
                reSukiSUStatus = ReSukiSUStatus.Checking,
                actionEnabled = false,
            )
    }
}

enum class ActivationPhase {
    Working,
    Succeeded,
    Failed,
}

data class ActivationState(
    val lines: List<String>,
    val reportId: String,
    val phase: ActivationPhase = ActivationPhase.Working,
    val startedAtElapsedMillis: Long,
)
