package com.vandam.prism

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.FrameMetrics
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.vandam.prism.ui.PrismScreen
import com.vandam.prism.ui.PrismTheme
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class PrismActivity : ComponentActivity() {
    private val viewModel by viewModels<PrismViewModel>()
    private var requestedPackage: ReleasePackage? = null
    private var pendingApk: File? = null
    private var downloadJob: Job? = null
    private val activeLayoutPending = AtomicBoolean()
    private val activeFrameReported = AtomicBoolean()
    private val activeStateLaidOut = AtomicBoolean()
    private val frameMetricsHandler = Handler(Looper.getMainLooper())
    private val frameMetricsListener =
        android.view.Window.OnFrameMetricsAvailableListener { _, _, _ ->
            if (activeLayoutPending.compareAndSet(true, false) &&
                activeFrameReported.compareAndSet(false, true)
            ) {
                Log.i(
                    "PrismVisibleState",
                    "active_frame uptime_ns=${android.os.SystemClock.elapsedRealtimeNanos()}",
                )
            }
        }
    private val packageInstaller =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            ReleaseInstaller.delete(pendingApk)
            pendingApk = null
            viewModel.refresh()
        }
    private val unknownSources =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            val target = requestedPackage
            requestedPackage = null
            if (target != null && canInstallPackages()) downloadAndInstall(target) else viewModel.refresh()
        }
    private val permissionListener =
        Shizuku.OnRequestPermissionResultListener { requestCode, _ ->
            if (requestCode == ShizukuBridge.PERMISSION_REQUEST) viewModel.refresh()
        }
    private val binderReceivedListener = Shizuku.OnBinderReceivedListener { viewModel.refresh() }
    private val binderDeadListener = Shizuku.OnBinderDeadListener { viewModel.refresh() }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permissionListener)
        window.addOnFrameMetricsAvailableListener(frameMetricsListener, frameMetricsHandler)
        setContent {
            val state by viewModel.state.collectAsState()
            PrismTheme {
                PrismScreen(
                    state = state,
                    onPrimaryAction = { perform(state.action) },
                    onActivationAction = viewModel::activate,
                    onActivationBack = viewModel::closeActivationLog,
                    onActivationShare = { state.activation?.let(::shareActivationReport) },
                    onActiveLayout = {
                        activeStateLaidOut.set(true)
                        requestActiveFrameReport()
                    },
                )
            }
        }
        if (isDebuggable() && intent.getBooleanExtra(DEBUG_FAILURE_EXTRA, false)) {
            intent.removeExtra(DEBUG_FAILURE_EXTRA)
            viewModel.showDebugFailure()
        }
    }

    override fun onResume() {
        super.onResume()
        activeFrameReported.set(false)
        if (activeStateLaidOut.get()) requestActiveFrameReport()
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        window.decorView.systemUiVisibility = 0
        if (downloadJob?.isActive != true) viewModel.refresh()
    }

    override fun onPause() {
        activeLayoutPending.set(false)
        activeFrameReported.set(false)
        super.onPause()
    }

    override fun onDestroy() {
        window.removeOnFrameMetricsAvailableListener(frameMetricsListener)
        Shizuku.removeBinderReceivedListener(binderReceivedListener)
        Shizuku.removeBinderDeadListener(binderDeadListener)
        Shizuku.removeRequestPermissionResultListener(permissionListener)
        super.onDestroy()
    }

    private fun requestActiveFrameReport() {
        if (activeFrameReported.get()) return
        activeLayoutPending.set(true)
        window.decorView.postInvalidateOnAnimation()
    }

    private fun perform(action: PrismAction?) {
        when (action) {
            PrismAction.GetShizuku -> install(ReleasePackage.Shizuku)
            PrismAction.OpenShizuku -> openPackage(PrismViewModel.SHIZUKU_PACKAGE)
            PrismAction.AllowShizuku -> viewModel.requestShizukuPermission()
            PrismAction.GetReSukiSU -> install(ReleasePackage.ReSukiSU)
            PrismAction.Activate,
            PrismAction.Retry,
            -> viewModel.activate()
            PrismAction.OpenReSukiSU -> openPackage(PrismViewModel.RESUKISU_PACKAGE)
            null -> Unit
        }
    }

    private fun install(target: ReleasePackage) {
        if (canInstallPackages()) {
            downloadAndInstall(target)
            return
        }
        requestedPackage = target
        val intent =
            Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:$packageName"),
            )
        runCatching { unknownSources.launch(intent) }
            .onFailure {
                requestedPackage = null
                viewModel.refresh()
            }
    }

    private fun canInstallPackages(): Boolean = packageManager.canRequestPackageInstalls()

    private fun isDebuggable(): Boolean =
        applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    private fun downloadAndInstall(target: ReleasePackage) {
        if (downloadJob?.isActive == true) return
        viewModel.downloadStarted()
        downloadJob =
            lifecycleScope.launch {
                var apk: File? = null
                try {
                    apk = withContext(Dispatchers.IO) { ReleaseInstaller.download(this@PrismActivity, target) }
                    openInstaller(apk)
                    apk = null
                } catch (failure: CancellationException) {
                    throw failure
                } catch (_: Exception) {
                    viewModel.refresh()
                } finally {
                    withContext(NonCancellable + Dispatchers.IO) { ReleaseInstaller.delete(apk) }
                    downloadJob = null
                }
            }
    }

    private fun openInstaller(apk: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.files", apk)
        val intent =
            Intent(Intent.ACTION_INSTALL_PACKAGE)
                .setData(uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                .putExtra(Intent.EXTRA_RETURN_RESULT, true)
        pendingApk = apk
        try {
            packageInstaller.launch(intent)
        } catch (failure: Exception) {
            pendingApk = null
            throw failure
        }
    }

    private fun openPackage(packageName: String) {
        packageManager.getLaunchIntentForPackage(packageName)?.let(::startActivity)
    }

    private fun shareActivationReport(activation: ActivationState) {
        runCatching {
            val report = ActivationDiagnostics.report(activation)
            getSystemService(ClipboardManager::class.java).setPrimaryClip(
                ClipData.newPlainText("Prism report ${activation.reportId}", report),
            )
            val directory = File(cacheDir, "reports").apply { mkdirs() }
            directory.listFiles { file ->
                file.name.startsWith("prism-report-") && file.extension == "txt"
            }?.forEach(File::delete)
            val file = File(directory, "prism-report-${activation.reportId.lowercase()}.txt")
            file.writeText(report)
            val uri = FileProvider.getUriForFile(this, "$packageName.files", file)
            val send =
                Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "Prism report ${activation.reportId}")
                    .putExtra(Intent.EXTRA_TEXT, report)
                    .putExtra(Intent.EXTRA_STREAM, uri)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    .apply {
                        clipData = ClipData.newUri(contentResolver, "Prism activation report", uri)
                    }
            Toast.makeText(this, "Report copied", Toast.LENGTH_SHORT).show()
            startActivity(Intent.createChooser(send, "Send Prism report"))
        }.onFailure {
            Toast.makeText(this, "Could not share the report", Toast.LENGTH_SHORT).show()
        }
    }

    companion object {
        private const val DEBUG_FAILURE_EXTRA = "prism_debug_failure"
    }
}
