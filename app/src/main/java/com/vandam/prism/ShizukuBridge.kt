package com.vandam.prism

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import rikka.shizuku.Shizuku

class ShizukuBridge(context: Context) {
    private val context = context.applicationContext
    private val component = ComponentName(context.packageName, PrismUserService::class.java.name)
    private val userServiceVersion =
        (context.applicationInfo.sourceDir.hashCode() and Int.MAX_VALUE)
            .takeIf { it != 0 } ?: BuildConfig.VERSION_CODE

    fun isAvailable(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    fun hasPermission(): Boolean =
        runCatching { Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED }
            .getOrDefault(false)

    fun permissionWasDenied(): Boolean =
        runCatching { Shizuku.shouldShowRequestPermissionRationale() }.getOrDefault(false)

    fun requestPermission() {
        Shizuku.requestPermission(PERMISSION_REQUEST)
    }

    suspend fun preflight(): String =
        withTimeout(15_000L) {
            suspendCancellableCoroutine { continuation ->
                val arguments =
                    Shizuku.UserServiceArgs(component)
                        .daemon(false)
                        .processNameSuffix("prism_shell")
                        .debuggable(false)
                        .version(userServiceVersion)
                        .tag("prism-preflight")
                val unbindScheduled = AtomicBoolean()
                val connection =
                    object : ServiceConnection {
                        override fun onServiceConnected(
                            name: ComponentName,
                            service: IBinder,
                        ) {
                            val result =
                                runCatching {
                                    IPrismUserService.Stub
                                        .asInterface(service)
                                        .preflight(randomNonce())
                                }.getOrElse { "status=fail reason=${it.javaClass.simpleName}" }
                            scheduleUnbind(arguments, this, true, unbindScheduled)
                            if (continuation.isActive) continuation.resume(result)
                        }

                        override fun onServiceDisconnected(name: ComponentName) {
                            if (continuation.isActive) {
                                continuation.resume("status=fail reason=service-disconnected")
                            }
                        }
                    }
                continuation.invokeOnCancellation {
                    scheduleUnbind(arguments, connection, true, unbindScheduled)
                }
                runCatching { Shizuku.bindUserService(arguments, connection) }
                    .onFailure {
                        if (continuation.isActive) {
                            continuation.resume("status=fail reason=${it.javaClass.simpleName}")
                        }
                    }
            }
        }

    suspend fun startReSukiSuActivation(managerUid: Int): ActivationHandle {
        val nonce = randomNonce()
        val startedAtElapsedMillis = SystemClock.elapsedRealtime()
        val preArm = PrismAppBridgeService.preArm(context, nonce)
        if (!preArm.startsWith("status=pass ")) {
            val stale = BUSY_PREARM.matchEntire(preArm)
                ?: return ActivationHandle(nonce, preArm, startedAtElapsedMillis)
            val staleSession = stale.groupValues[1]
            val staleBootId = stale.groupValues[2]
            val staleStartedAt = pendingStartedAt(staleSession, staleBootId)
                ?: startedAtElapsedMillis
            if (!persistPendingActivation(staleSession, staleBootId, staleStartedAt)) {
                return ActivationHandle(
                    staleSession,
                    "status=fail session=$staleSession " +
                        "phase=pending-session terminal=1 unsafe=0",
                    staleStartedAt,
                )
            }
            val recovery = callService {
                it.recoverStaleActivation(staleSession, staleBootId)
            }
            return ActivationHandle(staleSession, recovery, staleStartedAt)
        }
        val bootId = currentBootId()
        if (bootId == null ||
            !persistPendingActivation(nonce, bootId, startedAtElapsedMillis)
        ) {
            return ActivationHandle(
                nonce,
                "status=fail session=$nonce phase=pending-session terminal=1 unsafe=0",
                startedAtElapsedMillis,
            )
        }
        val result = callService { it.startReSukiSuActivation(nonce, managerUid) }
        if (isTerminalSnapshot(result, nonce) ||
            !result.startsWith("status=working session=$nonce ")
        ) {
            clearPendingActivation(nonce)
        }
        return ActivationHandle(nonce, result, startedAtElapsedMillis)
    }

    suspend fun getActivationSnapshot(handle: ActivationHandle): String {
        val result = callService { it.getActivationSnapshot(handle.nonce) }
        if (isTerminalSnapshot(result, handle.nonce)) {
            clearPendingActivation(handle.nonce)
        }
        return result
    }

    fun pendingActivation(): ActivationHandle? {
        val preferences =
            context.getSharedPreferences(PENDING_PREFERENCES, Context.MODE_PRIVATE)
        val nonce = preferences.getString(PENDING_SESSION, null)
        val bootId = preferences.getString(PENDING_BOOT_ID, null)
        val now = SystemClock.elapsedRealtime()
        if (nonce == null || !nonce.matches(Regex("[0-9a-f]{64}")) ||
            bootId == null || bootId != currentBootId()
        ) {
            preferences.edit().clear().commit()
            return null
        }
        val storedStartedAt = preferences.getLong(PENDING_STARTED_AT, -1L)
        val startedAtElapsedMillis = storedStartedAt.takeIf { it in 0..now } ?: now
        if (storedStartedAt != startedAtElapsedMillis) {
            preferences.edit().putLong(PENDING_STARTED_AT, startedAtElapsedMillis).commit()
        }
        return ActivationHandle(
            nonce,
            "status=working session=$nonce phase=reattaching terminal=0 unsafe=0",
            startedAtElapsedMillis,
        )
    }

    private fun clearPendingActivation(nonce: String) {
        val preferences =
            context.getSharedPreferences(PENDING_PREFERENCES, Context.MODE_PRIVATE)
        if (nonce == preferences.getString(PENDING_SESSION, null)) {
            preferences.edit().clear().commit()
        }
    }

    private fun persistPendingActivation(
        nonce: String,
        bootId: String,
        startedAtElapsedMillis: Long,
    ): Boolean =
        context
            .getSharedPreferences(PENDING_PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(PENDING_SESSION, nonce)
            .putString(PENDING_BOOT_ID, bootId)
            .putLong(PENDING_STARTED_AT, startedAtElapsedMillis)
            .commit()

    private fun pendingStartedAt(nonce: String, bootId: String): Long? {
        val preferences =
            context.getSharedPreferences(PENDING_PREFERENCES, Context.MODE_PRIVATE)
        val value = preferences.getLong(PENDING_STARTED_AT, -1L)
        return value.takeIf {
            nonce == preferences.getString(PENDING_SESSION, null) &&
                bootId == preferences.getString(PENDING_BOOT_ID, null) &&
                it in 0..SystemClock.elapsedRealtime()
        }
    }

    private suspend fun callService(
        action: (IPrismUserService) -> String,
    ): String =
        withTimeout(15_000L) {
            suspendCancellableCoroutine { continuation ->
                val arguments = serviceArguments()
                val unbindScheduled = AtomicBoolean()
                val connection =
                    object : ServiceConnection {
                        override fun onServiceConnected(
                            name: ComponentName,
                            service: IBinder,
                        ) {
                            val result =
                                runCatching { action(IPrismUserService.Stub.asInterface(service)) }
                                    .getOrElse { "status=fail reason=${it.javaClass.simpleName}" }
                            scheduleUnbind(arguments, this, false, unbindScheduled)
                            if (continuation.isActive) continuation.resume(result)
                        }

                        override fun onServiceDisconnected(name: ComponentName) {
                            if (continuation.isActive) {
                                continuation.resume("status=fail reason=service-disconnected")
                            }
                        }
                    }
                continuation.invokeOnCancellation {
                    scheduleUnbind(arguments, connection, false, unbindScheduled)
                }
                runCatching { Shizuku.bindUserService(arguments, connection) }
                    .onFailure {
                        if (continuation.isActive) {
                            continuation.resume("status=fail reason=${it.javaClass.simpleName}")
                        }
                    }
            }
        }

    private fun scheduleUnbind(
        arguments: Shizuku.UserServiceArgs,
        connection: ServiceConnection,
        remove: Boolean,
        scheduled: AtomicBoolean,
    ) {
        if (!scheduled.compareAndSet(false, true)) return
        mainHandler.post {
            runCatching { Shizuku.unbindUserService(arguments, connection, remove) }
        }
    }

    private fun serviceArguments(): Shizuku.UserServiceArgs =
        Shizuku.UserServiceArgs(component)
            .daemon(true)
            .processNameSuffix("prism_activation")
            .debuggable(false)
            .version(userServiceVersion)
            .tag("prism-activation")

    companion object {
        const val PERMISSION_REQUEST = 41_671
        private const val PENDING_PREFERENCES = "prism-pending-activation"
        private const val PENDING_SESSION = "session"
        private const val PENDING_BOOT_ID = "boot-id"
        private const val PENDING_STARTED_AT = "started-at-elapsed-millis"
        private val mainHandler = Handler(Looper.getMainLooper())
        private val BUSY_PREARM = Regex(
            "^status=fail stage=app-bridge-prearm reason=busy " +
                "session=([0-9a-f]{64}) boot_id=" +
                "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                "[0-9a-f]{4}-[0-9a-f]{12})$",
        )

        private fun currentBootId(): String? =
            runCatching {
                File("/proc/sys/kernel/random/boot_id").readText().trim()
            }.getOrNull()?.takeIf {
                it.matches(
                    Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
                )
            }

        private fun isTerminalSnapshot(value: String, nonce: String): Boolean {
            val header = value.lineSequence().firstOrNull() ?: return false
            return header.split(' ').toSet().containsAll(
                setOf("session=$nonce", "terminal=1"),
            )
        }

        private fun randomNonce(): String {
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
    }

    class ActivationHandle internal constructor(
        internal val nonce: String,
        val startResult: String,
        internal val startedAtElapsedMillis: Long,
    )
}
