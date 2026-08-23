package com.vandam.prism;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Narrow app-UID bridge for the shell-owned activation controller. */
public final class PrismAppBridgeService extends Service {
    private static final String CHANNEL = "prism-activation-bridge";
    public static final int SIGNAL_RESULT = 1;
    public static final int SIGNAL_PROGRESS = 2;
    public static final int SIGNAL_PRIVATE_CREDENTIAL = 3;
    public static final int SIGNAL_RESUKISU_STAGE_PLAN = 4;
    public static final int SIGNAL_CTLBUF_RESCUE_PLAN = 5;
    public static final int SIGNAL_TERMINAL_CLEANUP = 6;
    public static final int SIGNAL_TERMINAL_CLEANUP_STAGE = 7;
    public static final int SIGNAL_DONOR_RETIREMENT = 8;
    public static final int SIGNAL_PROC_TEARDOWN_TOKEN = 9;
    public static final int SIGNAL_CREDENTIAL_TARGET_DEATH = 10;

    public static final int GATE_ROOT_WRITE_ARM = 1;
    public static final int GATE_PRIVATE_CREDENTIAL_ARM = 2;
    public static final int GATE_ROOT_WATCHDOG_ARM = 3;
    public static final int GATE_ROOT_ACTION_DONE = 4;
    public static final int GATE_CTLBUF_DONOR_FROZEN = 5;
    public static final int GATE_ROOT_ACTION_SECURITY = 6;
    public static final int GATE_CTLBUF_FINALISE = 7;
    public static final int GATE_HELPER_NORMALISED = 8;
    public static final int GATE_HELPER_RETIRED = 9;

    private static final int READ_LIMIT = 256 * 1024;
    private static final int GATE_LIMIT = 32 * 1024;
    private static final String SESSION_PATTERN = "[0-9a-f]{64}";
    private static final String BRIDGE_NONCE_PATTERN = "[0-9a-f]{32}";
    private static final String BOOT_ID_PATTERN =
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final int MIN_PORT = 49_152;
    private static final String CAPABILITY_PREFS = "prism-activation-capability";
    private static final String CAPABILITY_SESSION = "session";
    private static final String CAPABILITY_BOOT_ID = "boot-id";
    private static final String CAPABILITY_STATE = "state";
    private static final String CAPABILITY_BRIDGE_NONCE = "bridge-nonce";
    private static final String CAPABILITY_HELPER_PID = "helper-pid";
    private static final String CAPABILITY_HELPER_START = "helper-start";
    private static final String CAPABILITY_TEARDOWN_DIGEST = "teardown-digest";
    private static final String CAPABILITY_CLOSE_RECEIPT = "close-receipt";
    private static final String CAPABILITY_SAFE_RESET_BINDING =
            "safe-reset-binding";
    private static final String STATE_PREARMED = "prearmed";
    private static final String STATE_OPEN = "open";
    private static final String STATE_STARTED = "started";
    private static final String STATE_TEARDOWN_ARMED = "teardown-armed";
    private static final String STATE_TEARDOWN_COMPLETE = "teardown-complete";
    private static final String STATE_STRICT_CLEAN = "strict-clean";
    private static final String STATE_SAFE_RESET_PENDING = "safe-reset-pending";
    private static final Object CAPABILITY_LOCK = new Object();

    private final Object lock = new Object();
    private static final ThreadLocal<Boolean> TRUSTED_LOCAL = new ThreadLocal<>();
    private String session = "";
    private String bootId = "";
    private boolean rootChainStarted;
    private volatile Thread serverThread;
    private BridgeLaunch activeLaunch;
    private BridgeLaunch pendingLaunch;
    private long nextGeneration;

    static String preArm(Context context, String requestedSession) {
        String currentBootId = readBootId();
        if (!validSession(requestedSession) ||
                !currentBootId.matches(BOOT_ID_PATTERN)) {
            return "status=fail stage=app-bridge-prearm reason=binding";
        }
        synchronized (CAPABILITY_LOCK) {
            SharedPreferences preferences = capabilityPreferences(context);
            String storedBootId = preferences.getString(CAPABILITY_BOOT_ID, "");
            String storedState = preferences.getString(CAPABILITY_STATE, "");
            if (currentBootId.equals(storedBootId) &&
                    (STATE_STARTED.equals(storedState) ||
                            STATE_TEARDOWN_ARMED.equals(storedState) ||
                            STATE_TEARDOWN_COMPLETE.equals(storedState) ||
                            STATE_STRICT_CLEAN.equals(storedState) ||
                            STATE_SAFE_RESET_PENDING.equals(storedState) ||
                            (STATE_PREARMED.equals(storedState) &&
                                    !preferences.getString(
                                            CAPABILITY_SAFE_RESET_BINDING,
                                            "").isEmpty()))) {
                String storedSession = preferences.getString(
                        CAPABILITY_SESSION, "");
                return validSession(storedSession)
                        ? "status=fail stage=app-bridge-prearm reason=busy" +
                                " session=" + storedSession +
                                " boot_id=" + currentBootId
                        : "status=fail stage=app-bridge-prearm reason=busy-invalid";
            }
            boolean committed = preferences.edit()
                    .clear()
                    .putString(CAPABILITY_SESSION, requestedSession)
                    .putString(CAPABILITY_BOOT_ID, currentBootId)
                    .putString(CAPABILITY_STATE, STATE_PREARMED)
                    .commit();
            return committed
                    ? "status=pass stage=app-bridge-prearm"
                    : "status=fail stage=app-bridge-prearm reason=storage";
        }
    }

    private final IPrismAppBridge.Stub binder = new IPrismAppBridge.Stub() {
        @Override
        public String openSession(String requestedSession, String requestedBootId) {
            if (!isShellCaller()) {
                return "status=fail stage=app-bridge-open reason=caller";
            }
            if (!validSession(requestedSession) || requestedBootId == null ||
                    !requestedBootId.matches(BOOT_ID_PATTERN) ||
                    !requestedBootId.equals(readBootId())) {
                return "status=fail stage=app-bridge-open reason=binding";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                if (!hasCapability(
                        PrismAppBridgeService.this,
                        requestedSession,
                        requestedBootId,
                        STATE_PREARMED,
                        STATE_OPEN) || rootChainStarted ||
                        !preferences.getString(
                                CAPABILITY_SAFE_RESET_BINDING,
                                "").isEmpty()) {
                    return "status=fail stage=app-bridge-open reason=busy";
                }
                if (!clearControllerFiles()) {
                    return "status=fail stage=app-bridge-open reason=cleanup";
                }
                if (!setCapabilityState(
                        PrismAppBridgeService.this,
                        requestedSession,
                        requestedBootId,
                        STATE_OPEN)) {
                    return "status=fail stage=app-bridge-open reason=storage";
                }
                session = requestedSession;
                bootId = requestedBootId;
                return "status=pass stage=app-bridge-open";
            }
        }

        @Override
        public String readSignal(String requestedSession, int signal) {
            if (!isBoundCaller(requestedSession)) {
                return "status=fail stage=app-bridge-read reason=binding";
            }
            String name = signalName(signal);
            if (name == null) {
                return "status=fail stage=app-bridge-read reason=signal";
            }
            try {
                return readSmall(new File(getFilesDir(), name));
            } catch (Exception exception) {
                return "";
            }
        }

        @Override
        public String writeGate(String requestedSession, int gate, String value) {
            if (!isBoundCaller(requestedSession)) {
                return "status=fail stage=app-bridge-write reason=binding";
            }
            String name = gateName(gate);
            if (name == null || value == null || value.length() > GATE_LIMIT ||
                    value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 ||
                    !isGateValueValid(gate, value)) {
                return "status=fail stage=app-bridge-write reason=gate";
            }
            try {
                writeAtomic(name, value);
                return "status=pass stage=app-bridge-write gate=" + gate;
            } catch (Exception exception) {
                return "status=fail stage=app-bridge-write reason=" +
                        exception.getClass().getSimpleName();
            }
        }

        @Override
        public String startRootChain(
                String requestedSession,
                String bridgeNonce,
                int helperPid,
                String helperStart,
                int donorPid,
                String donorStart,
                int ueventdPid) {
            if (!isBoundCaller(requestedSession) || bridgeNonce == null ||
                    !bridgeNonce.matches(BRIDGE_NONCE_PATTERN) ||
                    helperPid <= 0 || donorPid <= 0 || ueventdPid <= 0 ||
                    helperStart == null || !helperStart.matches("[1-9][0-9]*") ||
                    donorStart == null || !donorStart.matches("[1-9][0-9]*")) {
                return "status=fail stage=app-bridge-start reason=binding";
            }
            synchronized (lock) {
                if (rootChainStarted || !hasCapability(
                        PrismAppBridgeService.this,
                        requestedSession,
                        bootId,
                        STATE_OPEN)) {
                    return "status=fail stage=app-bridge-start reason=busy";
                }
                Intent intent = new Intent(
                        PrismAppBridgeService.this, HarnessService.class)
                        .putExtra("stage", "root-chain")
                        .putExtra("restore-after-action", false)
                        .putExtra("direct-security-cred", true)
                        .putExtra("direct-security-repair", true)
                        .putExtra("root-watchdog-nonce", bridgeNonce)
                        .putExtra("root-watchdog-helper-pid", Integer.toString(helperPid))
                        .putExtra("root-watchdog-helper-start", helperStart)
                        .putExtra("root-watchdog-boot-id", bootId)
                        .putExtra("process-teardown-supported", true)
                        .putExtra("direct-terminal-cleanup", true)
                        .putExtra("ctlbuf-ueventd-pid", Integer.toString(ueventdPid))
                        .putExtra("ctlbuf-donor-pid", Integer.toString(donorPid))
                        .putExtra("ctlbuf-donor-start", donorStart)
                        .putExtra("direct-action-after-security-swap", true);
                try {
                    if (!markCapabilityStarted(
                            PrismAppBridgeService.this,
                            requestedSession,
                            bootId,
                            bridgeNonce,
                            helperPid,
                            helperStart)) {
                        return "status=fail stage=app-bridge-start reason=storage";
                    }
                    rootChainStarted = true;
                    startForegroundService(intent);
                    return "status=pass stage=app-bridge-start";
                } catch (Exception exception) {
                    rootChainStarted = false;
                    setCapabilityState(
                            PrismAppBridgeService.this,
                            requestedSession,
                            bootId,
                            STATE_OPEN);
                    return "status=fail stage=app-bridge-start reason=" +
                            exception.getClass().getSimpleName();
                }
            }
        }

        @Override
        public String closeSession(String requestedSession) {
            if (!isShellCaller() || !validSession(requestedSession)) {
                return "status=fail stage=app-bridge-close reason=binding";
            }
            synchronized (lock) {
                String currentBootId = readBootId();
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                if (!requestedSession.equals(preferences.getString(
                                CAPABILITY_SESSION, "")) ||
                        !currentBootId.equals(preferences.getString(
                                CAPABILITY_BOOT_ID, ""))) {
                    return "status=fail stage=app-bridge-close reason=binding";
                }
                String state = preferences.getString(CAPABILITY_STATE, "");
                boolean freelyCloseable =
                        (STATE_PREARMED.equals(state) &&
                                preferences.getString(
                                        CAPABILITY_SAFE_RESET_BINDING,
                                        "").isEmpty()) ||
                        STATE_OPEN.equals(state);
                boolean receipted = STATE_STRICT_CLEAN.equals(state) &&
                        validCloseReceipt(
                                preferences.getString(
                                        CAPABILITY_CLOSE_RECEIPT, ""),
                                state,
                                requestedSession,
                                currentBootId);
                if (!freelyCloseable && !receipted) {
                    return "status=fail stage=app-bridge-close reason=active";
                }
                if (!clearCapability(
                        PrismAppBridgeService.this,
                        requestedSession,
                        currentBootId)) {
                    return "status=fail stage=app-bridge-close reason=storage";
                }
                if (receipted && !clearTransientResultFiles()) {
                    android.util.Log.w(
                            "PrismActivation",
                            "Successful diagnostics cleanup was incomplete");
                }
                rootChainStarted = false;
                session = "";
                bootId = "";
                return "status=pass stage=app-bridge-close";
            }
        }

        @Override
        public String recordStrictCleanReceipt(
                String requestedSession, String receipt) {
            if (!isBoundCaller(requestedSession) ||
                    !validCloseReceipt(
                            receipt,
                            STATE_STRICT_CLEAN,
                            requestedSession,
                            bootId)) {
                return "status=fail stage=app-bridge-strict-clean reason=binding";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                String state = preferences.getString(CAPABILITY_STATE, "");
                if (STATE_STRICT_CLEAN.equals(state)) {
                    return receipt.equals(preferences.getString(
                            CAPABILITY_CLOSE_RECEIPT, ""))
                            ? "status=pass stage=app-bridge-strict-clean"
                            : "status=fail stage=app-bridge-strict-clean reason=conflict";
                }
                if (!STATE_STARTED.equals(state) ||
                        !hasCapability(
                                PrismAppBridgeService.this,
                                requestedSession,
                                bootId,
                                STATE_STARTED)) {
                    return "status=fail stage=app-bridge-strict-clean reason=state";
                }
                boolean committed = preferences.edit()
                        .putString(CAPABILITY_STATE, STATE_STRICT_CLEAN)
                        .putString(CAPABILITY_CLOSE_RECEIPT, receipt)
                        .commit();
                return committed
                        ? "status=pass stage=app-bridge-strict-clean"
                        : "status=fail stage=app-bridge-strict-clean reason=storage";
            }
        }

        @Override
        public String recordSafeMissReceipt(
                String requestedSession,
                String result,
                String progress,
                String binding) {
            if (!isBoundCaller(requestedSession)) {
                return "status=fail stage=app-bridge-safe-miss reason=binding";
            }
            ActivationProofs.SafeAcquisitionMissProof proof =
                    ActivationProofs.parseSafeAcquisitionMiss(result, progress);
            SafeResetRecord record = SafeResetRecord.parse(binding);
            SharedPreferences preferences = capabilityPreferences(
                    PrismAppBridgeService.this);
            if (proof == null || record == null || !record.bindsProof(
                    requestedSession,
                    bootId,
                    result,
                    progress,
                    preferences.getInt(CAPABILITY_HELPER_PID, -1),
                    preferences.getString(CAPABILITY_HELPER_START, ""))) {
                return "status=fail stage=app-bridge-safe-miss reason=proof";
            }
            synchronized (lock) {
                String state = preferences.getString(CAPABILITY_STATE, "");
                if (STATE_SAFE_RESET_PENDING.equals(state)) {
                    return binding.equals(preferences.getString(
                            CAPABILITY_SAFE_RESET_BINDING, ""))
                            ? "status=pass stage=app-bridge-safe-miss"
                            : "status=fail stage=app-bridge-safe-miss reason=conflict";
                }
                if (!STATE_STARTED.equals(state) ||
                        !hasCapability(
                                PrismAppBridgeService.this,
                                requestedSession,
                                bootId,
                                STATE_STARTED)) {
                    return "status=fail stage=app-bridge-safe-miss reason=state";
                }
                boolean committed = preferences.edit()
                        .putString(
                                CAPABILITY_STATE,
                                STATE_SAFE_RESET_PENDING)
                        .putString(CAPABILITY_SAFE_RESET_BINDING, binding)
                        .remove(CAPABILITY_CLOSE_RECEIPT)
                        .commit();
                return committed
                        ? "status=pass stage=app-bridge-safe-miss"
                        : "status=fail stage=app-bridge-safe-miss reason=storage";
            }
        }

        @Override
        public String inspectSafeReset(
                String requestedSession, String requestedBootId) {
            if (!isShellCaller() || !validSession(requestedSession) ||
                    requestedBootId == null ||
                    !requestedBootId.matches(BOOT_ID_PATTERN) ||
                    !requestedBootId.equals(readBootId())) {
                return "status=fail stage=app-bridge-safe-reset-inspect reason=binding";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                if (!requestedSession.equals(preferences.getString(
                                CAPABILITY_SESSION, "")) ||
                        !requestedBootId.equals(preferences.getString(
                                CAPABILITY_BOOT_ID, ""))) {
                    return "status=fail stage=app-bridge-safe-reset-inspect reason=binding";
                }
                String state = preferences.getString(CAPABILITY_STATE, "");
                String binding = preferences.getString(
                        CAPABILITY_SAFE_RESET_BINDING, "");
                SafeResetRecord record = SafeResetRecord.parse(binding);
                if (record == null || !requestedSession.equals(record.session) ||
                        !requestedBootId.equals(record.bootId)) {
                    return "status=fail stage=app-bridge-safe-reset-inspect reason=state";
                }
                if (STATE_SAFE_RESET_PENDING.equals(state)) {
                    return "status=pass stage=app-bridge-safe-reset-inspect " +
                            "state=pending binding=" + binding;
                }
                if (STATE_PREARMED.equals(state)) {
                    return "status=pass stage=app-bridge-safe-reset-inspect " +
                            "state=complete binding=" + binding;
                }
                return "status=fail stage=app-bridge-safe-reset-inspect reason=state";
            }
        }

        @Override
        public String completeSafeReset(
                String requestedSession, String binding, String receipt) {
            if (!isShellCaller() || !validSession(requestedSession)) {
                return "status=fail stage=app-bridge-safe-reset-complete reason=binding";
            }
            SafeResetRecord record = SafeResetRecord.parse(binding);
            String currentBootId = readBootId();
            if (record == null || !requestedSession.equals(record.session) ||
                    !currentBootId.equals(record.bootId) ||
                    !validSafeResetCompletionReceipt(record, receipt)) {
                return "status=fail stage=app-bridge-safe-reset-complete reason=proof";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                if (!requestedSession.equals(preferences.getString(
                                CAPABILITY_SESSION, "")) ||
                        !currentBootId.equals(preferences.getString(
                                CAPABILITY_BOOT_ID, "")) ||
                        !binding.equals(preferences.getString(
                                CAPABILITY_SAFE_RESET_BINDING, ""))) {
                    return "status=fail stage=app-bridge-safe-reset-complete reason=binding";
                }
                String state = preferences.getString(CAPABILITY_STATE, "");
                if (STATE_PREARMED.equals(state)) {
                    return "status=pass stage=app-bridge-safe-reset-complete";
                }
                if (!STATE_SAFE_RESET_PENDING.equals(state) ||
                        !preferences.edit()
                                .putString(CAPABILITY_STATE, STATE_PREARMED)
                                .commit()) {
                    return "status=fail stage=app-bridge-safe-reset-complete reason=storage";
                }
                rootChainStarted = false;
                return "status=pass stage=app-bridge-safe-reset-complete";
            }
        }

        @Override
        public String acknowledgeSafeReset(
                String requestedSession, String binding) {
            if (!isShellCaller() || !validSession(requestedSession)) {
                return "status=fail stage=app-bridge-safe-reset-ack reason=binding";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                String currentBootId = readBootId();
                if (!requestedSession.equals(preferences.getString(
                                CAPABILITY_SESSION, "")) ||
                        !currentBootId.equals(preferences.getString(
                                CAPABILITY_BOOT_ID, "")) ||
                        !STATE_PREARMED.equals(preferences.getString(
                                CAPABILITY_STATE, "")) ||
                        !binding.equals(preferences.getString(
                                CAPABILITY_SAFE_RESET_BINDING, "")) ||
                        SafeResetRecord.parse(binding) == null ||
                        !preferences.edit()
                                .remove(CAPABILITY_SAFE_RESET_BINDING)
                                .remove(CAPABILITY_BRIDGE_NONCE)
                                .remove(CAPABILITY_HELPER_PID)
                                .remove(CAPABILITY_HELPER_START)
                                .remove(CAPABILITY_TEARDOWN_DIGEST)
                                .remove(CAPABILITY_CLOSE_RECEIPT)
                                .commit()) {
                    return "status=fail stage=app-bridge-safe-reset-ack reason=state";
                }
                return "status=pass stage=app-bridge-safe-reset-ack";
            }
        }

        @Override
        public String probe(String nonce, String requestedBootId) {
            if (!isShellCaller()) {
                return "status=fail stage=app-bridge-probe reason=caller";
            }
            if (!validSession(nonce) || requestedBootId == null ||
                    !requestedBootId.matches(BOOT_ID_PATTERN) ||
                    !requestedBootId.equals(readBootId()) ||
                    !hasCapability(
                            PrismAppBridgeService.this,
                            nonce,
                            requestedBootId,
                            STATE_PREARMED,
                            STATE_OPEN,
                            STATE_STARTED,
                            STATE_TEARDOWN_ARMED,
                            STATE_TEARDOWN_COMPLETE,
                            STATE_STRICT_CLEAN,
                            STATE_SAFE_RESET_PENDING)) {
                return "status=fail stage=app-bridge-probe reason=binding";
            }
            return "status=pass stage=app-bridge-probe uid=" + Process.myUid();
        }

        @Override
        public String validateProcessTeardown(
                String requestedSession, String token) {
            if (!isBoundCaller(requestedSession) ||
                    !hasCapability(
                            PrismAppBridgeService.this,
                            requestedSession,
                            bootId,
                            STATE_STARTED)) {
                return "status=fail stage=app-bridge-teardown-arm reason=binding";
            }
            synchronized (lock) {
                String rejection = processTeardownTokenRejection(
                        requestedSession, token, true);
                if (!rejection.isEmpty()) {
                    return "status=fail stage=app-bridge-teardown-arm reason=" +
                            rejection;
                }
                if (!setCapabilityState(
                        PrismAppBridgeService.this,
                        requestedSession,
                        bootId,
                        STATE_TEARDOWN_ARMED)) {
                    return "status=fail stage=app-bridge-teardown-arm reason=storage";
                }
                return "status=pass stage=app-bridge-teardown-arm";
            }
        }

        @Override
        public String completeProcessTeardown(
                String requestedSession, String token) {
            if (!isShellCaller() || !validSession(requestedSession) ||
                    !requestedSession.equals(session) ||
                    !bootId.equals(readBootId()) ||
                    !hasCapability(
                            PrismAppBridgeService.this,
                            requestedSession,
                            bootId,
                            STATE_PREARMED,
                            STATE_TEARDOWN_ARMED,
                            STATE_TEARDOWN_COMPLETE)) {
                return "status=fail stage=app-bridge-teardown-complete reason=binding";
            }
            synchronized (lock) {
                SharedPreferences preferences = capabilityPreferences(
                        PrismAppBridgeService.this);
                String state = preferences.getString(CAPABILITY_STATE, "");
                String digest = teardownDigest(token);
                if (digest.isEmpty()) {
                    return "status=fail stage=app-bridge-teardown-complete reason=proof";
                }

                if (STATE_TEARDOWN_ARMED.equals(state)) {
                    if (!validProcessTeardownToken(
                            requestedSession, token, false) ||
                            !preferences.edit()
                                    .putString(
                                            CAPABILITY_STATE,
                                            STATE_TEARDOWN_COMPLETE)
                                    .putString(
                                            CAPABILITY_TEARDOWN_DIGEST,
                                            digest)
                                    .commit()) {
                        return "status=fail stage=app-bridge-teardown-complete reason=proof";
                    }
                    state = STATE_TEARDOWN_COMPLETE;
                }

                if (STATE_PREARMED.equals(state)) {
                    return digest.equals(preferences.getString(
                            CAPABILITY_TEARDOWN_DIGEST, "")) &&
                            validCompletedProcessTeardown(token, false)
                            ? "status=pass stage=app-bridge-teardown-complete"
                            : "status=fail stage=app-bridge-teardown-complete reason=proof";
                }
                if (!STATE_TEARDOWN_COMPLETE.equals(state) ||
                        !digest.equals(preferences.getString(
                                CAPABILITY_TEARDOWN_DIGEST, "")) ||
                        !validCompletedProcessTeardown(token, true)) {
                    return "status=fail stage=app-bridge-teardown-complete reason=proof";
                }

                File tokenFile = new File(getFilesDir(), "proc-teardown.token");
                if (tokenFile.exists() &&
                        (!token.equals(readFileOrEmpty(tokenFile)) ||
                                !tokenFile.delete())) {
                    return "status=fail stage=app-bridge-teardown-complete reason=token";
                }
                if (tokenFile.exists() || !preferences.edit()
                        .putString(CAPABILITY_STATE, STATE_PREARMED)
                        .commit()) {
                    return "status=fail stage=app-bridge-teardown-complete reason=storage";
                }
                rootChainStarted = false;
                return "status=pass stage=app-bridge-teardown-complete";
            }
        }

        @Override
        public String inspectProcessTeardownResidue(
                String requestedSession, String requestedBootId) {
            if (!isShellCaller() || !validSession(requestedSession) ||
                    requestedBootId == null ||
                    !requestedBootId.matches(BOOT_ID_PATTERN) ||
                    !requestedBootId.equals(readBootId()) ||
                    !hasCapability(
                            PrismAppBridgeService.this,
                            requestedSession,
                            requestedBootId,
                            STATE_PREARMED,
                            STATE_OPEN,
                            STATE_STARTED,
                            STATE_TEARDOWN_ARMED,
                            STATE_TEARDOWN_COMPLETE)) {
                return "status=fail stage=app-bridge-teardown-residue reason=binding";
            }
            File tokenFile = new File(getFilesDir(), "proc-teardown.token");
            if (!tokenFile.exists()) {
                return "status=pass stage=app-bridge-teardown-residue state=absent";
            }
            String token = readFileOrEmpty(tokenFile);
            ActivationProofs.ProcessTeardownProof proof =
                    ActivationProofs.parseProcessTeardownToken(token);
            if (proof != null && !requestedBootId.equals(proof.bootId())) {
                return "status=pass stage=app-bridge-teardown-residue state=old-boot";
            }
            return "status=fail stage=app-bridge-teardown-residue state=" +
                    (proof == null ? "invalid" : "same-boot");
        }

    };

    @Override
    public IBinder onBind(Intent intent) {
        // The manifest permission filters binders before this callback. Each
        // AIDL transaction also verifies the live Binder caller as shell.
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String requestedSession = intent == null ? null :
                intent.getStringExtra("session");
        String requestedBootId = intent == null ? null :
                intent.getStringExtra("boot-id");
        int requestedPort = intent == null ? -1 : intent.getIntExtra("port", -1);
        startBridgeForeground();
        if (!validSession(requestedSession) || requestedBootId == null ||
                !requestedBootId.matches(BOOT_ID_PATTERN) ||
                !requestedBootId.equals(readBootId()) ||
                requestedPort < MIN_PORT || requestedPort > 65_535 ||
                !hasCapability(
                        this,
                        requestedSession,
                        requestedBootId,
                        STATE_PREARMED,
                        STATE_OPEN,
                        STATE_STARTED,
                        STATE_TEARDOWN_ARMED,
                        STATE_TEARDOWN_COMPLETE,
                        STATE_STRICT_CLEAN,
                        STATE_SAFE_RESET_PENDING)) {
            synchronized (lock) {
                if ((serverThread == null || !serverThread.isAlive()) &&
                        !rootChainStarted) {
                    stopForeground(true);
                    stopSelf(startId);
                }
            }
            return START_NOT_STICKY;
        }
        synchronized (lock) {
            rootChainStarted = hasCapability(
                    this,
                    requestedSession,
                    requestedBootId,
                    STATE_STARTED,
                    STATE_TEARDOWN_ARMED,
                    STATE_TEARDOWN_COMPLETE,
                    STATE_STRICT_CLEAN,
                    STATE_SAFE_RESET_PENDING);
            session = requestedSession;
            bootId = requestedBootId;
            BridgeLaunch launch = new BridgeLaunch(
                    ++nextGeneration,
                    startId,
                    requestedSession,
                    requestedBootId,
                    requestedPort);
            if (serverThread != null && serverThread.isAlive()) {
                if (activeLaunch != null && activeLaunch.sameEndpoint(launch)) {
                    return START_NOT_STICKY;
                }
                if (pendingLaunch == null ||
                        !pendingLaunch.sameEndpoint(launch)) {
                    pendingLaunch = launch;
                }
                return START_NOT_STICKY;
            }
            startServerLocked(launch);
        }
        return START_NOT_STICKY;
    }

    private void startBridgeForeground() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
                CHANNEL, "Prism activation", NotificationManager.IMPORTANCE_LOW));
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("Prism")
                .setContentText("Preparing activation")
                .setOngoing(true)
                .build();
        startForeground(2, notification);
    }

    private void startServerLocked(BridgeLaunch launch) {
        activeLaunch = launch;
        serverThread = new Thread(
                () -> serveSocket(launch),
                "prism-app-bridge-" + launch.generation);
        serverThread.start();
    }

    private void serveSocket(BridgeLaunch launch) {
        long deadline = android.os.SystemClock.elapsedRealtime() + 15_000;
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(false);
            server.bind(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), launch.port), 1);
            server.setSoTimeout(500);
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                try (Socket socket = accept(server)) {
                    if (socket == null ||
                            !socket.getInetAddress().isLoopbackAddress()) {
                        continue;
                    }
                    socket.setSoTimeout(1_000);
                    boolean authenticated = false;
                    try (DataInputStream input = new DataInputStream(socket.getInputStream());
                         DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
                        int magic = input.readInt();
                        int version = input.readInt();
                        String requestedSession = PrismAppBridgeClient.readString(input, 128);
                        String requestedBootId = PrismAppBridgeClient.readString(input, 128);
                        if (magic != PrismAppBridgeClient.MAGIC ||
                                version != PrismAppBridgeClient.VERSION ||
                                !launch.session.equals(requestedSession) ||
                                !launch.bootId.equals(requestedBootId) ||
                                !launch.bootId.equals(readBootId())) {
                            PrismAppBridgeClient.writeString(
                                    output,
                                    "status=fail stage=app-bridge-handshake reason=binding");
                            output.flush();
                            continue;
                        }
                        PrismAppBridgeClient.writeString(
                                output, "status=pass stage=app-bridge-handshake");
                        output.flush();
                        authenticated = true;
                        socket.setSoTimeout(0);
                        TRUSTED_LOCAL.set(Boolean.TRUE);
                        try {
                            serveRequests(
                                    input,
                                    output,
                                    requestedSession,
                                    requestedBootId);
                        } finally {
                            TRUSTED_LOCAL.remove();
                        }
                        return;
                    } catch (EOFException | SocketTimeoutException exception) {
                        if (authenticated) {
                            recordBridgeFailure(
                                    "authenticated-read-" +
                                            exception.getClass().getSimpleName());
                            return;
                        }
                        // Ignore unauthenticated clients until the bounded deadline.
                    }
                }
            }
        } catch (EOFException ignored) {
            // The shell controller closed its bounded session.
        } catch (Exception exception) {
            recordBridgeFailure(
                    "server-" + exception.getClass().getSimpleName());
            android.util.Log.e("PrismActivation", "App bridge socket failed", exception);
        } finally {
            synchronized (lock) {
                if (Thread.currentThread() == serverThread) {
                    serverThread = null;
                    activeLaunch = null;
                }
                BridgeLaunch next = pendingLaunch;
                pendingLaunch = null;
                if (next != null && launchStillValid(next)) {
                    startServerLocked(next);
                } else if (!rootChainStarted) {
                    stopForeground(true);
                    stopSelf();
                }
            }
        }
    }

    private boolean launchStillValid(BridgeLaunch launch) {
        return launch.bootId.equals(readBootId()) &&
                hasCapability(
                        this,
                        launch.session,
                        launch.bootId,
                        STATE_PREARMED,
                        STATE_OPEN,
                        STATE_STARTED,
                        STATE_TEARDOWN_ARMED,
                        STATE_TEARDOWN_COMPLETE,
                        STATE_STRICT_CLEAN,
                        STATE_SAFE_RESET_PENDING);
    }

    private static Socket accept(ServerSocket server) throws Exception {
        try {
            return server.accept();
        } catch (SocketTimeoutException ignored) {
            return null;
        }
    }

    private void serveRequests(
            DataInputStream input,
            DataOutputStream output,
            String requestedSession,
            String requestedBootId) throws Exception {
        while (true) {
            int operation = input.readInt();
            int count = input.readInt();
            if (count < 0 || count > 8) {
                throw new IllegalStateException("request-count");
            }
            String[] values = new String[count];
            for (int index = 0; index < count; index++) {
                values[index] = PrismAppBridgeClient.readString(input, GATE_LIMIT);
            }
            String response;
            switch (operation) {
                case PrismAppBridgeClient.OP_PROBE:
                    response = count == 0
                            ? binder.probe(requestedSession, requestedBootId)
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_OPEN:
                    response = count == 0
                            ? binder.openSession(requestedSession, requestedBootId)
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_READ:
                    response = count == 1
                            ? binder.readSignal(
                                    requestedSession, parseInt(values[0]))
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_WRITE:
                    response = count == 2
                            ? binder.writeGate(
                                    requestedSession,
                                    parseInt(values[0]),
                                    values[1])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_START:
                    response = count == 6
                            ? binder.startRootChain(
                                    requestedSession,
                                    values[0],
                                    parseInt(values[1]),
                                    values[2],
                                    parseInt(values[3]),
                                    values[4],
                                    parseInt(values[5]))
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_CLOSE:
                    response = count == 0
                            ? binder.closeSession(requestedSession)
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_VALIDATE_PROCESS_TEARDOWN:
                    response = count == 1
                            ? binder.validateProcessTeardown(
                                    requestedSession, values[0])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_COMPLETE_PROCESS_TEARDOWN:
                    response = count == 1
                            ? binder.completeProcessTeardown(
                                    requestedSession, values[0])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_INSPECT_PROCESS_TEARDOWN_RESIDUE:
                    response = count == 0
                            ? binder.inspectProcessTeardownResidue(
                                    requestedSession, requestedBootId)
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_RECORD_STRICT_CLEAN_RECEIPT:
                    response = count == 1
                            ? binder.recordStrictCleanReceipt(
                                    requestedSession, values[0])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_RECORD_SAFE_MISS_RECEIPT:
                    response = count == 3
                            ? binder.recordSafeMissReceipt(
                                    requestedSession,
                                    values[0],
                                    values[1],
                                    values[2])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_INSPECT_SAFE_RESET:
                    response = count == 0
                            ? binder.inspectSafeReset(
                                    requestedSession, requestedBootId)
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_COMPLETE_SAFE_RESET:
                    response = count == 2
                            ? binder.completeSafeReset(
                                    requestedSession, values[0], values[1])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                case PrismAppBridgeClient.OP_ACKNOWLEDGE_SAFE_RESET:
                    response = count == 1
                            ? binder.acknowledgeSafeReset(
                                    requestedSession, values[0])
                            : "status=fail stage=app-bridge-request reason=count";
                    break;
                default:
                    response = "status=fail stage=app-bridge-request reason=operation";
            }
            PrismAppBridgeClient.writeString(output, response);
            output.flush();
        }
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (Exception exception) {
            return -1;
        }
    }

    private boolean isBoundCaller(String requestedSession) {
        synchronized (lock) {
            return isShellCaller() && validSession(requestedSession) &&
                    requestedSession.equals(session) &&
                    bootId.equals(readBootId()) &&
                    hasCapability(
                            this,
                            requestedSession,
                            bootId,
                            STATE_OPEN,
                            STATE_STARTED,
                            STATE_TEARDOWN_ARMED,
                            STATE_STRICT_CLEAN);
        }
    }

    private static SharedPreferences capabilityPreferences(Context context) {
        return context.getSharedPreferences(CAPABILITY_PREFS, Context.MODE_PRIVATE);
    }

    private static boolean hasCapability(
            Context context,
            String requestedSession,
            String requestedBootId,
            String... allowedStates) {
        synchronized (CAPABILITY_LOCK) {
            SharedPreferences preferences = capabilityPreferences(context);
            if (!requestedSession.equals(
                    preferences.getString(CAPABILITY_SESSION, "")) ||
                    !requestedBootId.equals(
                            preferences.getString(CAPABILITY_BOOT_ID, ""))) {
                return false;
            }
            String state = preferences.getString(CAPABILITY_STATE, "");
            for (String allowedState : allowedStates) {
                if (allowedState.equals(state)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static boolean setCapabilityState(
            Context context,
            String requestedSession,
            String requestedBootId,
            String state) {
        synchronized (CAPABILITY_LOCK) {
            if (!hasCapability(
                    context,
                    requestedSession,
                    requestedBootId,
                    STATE_PREARMED,
                    STATE_OPEN,
                    STATE_STARTED,
                    STATE_TEARDOWN_ARMED,
                    STATE_TEARDOWN_COMPLETE,
                            STATE_STRICT_CLEAN,
                            STATE_SAFE_RESET_PENDING)) {
                return false;
            }
            return capabilityPreferences(context).edit()
                    .putString(CAPABILITY_STATE, state)
                    .commit();
        }
    }

    private static boolean markCapabilityStarted(
            Context context,
            String requestedSession,
            String requestedBootId,
            String bridgeNonce,
            int helperPid,
            String helperStart) {
        synchronized (CAPABILITY_LOCK) {
            if (!hasCapability(
                    context,
                    requestedSession,
                    requestedBootId,
                    STATE_OPEN)) {
                return false;
            }
            return capabilityPreferences(context).edit()
                    .putString(CAPABILITY_STATE, STATE_STARTED)
                    .putString(CAPABILITY_BRIDGE_NONCE, bridgeNonce)
                    .putInt(CAPABILITY_HELPER_PID, helperPid)
                    .putString(CAPABILITY_HELPER_START, helperStart)
                    .remove(CAPABILITY_TEARDOWN_DIGEST)
                    .remove(CAPABILITY_CLOSE_RECEIPT)
                    .remove(CAPABILITY_SAFE_RESET_BINDING)
                    .commit();
        }
    }

    private static boolean clearCapability(
            Context context,
            String requestedSession,
            String requestedBootId) {
        synchronized (CAPABILITY_LOCK) {
            if (!hasCapability(
                    context,
                    requestedSession,
                    requestedBootId,
                    STATE_PREARMED,
                    STATE_OPEN,
                    STATE_STARTED,
                    STATE_TEARDOWN_ARMED,
                    STATE_TEARDOWN_COMPLETE,
                            STATE_STRICT_CLEAN,
                            STATE_SAFE_RESET_PENDING)) {
                return false;
            }
            return capabilityPreferences(context).edit().clear().commit();
        }
    }

    private boolean validProcessTeardownToken(
            String requestedSession, String token, boolean processesMustBeLive) {
        return processTeardownTokenRejection(
                requestedSession, token, processesMustBeLive).isEmpty();
    }

    private String processTeardownTokenRejection(
            String requestedSession, String token,
            boolean processesMustBeLive) {
        try {
            if (token == null || token.length() > 4096 ||
                    token.indexOf('\n') >= 0 || token.indexOf('\r') >= 0) {
                return "token-format";
            }
            if (!token.equals(readSmall(
                    new File(getFilesDir(), "proc-teardown.token")))) {
                return "token-file";
            }
            if (!"0".equals(readSmall(
                    new File(getFilesDir(), "controlled-free.enable.0")))) {
                return "free-gate";
            }
            if (new File(getFilesDir(),
                    "controlled-free.result.0").exists()) {
                return "free-result";
            }
            SharedPreferences preferences = capabilityPreferences(this);
            String storedNonce = preferences.getString(
                    CAPABILITY_BRIDGE_NONCE, "");
            int storedHelperPid = preferences.getInt(CAPABILITY_HELPER_PID, -1);
            String storedHelperStart = preferences.getString(
                    CAPABILITY_HELPER_START, "");
            ActivationProofs.ProcessTeardownProof proof =
                    ActivationProofs.parseProcessTeardownToken(token);
            if (proof == null) {
                return "token-parse";
            }
            if (!proof.bindsTo(
                    storedNonce,
                    bootId,
                    storedHelperPid,
                    storedHelperStart)) {
                return "binding";
            }
            if (!requestedSession.equals(session)) {
                return "session";
            }
            if (processesMustBeLive) {
                if (!processIdentityMatches(proof.harness())) {
                    return "harness-dead";
                }
                if (!processIdentityMatches(proof.rawTarget())) {
                    return "raw-target-dead";
                }
                if (!processIdentityMatches(proof.rawClient())) {
                    return "raw-client-dead";
                }
                if (!processIdentityMatches(
                        storedHelperPid, storedHelperStart)) {
                    return "helper-dead";
                }
            } else {
                if (processIdentityMatches(proof.harness())) {
                    return "harness-live";
                }
                if (processIdentityMatches(proof.rawTarget())) {
                    return "raw-target-live";
                }
                if (processIdentityMatches(proof.rawClient())) {
                    return "raw-client-live";
                }
                if (processIdentityMatches(
                        storedHelperPid, storedHelperStart)) {
                    return "helper-live";
                }
            }
            return "";
        } catch (Exception exception) {
            return "exception-" + exception.getClass().getSimpleName();
        }
    }

    private boolean validCompletedProcessTeardown(
            String token, boolean tokenMayExist) {
        try {
            if (token == null || token.length() > 4096 ||
                    token.indexOf('\n') >= 0 || token.indexOf('\r') >= 0 ||
                    !"0".equals(readSmall(
                            new File(getFilesDir(), "controlled-free.enable.0"))) ||
                    new File(getFilesDir(), "controlled-free.result.0").exists()) {
                return false;
            }
            File tokenFile = new File(getFilesDir(), "proc-teardown.token");
            if (tokenFile.exists() &&
                    (!tokenMayExist || !token.equals(readSmall(tokenFile)))) {
                return false;
            }
            SharedPreferences preferences = capabilityPreferences(this);
            String storedNonce = preferences.getString(
                    CAPABILITY_BRIDGE_NONCE, "");
            int storedHelperPid = preferences.getInt(CAPABILITY_HELPER_PID, -1);
            String storedHelperStart = preferences.getString(
                    CAPABILITY_HELPER_START, "");
            ActivationProofs.ProcessTeardownProof proof =
                    ActivationProofs.parseProcessTeardownToken(token);
            return proof != null && proof.bindsTo(
                            storedNonce,
                            bootId,
                            storedHelperPid,
                            storedHelperStart) &&
                    !processIdentityMatches(proof.harness()) &&
                    !processIdentityMatches(proof.rawTarget()) &&
                    !processIdentityMatches(proof.rawClient()) &&
                    !processIdentityMatches(storedHelperPid, storedHelperStart);
        } catch (Exception exception) {
            return false;
        }
    }

    private static boolean processIdentityMatches(
            ActivationProofs.TokenProcessIdentity identity) {
        try {
            return processIdentityMatches(
                    Integer.parseInt(identity.pid()), identity.startTime());
        } catch (Exception exception) {
            return false;
        }
    }

    private static boolean processIdentityMatches(int pid, String startTime) {
        return pid > 0 && startTime != null && !startTime.isEmpty() &&
                startTime.equals(processStartTime(pid));
    }

    private static boolean processExists(int pid) {
        if (pid <= 0) {
            return false;
        }
        try {
            Os.kill(pid, 0);
            return true;
        } catch (ErrnoException exception) {
            return exception.errno != OsConstants.ESRCH;
        }
    }

    private static String processStartTime(int pid) {
        try {
            String value = new String(
                    Files.readAllBytes(Path.of(
                            "/proc", Integer.toString(pid), "stat")),
                    StandardCharsets.US_ASCII);
            int close = value.lastIndexOf(')');
            if (close < 0) {
                return "";
            }
            String[] fields = value.substring(close + 1).trim().split("\\s+");
            return fields.length > 19 && fields[19].matches("[0-9]+")
                    ? fields[19] : "";
        } catch (Exception exception) {
            return "";
        }
    }

    private static String teardownDigest(String token) {
        if (token == null || token.length() > 4096 ||
                token.indexOf('\n') >= 0 || token.indexOf('\r') >= 0) {
            return "";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    token.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                result.append(String.format(
                        Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (Exception exception) {
            return "";
        }
    }

    private static String readFileOrEmpty(File file) {
        try {
            return readSmall(file);
        } catch (Exception exception) {
            return "";
        }
    }

    private static boolean validCloseReceipt(
            String receipt,
            String state,
            String requestedSession,
            String requestedBootId) {
        if (receipt == null || receipt.length() > 1024 ||
                receipt.indexOf('\n') >= 0 || receipt.indexOf('\r') >= 0) {
            return false;
        }
        String binding = " session=" + requestedSession +
                " boot_id=" + requestedBootId;
        if (STATE_STRICT_CLEAN.equals(state)) {
            Matcher matcher = Pattern.compile(
                    "^version=1 kind=strict-clean" +
                            Pattern.quote(binding) +
                            " proof_sha256=([0-9a-f]{64})" +
                            " dwell_ms=([1-9][0-9]*) jobs=([0-9]{1,3})" +
                            " ksud=35088 profile=exact health=normal" +
                            " donor=unique helper=absent watchdog=absent$")
                    .matcher(receipt);
            if (!matcher.matches()) {
                return false;
            }
            try {
                return Long.parseLong(matcher.group(2)) >= 10_000 &&
                        Integer.parseInt(matcher.group(3)) < 1000;
            } catch (NumberFormatException exception) {
                return false;
            }
        }
        return false;
    }

    private static boolean validSafeResetCompletionReceipt(
            SafeResetRecord record, String receipt) {
        if (receipt == null || receipt.length() > 2048 ||
                receipt.indexOf('\n') >= 0 || receipt.indexOf('\r') >= 0) {
            return false;
        }
        Matcher matcher = Pattern.compile(
                "^version=1 kind=safe-reset-complete session=" +
                        Pattern.quote(record.session) + " boot_id=" +
                        Pattern.quote(record.bootId) + " proof_sha256=" +
                        Pattern.quote(record.proofDigest) +
                        " jobs=([0-9]{1,3}) profile=exact health=normal" +
                        " donor=exact ueventd=exact helper=absent" +
                        " holder=absent cohort=absent$")
                .matcher(receipt);
        return matcher.matches() && Integer.parseInt(matcher.group(1)) < 1000;
    }

    private static String digest(String value) {
        if (value == null || value.length() > 1024 * 1024) {
            return "";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                result.append(String.format(
                        Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (Exception exception) {
            return "";
        }
    }

    private static boolean isShellCaller() {
        return Boolean.TRUE.equals(TRUSTED_LOCAL.get()) ||
                Binder.getCallingUid() == Process.SHELL_UID;
    }

    private static boolean validSession(String value) {
        return value != null && value.matches(SESSION_PATTERN);
    }

    private static String readBootId() {
        try {
            return new String(
                    Files.readAllBytes(Path.of(
                            "/proc/sys/kernel/random/boot_id")),
                    StandardCharsets.US_ASCII).trim();
        } catch (Exception exception) {
            return "";
        }
    }

    private static String signalName(int signal) {
        switch (signal) {
            case SIGNAL_RESULT:
                return "direct.result";
            case SIGNAL_PROGRESS:
                return "chain.progress";
            case SIGNAL_PRIVATE_CREDENTIAL:
                return "private-credential.request";
            case SIGNAL_RESUKISU_STAGE_PLAN:
                return "resukisu-stage.plan";
            case SIGNAL_CTLBUF_RESCUE_PLAN:
                return "ctlbuf-rescue.plan";
            case SIGNAL_TERMINAL_CLEANUP:
                return "terminal-cleanup.result";
            case SIGNAL_TERMINAL_CLEANUP_STAGE:
                return "terminal-cleanup.stage";
            case SIGNAL_DONOR_RETIREMENT:
                return "terminal-donor-retirement.result";
            case SIGNAL_PROC_TEARDOWN_TOKEN:
                return "proc-teardown.token";
            case SIGNAL_CREDENTIAL_TARGET_DEATH:
                return "credential-target-death.result";
            default:
                return null;
        }
    }

    private static String gateName(int gate) {
        switch (gate) {
            case GATE_ROOT_WRITE_ARM:
                return "root-write-arm.done";
            case GATE_PRIVATE_CREDENTIAL_ARM:
                return "private-credential-arm.done";
            case GATE_ROOT_WATCHDOG_ARM:
                return "root-watchdog-arm.done";
            case GATE_ROOT_ACTION_DONE:
                return "root-action.done";
            case GATE_CTLBUF_DONOR_FROZEN:
                return "ctlbuf-donor-frozen.done";
            case GATE_ROOT_ACTION_SECURITY:
                return "root-action-security.done";
            case GATE_CTLBUF_FINALISE:
                return "ctlbuf-finalise.result";
            case GATE_HELPER_NORMALISED:
                return "helper-normalised.done";
            case GATE_HELPER_RETIRED:
                return "helper-retired.done";
            default:
                return null;
        }
    }

    private static boolean isGateValueValid(int gate, String value) {
        switch (gate) {
            case GATE_ROOT_WRITE_ARM:
            case GATE_ROOT_ACTION_DONE:
                return value.isEmpty();
            case GATE_PRIVATE_CREDENTIAL_ARM:
                return value.matches(
                        "nonce=[0-9a-f]{32} helper_pid=[1-9][0-9]* " +
                        "helper_start_time=[1-9][0-9]* main_tid=[1-9][0-9]* " +
                        "boot_id=[0-9a-f-]{36} host_helper_identity=1");
            case GATE_ROOT_WATCHDOG_ARM:
            case GATE_ROOT_ACTION_SECURITY:
                return value.matches(
                        "nonce=[0-9a-f]{32} helper_pid=[1-9][0-9]* " +
                        "helper_start_time=[1-9][0-9]* watchdog_tid=[1-9][0-9]* " +
                        "boot_id=[0-9a-f-]{36} host_helper_identity=1");
            case GATE_CTLBUF_DONOR_FROZEN:
                return value.matches(
                        "nonce=[0-9a-f]{32} donor_pid=[1-9][0-9]* " +
                        "donor_start_time=[1-9][0-9]* boot_id=[0-9a-f-]{36} " +
                        "host_donor_frozen=1");
            case GATE_CTLBUF_FINALISE:
                return value.startsWith("status=pass stage=ctlbuf-finalise ");
            case GATE_HELPER_NORMALISED:
                return value.startsWith("nonce=") &&
                        value.endsWith(" host_helper_identity=1");
            case GATE_HELPER_RETIRED:
                return value.startsWith("nonce=") &&
                        value.endsWith(" helper_retired=1 host_helper_identity=1");
            default:
                return false;
        }
    }

    private boolean clearControllerFiles() {
        String[] names = {
                "direct.result", "chain.progress", "root-action.done",
                "root-action-security.done", "root-write-arm.done",
                "root-watchdog-arm.done", "private-credential.request",
                "private-credential-arm.done", "helper-normalised.done",
                "helper-retired.done", "credential-target-death.result",
                "ctlbuf-finalise.result", "ctlbuf-donor-frozen.done",
                "terminal-cleanup.result", "ctlbuf-rescue.plan",
                "ctlbuf-rescue-plan.result",
                "resukisu-stage.plan", "terminal-cleanup.stage",
                "terminal-donor-retirement.result"
        };
        for (String name : names) {
            File file = new File(getFilesDir(), name);
            if (file.exists() && !file.delete()) {
                return false;
            }
        }
        return clearTransientResultFiles();
    }

    private void recordBridgeFailure(String reason) {
        synchronized (lock) {
            if (!rootChainStarted) {
                return;
            }
        }
        try {
            writeAtomic(
                    "app-bridge.failure",
                    android.os.SystemClock.elapsedRealtime() + " " + reason);
        } catch (Exception exception) {
            android.util.Log.e(
                    "PrismActivation",
                    "App bridge failure evidence could not be stored",
                    exception);
        }
    }

    private boolean clearTransientResultFiles() {
        File[] files = getFilesDir().listFiles();
        if (files == null) {
            return false;
        }
        File bridgeFailure = new File(getFilesDir(), "app-bridge.failure");
        boolean cleared = !bridgeFailure.exists() || bridgeFailure.delete();
        String rawPrefix = "raw-client.result.";
        String atomicPrefix = "direct.result.tmp.";
        for (File file : files) {
            String name = file.getName();
            boolean rawResult = name.startsWith(rawPrefix) &&
                    name.substring(rawPrefix.length()).matches("[1-9][0-9]*");
            boolean atomicResidue = name.startsWith(atomicPrefix) &&
                    name.substring(atomicPrefix.length()).matches(
                            "[1-9][0-9]*\\.[1-9][0-9]*");
            if ((rawResult || atomicResidue) &&
                    !file.delete()) {
                cleared = false;
            }
        }
        return cleared;
    }

    private void writeAtomic(String name, String value) throws Exception {
        File target = new File(getFilesDir(), name);
        File temporary = new File(getFilesDir(), name + ".app-bridge.tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            temporary.delete();
            throw new IllegalStateException("rename");
        }
    }

    private static String readSmall(File file) throws Exception {
        if (!file.isFile() || file.length() > READ_LIMIT) {
            return "";
        }
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] bytes = new byte[(int) file.length()];
            int offset = 0;
            while (offset < bytes.length) {
                int count = input.read(bytes, offset, bytes.length - offset);
                if (count < 0) {
                    break;
                }
                offset += count;
            }
            return new String(bytes, 0, offset, StandardCharsets.UTF_8).trim();
        }
    }

    private static final class BridgeLaunch {
        final long generation;
        final int startId;
        final String session;
        final String bootId;
        final int port;

        BridgeLaunch(
                long generation,
                int startId,
                String session,
                String bootId,
                int port) {
            this.generation = generation;
            this.startId = startId;
            this.session = session;
            this.bootId = bootId;
            this.port = port;
        }

        boolean sameEndpoint(BridgeLaunch other) {
            return other != null && port == other.port &&
                    session.equals(other.session) &&
                    bootId.equals(other.bootId);
        }
    }
}
