package com.vandam.prism;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Binder;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owns Prism's fixed shell-side ReSukiSU activation operation.
 *
 * <p>All kernel-mutation decisions stay in this shell-owned process. The
 * app-UID bridge only exposes fixed private markers and the exact Harness
 * launch operation.
 */
final class ReSukiSuActivationController {
    private static final String PRISM_PACKAGE = "com.vandam.prism";
    private static final String RESUKISU_PACKAGE = "com.resukisu.resukisu";
    private static final String RESUKISU_SIGNING_CERTIFICATE =
            "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64";
    private static final String NONCE_PATTERN = "[0-9a-f]{64}";
    private static final int MAX_SAME_BOOT_RETRIES = 5;
    private static final int MAX_LOG_LINES = 160;
    private static final int MAX_COMMAND_OUTPUT = 1024 * 1024;
    private static final Path BOOT_ID =
            Path.of("/proc/sys/kernel/random/boot_id");

    private static final Payload[] PAYLOADS = {
            new Payload(
                    "lp3-resukisu-ksud",
                    "/data/local/tmp/lp3-resukisu-ksud",
                    4_214_888L,
                    "7765acff69651e31629433fa6095a41b7ca034b62e17f9180c2a820b1f177483"),
            new Payload(
                    "lp3-resukisu-loader.so",
                    "/data/local/tmp/lp3-resukisu-loader.so",
                    1_301_464L,
                    "1fe42682ad736f43eb5acb42dc0ebba79828a6090f61e47970277b12fdb61275"),
    };

    private final Context context;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Object lock = new Object();
    private final ArrayDeque<String> logLines = new ArrayDeque<>();

    private String session = "";
    private String status = "idle";
    private String phase = "idle";
    private boolean terminal = true;
    private boolean unsafe;
    private int sequence;

    ReSukiSuActivationController(Context context) {
        this.context = context;
    }

    String start(String nonce, int managerUid) {
        if (nonce == null || !nonce.matches(NONCE_PATTERN)) {
            return header("fail", safeSession(nonce), "request-nonce", true, false);
        }
        if (Binder.getCallingUid() != prismUid()) {
            return header("fail", nonce, "caller-identity", true, false);
        }
        synchronized (lock) {
            if (!terminal) {
                return header("fail", nonce, "busy", true, false);
            }
            session = nonce;
            status = "working";
            phase = "preflight";
            terminal = false;
            unsafe = false;
            sequence = 0;
            logLines.clear();
            appendLocked("[*] Starting Prism activation");
        }
        executor.execute(() -> runPreflight(nonce, managerUid));
        return header("working", nonce, "preflight", false, false);
    }

    String snapshot(String nonce) {
        if (nonce == null || !nonce.matches(NONCE_PATTERN)) {
            return header("fail", safeSession(nonce), "request-nonce", true, false);
        }
        if (Binder.getCallingUid() != prismUid()) {
            return header("fail", nonce, "caller-identity", true, false);
        }
        synchronized (lock) {
            if (!nonce.equals(session)) {
                boolean active = false;
                if (terminal) {
                    active = canRecoverPendingActive(nonce);
                }
                if (!active) {
                    return header("fail", nonce, "unknown-session", true, false);
                }
                session = nonce;
                status = "pass";
                phase = "already-active";
                terminal = true;
                unsafe = false;
                sequence = 0;
                logLines.clear();
                appendLocked("[+] ReSukiSU is already active");
            }
            StringBuilder snapshot = new StringBuilder(header(
                    status, session, phase, terminal, unsafe));
            for (String line : logLines) {
                snapshot.append('\n').append(line);
            }
            return snapshot.toString();
        }
    }

    private boolean canRecoverPendingActive(String nonce) {
        try {
            if (Os.getuid() != Process.SHELL_UID ||
                    Os.getgid() != Process.SHELL_UID ||
                    !"status=pass stage=device-gate "
                            .concat("profile=tlp301-00ww-1-440000")
                            .equals(DeviceGate.verify(context))) {
                return false;
            }
            String currentBootId = new String(
                    Files.readAllBytes(BOOT_ID), StandardCharsets.UTF_8).trim();
            if (!currentBootId.matches(
                    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12}")) {
                return false;
            }
            if (!isReSukiSuActive()) {
                return false;
            }
            try (PrismAppBridgeClient appBridge =
                         PrismAppBridgeClient.connect(
                                 context, nonce, currentBootId)) {
                if (!appBridge.closeSession().startsWith("status=pass ")) {
                    return false;
                }
            } catch (Exception ignored) {
                // A completed activation normally has no remaining capability.
            }
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    String recoverStaleActivation(String staleSession, String staleBootId) {
        if (staleSession == null || !staleSession.matches(NONCE_PATTERN) ||
                staleBootId == null || !staleBootId.matches(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                                "[0-9a-f]{4}-[0-9a-f]{12}")) {
            return header(
                    "fail", safeSession(staleSession),
                    "stale-recovery-binding", true, false);
        }
        if (Binder.getCallingUid() != prismUid()) {
            return header(
                    "fail", staleSession,
                    "caller-identity", true, false);
        }
        synchronized (lock) {
            if (!terminal) {
                return header("fail", staleSession, "busy", true, false);
            }
            session = staleSession;
            status = "working";
            phase = "stale-recovery";
            terminal = false;
            unsafe = false;
            sequence = 0;
            logLines.clear();
            appendLocked("[!] Resuming interrupted activation cleanup");
        }
        executor.execute(() -> runStaleActivationRecovery(
                staleSession, staleBootId));
        return header(
                "working", staleSession, "stale-recovery", false, false);
    }

    private void runStaleActivationRecovery(
            String staleSession, String staleBootId) {
        try {
            requireShellIdentity();
            String currentBootId = new String(
                    Files.readAllBytes(BOOT_ID), StandardCharsets.UTF_8).trim();
            if (!staleBootId.equals(currentBootId)) {
                finish(
                        "fail", "stale-recovery-binding", false,
                        "The stale activation belongs to another boot");
                return;
            }
            if (resumeSafeReset(staleSession, staleBootId)) {
                return;
            }
            try (PrismAppBridgeClient appBridge = PrismAppBridgeClient.connect(
                    context, staleSession, staleBootId)) {
                String probe = appBridge.probe();
                if (!probe.startsWith("status=pass ")) {
                    append("The stale app capability could not be authenticated");
                } else {
                    append("The stale app capability was authenticated");
                    appBridge.inspectProcessTeardownResidue();
                    append("Interrupted process state inspected");
                }
            } catch (Exception exception) {
                append("The stale app capability could not be reached");
            }
            append("[!] Requesting a confirmed safety reboot");
            requestConfirmedSafetyReboot(staleBootId);
            finish(
                    "fail", "safety-reboot-complete", false,
                    "The safety reboot changed the boot identity");
        } catch (Exception exception) {
            append("Stale activation recovery could not validate shell identity");
            requestConfirmedSafetyReboot(staleBootId);
        }
    }

    private boolean resumeSafeReset(String staleSession, String staleBootId) {
        SafeResetRecord record = null;
        SafeResetRecord.Journal journal = SafeResetCoordinator.readJournal();
        if (journal != null &&
                staleSession.equals(journal.record.session) &&
                staleBootId.equals(journal.record.bootId)) {
            record = journal.record;
            append("Recovered safe reset checkpoint: " + journal.checkpoint);
        }

        try (PrismAppBridgeClient bridge = PrismAppBridgeClient.connect(
                context, staleSession, staleBootId)) {
            String inspection = bridge.inspectSafeReset();
            String pendingPrefix =
                    "status=pass stage=app-bridge-safe-reset-inspect " +
                            "state=pending binding=";
            String completePrefix =
                    "status=pass stage=app-bridge-safe-reset-inspect " +
                            "state=complete binding=";
            if (inspection.startsWith(pendingPrefix) ||
                    inspection.startsWith(completePrefix)) {
                String prefix = inspection.startsWith(pendingPrefix)
                        ? pendingPrefix : completePrefix;
                SafeResetRecord appRecord = SafeResetRecord.parse(
                        inspection.substring(prefix.length()));
                if (appRecord == null ||
                        !staleSession.equals(appRecord.session) ||
                        !staleBootId.equals(appRecord.bootId) ||
                        (record != null && !record.binding().equals(
                                appRecord.binding()))) {
                    append("The durable safe reset bindings conflict");
                    finish(
                            "fail", "safe-reset-pending", false,
                            "The no-mutation proof is safe and process cleanup remains pending");
                    return true;
                }
                record = appRecord;
                if (journal == null) {
                    SafeResetCoordinator.writeJournal(
                            record,
                            inspection.startsWith(completePrefix)
                                    ? SafeResetRecord.CHECKPOINT_BASELINE_VERIFIED
                                    : SafeResetRecord.CHECKPOINT_APP_RECEIPT);
                    append("Restored the shell safe reset checkpoint");
                }
            } else if (record != null) {
                String result = bridge.readSignal(
                        PrismAppBridgeService.SIGNAL_RESULT);
                String progress = bridge.readSignal(
                        PrismAppBridgeService.SIGNAL_PROGRESS);
                ActivationProofs.SafeAcquisitionMissProof proof =
                        ActivationProofs.parseSafeAcquisitionMiss(
                                result, progress);
                if (proof != null && bridge.recordSafeMissReceipt(
                        result,
                        progress,
                        record.binding()).startsWith("status=pass ")) {
                    SafeResetCoordinator.writeJournal(
                            record,
                            SafeResetRecord.CHECKPOINT_APP_RECEIPT);
                    append("Restored the app safe reset checkpoint");
                }
            }
        } catch (Exception exception) {
            if (record == null) {
                return false;
            }
            append("App safe reset checkpoint will be retried after process cleanup");
        }

        if (record == null) {
            return false;
        }
        advance("safe-reset-resume", "Resuming proven no-mutation cleanup");
        boolean completed = new SafeResetCoordinator(
                context, record, this::append).complete();
        finish(
                "fail",
                completed ? "safe-reset-complete" : "safe-reset-pending",
                false,
                completed
                        ? "The no-mutation reset passed; tap Root to retry"
                        : "The no-mutation proof is safe and process cleanup remains pending");
        return true;
    }

    private void runPreflight(String nonce, int managerUid) {
        try {
            requireSession(nonce);
            requireShellIdentity();
            advance("manager", "Checking the ReSukiSU manager identity");
            requireManagerUid(managerUid);

            advance("device-gate", "Checking the supported Light Phone build");
            String deviceGate = DeviceGate.verify(context);
            if (!deviceGate.startsWith("status=pass ")) {
                throw new GateException("device-gate", deviceGate);
            }
            append("Supported Light Phone build verified");

            advance("kernel-gate", "Checking the terminal cleanup kernel layout");
            requireTerminalCleanupKernelConfiguration();
            append("Kernel layout gate passed");

            advance(
                    "credential-layout-gate",
                    "Checking the exact credential layout profile");
            requireCredentialLayoutProfile();
            append("Credential layout profile verified");

            advance("jobs-gate", "Checking system job pressure");
            int registeredJobs = registeredJobCount();
            if (registeredJobs >= 1000) {
                throw new GateException(
                        "jobs-gate", "The registered JobScheduler count is unsafe");
            }
            append("Registered system jobs: " + registeredJobs);

            advance("process-gate", "Checking for a stale activation helper");
            requireNoExistingHelper();
            append("No stale activation helper is running");

            advance("payload-stage", "Verifying and staging signed-in payload bytes");
            for (Payload payload : PAYLOADS) {
                stagePayload(payload, nonce);
            }
            append("Signed activation payloads verified and staged");

            advance("app-bridge", "Checking the activation bridge");
            String bootId = new String(
                    Files.readAllBytes(BOOT_ID), StandardCharsets.UTF_8).trim();
            try (PrismAppBridgeClient appBridge =
                         PrismAppBridgeClient.connect(context, nonce, bootId)) {
                String bridgeState = appBridge.probe();
                if (!bridgeState.startsWith("status=pass ")) {
                    throw new GateException("app-bridge", bridgeState);
                }
                Thread.sleep(1_250);
                String idleState = appBridge.probe();
                if (!idleState.startsWith("status=pass ")) {
                    throw new GateException("app-bridge", idleState);
                }
                append("Activation bridge verified");

                advance(
                        "teardown-residue",
                        "Checking interrupted process state");
                String residue = appBridge.inspectProcessTeardownResidue();
                if (!residue.startsWith("status=pass ")) {
                    finish(
                            "fail", "teardown-residue", true,
                            "An unresolved same-boot teardown requires a safety reboot");
                    requestConfirmedSafetyReboot(bootId);
                    return;
                }
                append("Process state is clean");

                advance("active-check", "Checking whether ReSukiSU is already active");
                if (isReSukiSuActive()) {
                    String closed = appBridge.closeSession();
                    if (!closed.startsWith("status=pass ")) {
                        throw new GateException("app-bridge", closed);
                    }
                    finish(
                            "pass", "already-active", false,
                            "ReSukiSU is already active");
                    return;
                }
            }

            DirectReSukiSuActivation.Reporter reporter =
                    new DirectReSukiSuActivation.Reporter() {
                        @Override
                        public void phase(String value, String message) {
                            advance(value, message);
                        }

                        @Override
                        public void log(String message) {
                            append(message);
                        }
                    };
            int retries = 0;
            while (true) {
                requireSession(nonce);
                append("[*] Activation attempt " + (retries + 1));
                DirectReSukiSuActivation.Result result =
                        new DirectReSukiSuActivation(
                                context, nonce, managerUid, reporter).run();
                if (!"retry".equals(result.status)) {
                    finish(result.status, result.phase, result.unsafe, result.message);
                    return;
                }
                retries++;
                if (retries > MAX_SAME_BOOT_RETRIES) {
                    closePrearmedBridge(nonce, bootId);
                    finish(
                            "fail", "same-boot-retry-limit", false,
                            "Activation exhausted five safe same-boot retries");
                    return;
                }
                advance(
                        "same-boot-retry",
                        "Retrying activation attempt " + (retries + 1));
            }
        } catch (GateException exception) {
            finish("fail", exception.phase, false, exception.getMessage());
        } catch (Exception exception) {
            android.util.Log.e(
                    "PrismActivation", "Activation preflight failed", exception);
            finish(
                    "fail",
                    "preflight-error",
                    false,
                    "Preflight stopped: " + exception.getClass().getSimpleName());
        }
    }

    private void closePrearmedBridge(String nonce, String bootId) {
        try (PrismAppBridgeClient appBridge =
                     PrismAppBridgeClient.connect(context, nonce, bootId)) {
            String closed = appBridge.closeSession();
            if (!closed.startsWith("status=pass ")) {
                append("The exhausted retry capability could not be closed");
            }
        } catch (Exception exception) {
            append("The exhausted retry capability could not be reached");
        }
    }

    private void requestConfirmedSafetyReboot(String originalBootId) {
        while (true) {
            try {
                String current = new String(
                        Files.readAllBytes(BOOT_ID), StandardCharsets.UTF_8).trim();
                if (current.matches(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                                "[0-9a-f]{4}-[0-9a-f]{12}") &&
                        !originalBootId.equals(current)) {
                    return;
                }
                java.lang.Process reboot = new ProcessBuilder("/system/bin/reboot")
                        .redirectErrorStream(true)
                        .start();
                reboot.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
                if (reboot.isAlive()) {
                    reboot.destroyForcibly();
                }
            } catch (Exception ignored) {
                // Retry until the boot identity proves that the unsafe state ended.
            }
            try {
                Thread.sleep(3_000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void requireSession(String nonce) throws GateException {
        synchronized (lock) {
            if (!nonce.equals(session) || terminal) {
                throw new GateException("session", "Activation session changed");
            }
        }
    }

    private void requireShellIdentity() throws GateException {
        if (Os.getuid() != Process.SHELL_UID || Os.getgid() != Process.SHELL_UID) {
            throw new GateException("shell-identity", "Shizuku service is not shell");
        }
    }

    private int prismUid() {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                    PRISM_PACKAGE, 0);
            return info.uid;
        } catch (Exception ignored) {
            return -1;
        }
    }

    private void requireManagerUid(int requestedUid) throws GateException {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                    RESUKISU_PACKAGE, 0);
            if (requestedUid < Process.FIRST_APPLICATION_UID ||
                    requestedUid > Process.LAST_APPLICATION_UID ||
                    info.uid != requestedUid) {
                throw new GateException(
                        "manager-identity", "ReSukiSU manager UID does not match");
            }
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    RESUKISU_PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES);
            if (packageInfo.signingInfo == null ||
                    packageInfo.signingInfo.hasMultipleSigners()) {
                throw new GateException(
                        "manager-identity", "ReSukiSU manager signer does not match");
            }
            Signature[] signers = packageInfo.signingInfo.getApkContentsSigners();
            if (signers == null || signers.length != 1) {
                throw new GateException(
                        "manager-identity", "ReSukiSU manager signer does not match");
            }
            String certificate = hex(MessageDigest.getInstance("SHA-256")
                    .digest(signers[0].toByteArray()));
            if (!RESUKISU_SIGNING_CERTIFICATE.equals(certificate)) {
                throw new GateException(
                        "manager-identity", "ReSukiSU manager signer does not match");
            }
            append("ReSukiSU manager UID verified: " + requestedUid);
        } catch (GateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new GateException("manager-identity", "ReSukiSU manager is not installed");
        }
    }

    private void requireTerminalCleanupKernelConfiguration() throws Exception {
        String config = executeFixed(
                "/system/bin/sh", "-c", "exec /system/bin/toybox zcat /proc/config.gz");
        Set<String> lines = new HashSet<>(Arrays.asList(config.split("\\n")));
        if (!config.startsWith("#") ||
                !lines.contains("# CONFIG_DEBUG_CREDENTIALS is not set") ||
                !lines.contains("CONFIG_KEYS=y") ||
                !lines.contains("CONFIG_SECURITY=y")) {
            throw new GateException("kernel-gate", "Kernel cleanup prerequisites do not match");
        }
        for (String line : lines) {
            if (line.matches("CONFIG_[A-Z0-9_]*RANDSTRUCT[A-Z0-9_]*=(?:y|m)")) {
                throw new GateException("kernel-gate", "Kernel layout is randomised");
            }
        }
    }

    private void requireCredentialLayoutProfile() throws Exception {
        JSONObject layout;
        try (InputStream input = context.getAssets().open("device_profiles.json");
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 256 * 1024) {
                    throw new GateException(
                            "credential-layout-gate", "The device profile is too large");
                }
                output.write(buffer, 0, count);
            }
            JSONObject root = new JSONObject(
                    output.toString(StandardCharsets.UTF_8.name()));
            layout = root.getJSONArray("profiles")
                    .getJSONObject(0)
                    .getJSONObject("kernel")
                    .getJSONObject("credential_layout");
        }
        Set<String> expected = new HashSet<>(Arrays.asList(
                "task_real_cred_offset", "task_cred_offset",
                "cred_security_offset", "cred_user_offset",
                "cred_user_ns_offset", "cred_group_info_offset",
                "cred_rcu_offset", "debug_credentials", "randstruct",
                "ucounts_present", "shell_securebits"));
        Set<String> actual = new HashSet<>();
        java.util.Iterator<String> keys = layout.keys();
        while (keys.hasNext()) {
            actual.add(keys.next());
        }
        if (!actual.equals(expected) ||
                !"0x778".equals(layout.getString("task_real_cred_offset")) ||
                !"0x780".equals(layout.getString("task_cred_offset")) ||
                !"0x78".equals(layout.getString("cred_security_offset")) ||
                !"0x80".equals(layout.getString("cred_user_offset")) ||
                !"0x88".equals(layout.getString("cred_user_ns_offset")) ||
                !"0x90".equals(layout.getString("cred_group_info_offset")) ||
                !"0x98".equals(layout.getString("cred_rcu_offset")) ||
                layout.getBoolean("debug_credentials") ||
                layout.getBoolean("randstruct") ||
                layout.getBoolean("ucounts_present") ||
                layout.getInt("shell_securebits") != 47) {
            throw new GateException(
                    "credential-layout-gate",
                    "The credential layout profile does not match");
        }
    }

    private static int registeredJobCount() throws Exception {
        String output = executeFixed("/system/bin/dumpsys", "jobscheduler");
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "(?m)^Registered ([0-9]+) jobs:$").matcher(output);
        if (!matcher.find()) {
            throw new GateException(
                    "jobs-gate", "The registered JobScheduler count is unavailable");
        }
        int count = Integer.parseInt(matcher.group(1));
        if (matcher.find()) {
            throw new GateException(
                    "jobs-gate", "The registered JobScheduler count is ambiguous");
        }
        return count;
    }

    private void requireNoExistingHelper() throws Exception {
        String processes = executeFixed(
                "/system/bin/ps", "-A", "-o", "PID,ARGS");
        for (String line : processes.split("\\n")) {
            if (line.contains("com.vandam.prism.ShellBridgeMain")) {
                throw new GateException("process-gate", "A stale activation helper is running");
            }
        }
    }

    private void stagePayload(Payload payload, String nonce) throws Exception {
        File target = new File(payload.targetPath);
        if (isExactPayload(target, payload)) {
            return;
        }

        File temporary = new File(
                "/data/local/tmp/.prism-" + payload.assetName + "." + nonce);
        if (temporary.exists() && !temporary.delete()) {
            throw new GateException("payload-stage", "Cannot clear stale payload staging file");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long length = 0;
        try (InputStream input = context.getAssets().open(payload.assetName);
             FileOutputStream output = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                length += count;
                if (length > payload.size) {
                    throw new GateException("payload-stage", "Bundled payload size changed");
                }
            }
            output.getFD().sync();
        } catch (Exception exception) {
            temporary.delete();
            throw exception;
        }
        if (length != payload.size || !hex(digest.digest()).equals(payload.sha256)) {
            temporary.delete();
            throw new GateException("payload-stage", "Bundled payload digest changed");
        }

        Os.chmod(temporary.getAbsolutePath(), 0755);
        Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath());
        if (!isExactPayload(target, payload)) {
            throw new GateException("payload-stage", "Staged payload verification failed");
        }
    }

    private boolean isReSukiSuActive() throws Exception {
        java.lang.Process process = new ProcessBuilder(
                "/data/local/tmp/lp3-resukisu-ksud", "debug", "version")
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            byte[] buffer = new byte[1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 4096) {
                    process.destroyForcibly();
                    throw new GateException("active-check", "Version response is too large");
                }
                output.write(buffer, 0, count);
            }
        }
        int exit = process.waitFor();
        String version = output.toString(StandardCharsets.UTF_8.name()).trim();
        if (exit != 0) {
            throw new GateException(
                    "active-check", "Unable to query the ReSukiSU kernel state");
        }
        if ("Kernel Version: 35088".equals(version)) {
            return true;
        }
        if ("Kernel Version: 0".equals(version)) {
            return false;
        }
        throw new GateException("active-check", "Unexpected ReSukiSU version response");
    }

    private boolean isExactPayload(File file, Payload payload) throws Exception {
        if (!file.isFile()) {
            return false;
        }
        StructStat stat = Os.stat(file.getAbsolutePath());
        if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG ||
                stat.st_size != payload.size ||
                stat.st_uid != Process.SHELL_UID ||
                stat.st_gid != Process.SHELL_UID ||
                (stat.st_mode & 0777) != 0755) {
            return false;
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
        }
        return hex(digest.digest()).equals(payload.sha256);
    }

    private static String executeFixed(String... command) throws Exception {
        java.lang.Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > MAX_COMMAND_OUTPUT) {
                    process.destroyForcibly();
                    throw new GateException("command-output", "Fixed command output is too large");
                }
                output.write(buffer, 0, count);
            }
        }
        int exit = process.waitFor();
        String result = output.toString(StandardCharsets.UTF_8.name()).trim();
        if (exit != 0) {
            throw new GateException("fixed-command", "Fixed command failed: " + exit);
        }
        return result;
    }

    private void advance(String nextPhase, String message) {
        synchronized (lock) {
            phase = nextPhase;
            appendLocked("[*] " + message);
        }
    }

    private void append(String message) {
        synchronized (lock) {
            appendLocked(styleResult(message));
        }
    }

    private static String styleResult(String message) {
        if (message.startsWith("[+] ") || message.startsWith("[*] ") ||
                message.startsWith("[!] ") || message.startsWith("[-] ")) {
            return message;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        if (lower.contains("failed") || lower.contains("error") ||
                lower.contains("could not") || lower.contains("unsafe partial")) {
            return "[-] " + message;
        }
        if (lower.contains("retry") || lower.contains("missed") ||
                lower.contains("remains pending") || lower.startsWith("ambiguous") ||
                lower.startsWith("unresolved")) {
            return "[!] " + message;
        }
        return "[+] " + message;
    }

    private void appendLocked(String message) {
        String clean = message.replace('\n', ' ').replace('\r', ' ').trim();
        sequence++;
        logLines.addLast(String.format(Locale.ROOT, "%04d %s", sequence, clean));
        while (logLines.size() > MAX_LOG_LINES) {
            logLines.removeFirst();
        }
    }

    private void finish(
            String finalStatus,
            String finalPhase,
            boolean finalUnsafe,
            String message) {
        synchronized (lock) {
            status = finalStatus;
            phase = finalPhase;
            unsafe = finalUnsafe;
            terminal = true;
            appendLocked(("pass".equals(finalStatus) ? "[+] " :
                    finalUnsafe ? "[-] " : "[!] ") + message);
        }
        if ("pass".equals(finalStatus)) {
            returnToPrism();
        }
    }

    private void returnToPrism() {
        DirectReSukiSuActivation.controllerTrace("return-to-prism-enter");
        try {
            executeFixed(
                    "/system/bin/am", "start", "--user", "0",
                    "-f", "0x24000000", "-n",
                    PRISM_PACKAGE + "/.PrismActivity");
            DirectReSukiSuActivation.controllerTrace("return-to-prism-command-pass");
        } catch (Exception exception) {
            DirectReSukiSuActivation.controllerTrace("return-to-prism-command-fail type=" +
                    exception.getClass().getSimpleName());
            android.util.Log.w(
                    "PrismActivation", "Could not return to Prism", exception);
        }
    }

    private static String header(
            String status,
            String session,
            String phase,
            boolean terminal,
            boolean unsafe) {
        return "status=" + status +
                " session=" + session +
                " phase=" + phase +
                " terminal=" + (terminal ? "1" : "0") +
                " unsafe=" + (unsafe ? "1" : "0");
    }

    private static String safeSession(String nonce) {
        return nonce != null && nonce.matches(NONCE_PATTERN)
                ? nonce : "none";
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static final class Payload {
        final String assetName;
        final String targetPath;
        final long size;
        final String sha256;

        Payload(String assetName, String targetPath, long size, String sha256) {
            this.assetName = assetName;
            this.targetPath = targetPath;
            this.size = size;
            this.sha256 = sha256;
        }
    }

    private static final class GateException extends Exception {
        final String phase;

        GateException(String phase, String message) {
            super(message);
            this.phase = phase;
        }
    }
}
