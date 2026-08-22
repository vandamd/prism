package com.vandam.prism;

import android.content.Context;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Resumes a proven no-mutation reset without ever launching the Harness. */
final class SafeResetCoordinator {
    interface Logger {
        void log(String message);
    }

    static final String JOURNAL = "/data/local/tmp/prism-safe-reset-journal";

    private static final String PACKAGE = "com.vandam.prism";
    private static final String SU_ARM = "/data/local/tmp/light-side-su.arm";
    private static final String SU_TOKEN = "/data/local/tmp/light-side-su.token";
    private static final String HELPER_LOG =
            "/data/local/tmp/light-side-of-the-moon-helper.log";
    private static final String ROOT_WATCHDOG_ARM =
            "/data/local/tmp/light-side-root-watchdog.arm";
    private static final String NORMALISE_WAITING =
            "/data/local/tmp/light-side-normalise.waiting";
    private static final String ARM_HOLDER_PID =
            "/data/local/tmp/prism-arm-holder.pid";
    private static final String CONTROLLER_WATCHDOG_PID =
            "/data/local/tmp/prism-controller-watchdog.pid";
    private static final String BOOT_ID = "/proc/sys/kernel/random/boot_id";
    private static final String DEVICE_GATE =
            "status=pass stage=device-gate profile=tlp301-00ww-1-440000";

    private final Context context;
    private final SafeResetRecord record;
    private final Logger logger;
    private boolean prismStopped;
    private boolean prismRelaunched;

    SafeResetCoordinator(
            Context context, SafeResetRecord record, Logger logger) {
        this.context = context;
        this.record = record;
        this.logger = logger;
    }

    /**
     * Completes or resumes process-only cleanup.
     *
     * <p>A false result means the durable safe-reset checkpoint remains pending.
     */
    boolean complete() {
        try {
            requireSameBoot();
            writeCheckpoint(SafeResetRecord.CHECKPOINT_RETIRING);
            logger.log("Safe reset checkpoint: RETIRING");

            retireControllerWatchdog();
            retireIdentity(record.helperPid, record.helperStart, "helper");
            retireIdentity(record.holderPid, record.holderStart, "arm holder");
            requireArmLockFree();
            retireOldCohort();
            removeControlFiles();
            writeCheckpoint(SafeResetRecord.CHECKPOINT_PROCESSES_RETIRED);
            logger.log("Safe reset checkpoint: PROCESSES_RETIRED");

            requireStableBaseline();
            writeCheckpoint(SafeResetRecord.CHECKPOINT_BASELINE_VERIFIED);
            logger.log("Safe reset checkpoint: BASELINE_VERIFIED");

            int jobs = registeredJobCount();
            String receipt = "version=1 kind=safe-reset-complete session=" +
                    record.session + " boot_id=" + record.bootId +
                    " proof_sha256=" + record.proofDigest +
                    " jobs=" + jobs +
                    " profile=exact health=normal donor=exact ueventd=exact" +
                    " helper=absent holder=absent cohort=absent";
            relaunchPrismBestEffort();
            completeAppCapability(receipt);
            writeCheckpoint(SafeResetRecord.CHECKPOINT_PREARMED);
            deleteExactJournal();
            acknowledgeAppCapability();
            logger.log("Safe reset checkpoint: PREARMED");
            return true;
        } catch (Exception exception) {
            String detail = exception.getMessage();
            logger.log("Safe reset remains pending at the last checkpoint: " +
                    (detail == null || detail.isEmpty()
                            ? exception.getClass().getSimpleName()
                            : detail));
            return false;
        } finally {
            if (prismStopped && !prismRelaunched) {
                relaunchPrismBestEffort();
            }
        }
    }

    static SafeResetRecord.Journal readJournal() {
        try {
            String value = new String(
                    Files.readAllBytes(Path.of(JOURNAL)),
                    StandardCharsets.US_ASCII).trim();
            return SafeResetRecord.parseJournal(value);
        } catch (Exception exception) {
            return null;
        }
    }

    static void writeJournal(
            SafeResetRecord record, String checkpoint) throws Exception {
        SafeResetRecord.Journal existing = readJournal();
        if (Files.exists(Path.of(JOURNAL))) {
            if (existing == null) {
                throw new IllegalStateException("safe-reset-journal-invalid");
            }
            if (record.bootId.equals(existing.record.bootId) &&
                    !record.binding().equals(existing.record.binding())) {
                throw new IllegalStateException("safe-reset-journal-conflict");
            }
            if (record.binding().equals(existing.record.binding()) &&
                    SafeResetRecord.checkpointRank(existing.checkpoint) >=
                            SafeResetRecord.checkpointRank(checkpoint)) {
                return;
            }
        }
        String value = record.journal(checkpoint) + "\n";
        File temporary = new File(JOURNAL + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
        Os.chmod(temporary.getAbsolutePath(), 0600);
        Os.rename(temporary.getAbsolutePath(), JOURNAL);
        syncShellDirectory();
        String persisted = new String(
                Files.readAllBytes(Path.of(JOURNAL)),
                StandardCharsets.US_ASCII);
        if (!value.equals(persisted)) {
            throw new IllegalStateException("safe-reset-journal-persist");
        }
    }

    private void writeCheckpoint(String checkpoint) throws Exception {
        requireSameBoot();
        SafeResetRecord.Journal current = readJournal();
        if (current == null ||
                !record.binding().equals(current.record.binding())) {
            throw new IllegalStateException("safe-reset-journal-binding");
        }
        writeJournal(record, checkpoint);
    }

    private void retireIdentity(int pid, String start, String label)
            throws Exception {
        if (!identityMatches(pid, start)) {
            logger.log("Safe reset: exact " + label + " already absent");
            return;
        }
        requireShellProcess(pid, start, label);
        long deadline = android.os.SystemClock.elapsedRealtime() + 10_000;
        while (identityMatches(pid, start) &&
                android.os.SystemClock.elapsedRealtime() < deadline) {
            Os.kill(pid, android.system.OsConstants.SIGTERM);
            Thread.sleep(100);
        }
        if (identityMatches(pid, start)) {
            Os.kill(pid, android.system.OsConstants.SIGKILL);
        }
        deadline = android.os.SystemClock.elapsedRealtime() + 5_000;
        while (identityMatches(pid, start) &&
                android.os.SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(50);
        }
        if (identityMatches(pid, start)) {
            throw new IllegalStateException("safe-reset-" +
                    label.replace(' ', '-') + "-alive");
        }
        logger.log("Safe reset: exact " + label + " retired");
    }

    private void retireControllerWatchdog() throws Exception {
        File markerFile = new File(CONTROLLER_WATCHDOG_PID);
        if (!markerFile.exists()) {
            return;
        }
        String marker = readText(CONTROLLER_WATCHDOG_PID, 512).trim();
        Matcher match = Pattern.compile(
                "pid=([1-9][0-9]*) start=([1-9][0-9]*) session=" +
                        Pattern.quote(record.session) + " boot_id=" +
                        Pattern.quote(record.bootId))
                .matcher(marker);
        if (!match.matches()) {
            throw new IllegalStateException("safe-reset-watchdog-marker");
        }
        int pid = Integer.parseInt(match.group(1));
        String start = match.group(2);
        retireIdentity(pid, start, "controller watchdog");
        String current = markerFile.exists()
                ? readText(CONTROLLER_WATCHDOG_PID, 512).trim() : "";
        if (!current.isEmpty() && !marker.equals(current)) {
            throw new IllegalStateException("safe-reset-watchdog-marker-race");
        }
        Files.deleteIfExists(markerFile.toPath());
        if (markerFile.exists()) {
            throw new IllegalStateException("safe-reset-watchdog-marker-retire");
        }
    }

    private static void requireShellProcess(
            int pid, String start, String label) throws Exception {
        if (!identityMatches(pid, start)) {
            return;
        }
        String status = readText("/proc/" + pid + "/status", 64 * 1024);
        String context = readText("/proc/" + pid + "/attr/current", 1024)
                .replace("\0", "").trim();
        if (!status.matches("(?sm).*^Uid:\\s+2000\\s+2000\\s+2000\\s+2000$.*") ||
                !status.matches("(?sm).*^Gid:\\s+2000\\s+2000\\s+2000\\s+2000$.*") ||
                !"u:r:shell:s0".equals(context)) {
            throw new IllegalStateException("safe-reset-" +
                    label.replace(' ', '-') + "-identity");
        }
    }

    private void requireArmLockFree() throws Exception {
        if (!new File(SU_ARM).exists()) {
            return;
        }
        CommandResult result = command(
                "/system/bin/sh", "-c",
                "exec 0<" + SU_ARM + "; /system/bin/flock -n -x 0");
        if (result.exit != 0 || !result.output.isEmpty()) {
            throw new IllegalStateException("safe-reset-arm-lock");
        }
        logger.log("Safe reset: command arm lock is free");
    }

    private void retireOldCohort() throws Exception {
        long deadline = android.os.SystemClock.elapsedRealtime() + 30_000;
        int absentSamples = 0;
        forceStopPrism();
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            requireSameBoot();
            if (!oldCohortGone() || !currentPrismCohortGone()) {
                forceStopPrism();
                absentSamples = 0;
            } else if (++absentSamples >= 2) {
                logger.log("Safe reset: complete old app cohort retired");
                return;
            }
            Thread.sleep(200);
        }
        throw new IllegalStateException("safe-reset-cohort-alive");
    }

    private void forceStopPrism() throws Exception {
        CommandResult stopped = command(
                "/system/bin/am", "force-stop", "--user", "0", PACKAGE);
        if (stopped.exit != 0) {
            throw new IllegalStateException("safe-reset-force-stop");
        }
        prismStopped = true;
    }

    private boolean currentPrismCohortGone() throws Exception {
        int prismUid = context.getApplicationInfo().uid;
        CommandResult processes = command(
                "/system/bin/ps", "-A", "-o", "PID,UID,ARGS");
        if (processes.exit != 0) {
            throw new IllegalStateException("safe-reset-process-list");
        }
        for (String line : processes.output.split("\\n")) {
            String[] fields = line.trim().split("\\s+", 3);
            if (fields.length != 3 ||
                    !fields[0].matches("[1-9][0-9]*") ||
                    !fields[1].matches("[0-9]+")) {
                continue;
            }
            int pid = Integer.parseInt(fields[0]);
            int uid = Integer.parseInt(fields[1]);
            boolean packageLike = PACKAGE.equals(fields[2]) ||
                    fields[2].startsWith(PACKAGE + ":");
            if (uid == prismUid ||
                    (packageLike && !(uid == Process.SHELL_UID &&
                            pid == Process.myPid()))) {
                return false;
            }
        }
        return true;
    }

    private boolean oldCohortGone() {
        for (Map.Entry<Integer, String> identity : record.cohort.entrySet()) {
            if (identityMatches(identity.getKey(), identity.getValue())) {
                return false;
            }
        }
        return true;
    }

    private void removeControlFiles() throws Exception {
        for (String path : new String[] {
                SU_TOKEN, SU_ARM, ROOT_WATCHDOG_ARM,
                NORMALISE_WAITING, HELPER_LOG, ARM_HOLDER_PID}) {
            Files.deleteIfExists(Path.of(path));
        }
        if (identityMatches(record.helperPid, record.helperStart) ||
                identityMatches(record.holderPid, record.holderStart)) {
            throw new IllegalStateException("safe-reset-control-owner-live");
        }
    }

    private void requireStableBaseline() throws Exception {
        requireBaselineSample();
        Thread.sleep(3_000);
        requireBaselineSample();
    }

    private void requireBaselineSample() throws Exception {
        requireSameBoot();
        if (!DEVICE_GATE.equals(DeviceGate.verify(context)) ||
                identityMatches(record.helperPid, record.helperStart) ||
                identityMatches(record.holderPid, record.holderStart) ||
                !oldCohortGone() ||
                !currentPrismCohortGone() ||
                !identityMatches(record.donorPid, record.donorStart) ||
                !identityMatches(record.ueventdPid, record.ueventdStart) ||
                new File("/sys/module/lp3_ctlbuf_rescue").exists() ||
                registeredJobCount() >= 1000) {
            throw new IllegalStateException("safe-reset-baseline");
        }
        String donorPids = command("/system/bin/pidof", "update_engine")
                .output.trim();
        String ueventdPids = command("/system/bin/pidof", "ueventd")
                .output.trim();
        if (!Integer.toString(record.donorPid).equals(donorPids) ||
                !Integer.toString(record.ueventdPid).equals(ueventdPids)) {
            throw new IllegalStateException("safe-reset-unique-process");
        }
        requireNormalDeviceHealth();
    }

    private void completeAppCapability(String receipt) throws Exception {
        long deadline = android.os.SystemClock.elapsedRealtime() + 30_000;
        String last = "unavailable";
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            requireSameBoot();
            try (PrismAppBridgeClient bridge = PrismAppBridgeClient.connect(
                    context, record.session, record.bootId)) {
                String inspected = bridge.inspectSafeReset();
                if (!inspected.equals(
                        "status=pass stage=app-bridge-safe-reset-inspect " +
                                "state=pending binding=" + record.binding()) &&
                        !inspected.equals(
                                "status=pass stage=app-bridge-safe-reset-inspect " +
                                        "state=complete binding=" + record.binding())) {
                    last = inspected;
                } else {
                    String response = bridge.completeSafeReset(
                            record.binding(), receipt);
                    if (response.startsWith("status=pass ")) {
                        return;
                    }
                    last = response;
                }
            } catch (Exception exception) {
                last = exception.getClass().getSimpleName();
            }
            Thread.sleep(200);
        }
        throw new IllegalStateException("safe-reset-complete-" + last);
    }

    private void acknowledgeAppCapability() throws Exception {
        long deadline = android.os.SystemClock.elapsedRealtime() + 20_000;
        String last = "unavailable";
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            requireSameBoot();
            try (PrismAppBridgeClient bridge = PrismAppBridgeClient.connect(
                    context, record.session, record.bootId)) {
                String response = bridge.acknowledgeSafeReset(record.binding());
                if (response.startsWith("status=pass ")) {
                    return;
                }
                last = response;
            } catch (Exception exception) {
                last = exception.getClass().getSimpleName();
            }
            Thread.sleep(200);
        }
        throw new IllegalStateException("safe-reset-ack-" + last);
    }

    private void deleteExactJournal() throws Exception {
        SafeResetRecord.Journal journal = readJournal();
        if (journal == null ||
                !SafeResetRecord.CHECKPOINT_PREARMED.equals(journal.checkpoint) ||
                !record.binding().equals(journal.record.binding()) ||
                !Files.deleteIfExists(Path.of(JOURNAL)) ||
                Files.exists(Path.of(JOURNAL))) {
            throw new IllegalStateException("safe-reset-journal-retire");
        }
        syncShellDirectory();
    }

    private void relaunchPrismBestEffort() {
        try {
            CommandResult result = command(
                    "/system/bin/am", "start", "--user", "0",
                    "-f", "0x24000000", "-n",
                    PACKAGE + "/.PrismActivity");
            if (result.exit != 0) {
                logger.log("Prism UI relaunch was deferred");
            } else {
                prismRelaunched = true;
            }
        } catch (Exception ignored) {
            logger.log("Prism UI relaunch was deferred");
        }
    }

    private void requireSameBoot() throws Exception {
        if (!record.bootId.equals(readText(BOOT_ID, 128).trim())) {
            throw new IllegalStateException("safe-reset-boot");
        }
    }

    private static int registeredJobCount() throws Exception {
        String output = command("/system/bin/dumpsys", "jobscheduler").output;
        Matcher matcher = Pattern.compile(
                "(?m)^Registered ([0-9]+) jobs:$").matcher(output);
        if (!matcher.find()) {
            throw new IllegalStateException("safe-reset-jobs");
        }
        int count = Integer.parseInt(matcher.group(1));
        if (matcher.find()) {
            throw new IllegalStateException("safe-reset-jobs-ambiguous");
        }
        return count;
    }

    private static void requireNormalDeviceHealth() throws Exception {
        String output = command("/system/bin/dumpsys", "thermalservice").output;
        Matcher status = Pattern.compile(
                "(?m)^Thermal Status: ([0-9]+)$").matcher(output);
        if (!status.find() || !"0".equals(status.group(1)) || status.find()) {
            throw new IllegalStateException("safe-reset-thermal-status");
        }
        Matcher battery = Pattern.compile(
                "mValue=([0-9]+(?:\\.[0-9]+)?), mType=2, mName=battery")
                .matcher(output);
        if (!battery.find() || Double.parseDouble(battery.group(1)) >= 42.0) {
            throw new IllegalStateException("safe-reset-battery-temperature");
        }
        Matcher cpus = Pattern.compile(
                "mValue=([0-9]+(?:\\.[0-9]+)?), mType=0, mName=CPU[0-9]+")
                .matcher(output);
        int count = 0;
        double maximum = Double.NEGATIVE_INFINITY;
        while (cpus.find()) {
            count++;
            maximum = Math.max(maximum, Double.parseDouble(cpus.group(1)));
        }
        if (count == 0 || maximum >= 65.0) {
            throw new IllegalStateException("safe-reset-cpu-temperature");
        }
    }

    private static boolean identityMatches(int pid, String start) {
        return pid > 0 && start != null && start.equals(processStartTime(pid));
    }

    private static String processStartTime(int pid) {
        try {
            String value = readText("/proc/" + pid + "/stat", 64 * 1024);
            int close = value.lastIndexOf(')');
            String[] fields = value.substring(close + 1).trim().split("\\s+");
            return fields.length > 19 && fields[19].matches("[0-9]+")
                    ? fields[19] : "";
        } catch (Exception exception) {
            return "";
        }
    }

    private static void syncShellDirectory() throws Exception {
        FileDescriptor directory = Os.open(
                "/data/local/tmp", OsConstants.O_RDONLY, 0);
        try {
            Os.fsync(directory);
        } finally {
            Os.close(directory);
        }
    }

    private static String readText(String path, int limit) throws Exception {
        byte[] value = Files.readAllBytes(Path.of(path));
        if (value.length > limit) {
            throw new IllegalStateException("safe-reset-read-limit");
        }
        return new String(value, StandardCharsets.UTF_8);
    }

    private static CommandResult command(String... values) throws Exception {
        java.lang.Process process = new ProcessBuilder(values)
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Exception[] readFailure = new Exception[1];
        Thread reader = new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > 1024 * 1024) {
                        process.destroyForcibly();
                        throw new IllegalStateException(
                                "safe-reset-command-output");
                    }
                    output.write(buffer, 0, count);
                }
            } catch (Exception exception) {
                readFailure[0] = exception;
            }
        }, "prism-safe-reset-command");
        reader.setDaemon(true);
        reader.start();
        boolean finished = process.waitFor(30, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
        }
        reader.join(5_000);
        if (!finished) {
            throw new IllegalStateException("safe-reset-command-timeout");
        }
        if (reader.isAlive()) {
            process.destroyForcibly();
            throw new IllegalStateException("safe-reset-command-reader");
        }
        if (readFailure[0] != null) {
            throw readFailure[0];
        }
        return new CommandResult(
                process.exitValue(),
                output.toString(StandardCharsets.UTF_8.name()).trim());
    }

    private static final class CommandResult {
        final int exit;
        final String output;

        CommandResult(int exit, String output) {
            this.exit = exit;
            this.output = output;
        }
    }
}
