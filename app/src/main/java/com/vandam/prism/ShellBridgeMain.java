package com.vandam.prism;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileDescriptor;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.CRC32;

public final class ShellBridgeMain {
    private static final int TRANSACTION_PREPARE_PRIVATE_CREDENTIAL = 0x42b5;
    private static final int TRANSACTION_PROCESS_TEARDOWN = 0x42b6;
    private static final String TARGET_DESCRIPTOR =
            "com.vandam.prism.ShellBridgePrivateCredential";
    private static final CountDownLatch PRIVATE_CREDENTIAL_REQUESTED =
            new CountDownLatch(1);
    private static final CountDownLatch PROCESS_TEARDOWN_REQUESTED =
            new CountDownLatch(1);
    private static final AtomicBoolean PRIVATE_CREDENTIAL_PREPARED =
            new AtomicBoolean();
    private static volatile int privateCredentialCallerPid = -1;
    private static final String RESCUE_MODULE_ENTRY =
            "assets/lp3_ctlbuf_rescue.ko";
    private static final String RESCUE_MODULE_SHA256 =
            "2b4e520b65f252c1c7a51c303f8bc228663f6804cbca00f2ebc6005c9a9f26f8";
    private static final int RESCUE_MODULE_SIZE = 560_040;
    private static FileDescriptor rescueModuleFd;
    private static FileDescriptor rescueVendorFd;
    private static final Binder TARGET = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == TRANSACTION_PROCESS_TEARDOWN) {
                if (reply == null || (flags & IBinder.FLAG_ONEWAY) != 0) {
                    return false;
                }
                String nonce = data.readString();
                String expectedBootId = data.readString();
                int expectedPid = data.readInt();
                String expectedStart = data.readString();
                boolean nonceValid = false;
                boolean bootValid = false;
                boolean pidValid = false;
                boolean startValid = false;
                boolean callerValid = Binder.getCallingUid() >= 10_000;
                try {
                    nonceValid = runNonce.equals(nonce);
                    bootValid = bootId().equals(expectedBootId);
                    pidValid = Process.myPid() == expectedPid;
                    startValid = processStartTime(Process.myPid()).equals(
                            expectedStart);
                } catch (Exception ignored) {}
                boolean valid = nonceValid && bootValid && pidValid &&
                        startValid && callerValid;
                marker("PROC_TEARDOWN_SIGNAL nonce=" + runNonce +
                        " nonce_valid=" + (nonceValid ? 1 : 0) +
                        " boot_valid=" + (bootValid ? 1 : 0) +
                        " pid_valid=" + (pidValid ? 1 : 0) +
                        " start_valid=" + (startValid ? 1 : 0) +
                        " caller_valid=" + (callerValid ? 1 : 0) +
                        " flags=0x" + Integer.toHexString(flags));
                reply.writeNoException();
                reply.writeString(valid
                        ? "status=pass stage=process-teardown-watchdog"
                        : "status=fail stage=process-teardown-watchdog");
                if (valid) {
                    PROCESS_TEARDOWN_REQUESTED.countDown();
                }
                return true;
            }
            if (code != TRANSACTION_PREPARE_PRIVATE_CREDENTIAL) {
                return false;
            }
            if (reply == null) {
                return false;
            }
            String state = preparePrivateCredentialRequest(
                    data, reply, flags);
            reply.writeNoException();
            reply.writeString(state);
            if (state.startsWith("status=pass")) {
                reply.writeFileDescriptor(rescueModuleFd);
                reply.writeFileDescriptor(rescueVendorFd);
                PRIVATE_CREDENTIAL_REQUESTED.countDown();
            }
            return true;
        }
    };
    private static final int COPY_SIGNAL_PORT = 47391;
    private static final int PARTITION_SIGNAL_PORT = 47392;
    private static final int COMMAND_PORT = 47393;
    private static final int COMMAND_LIMIT = 65_536;
    private static final int COMMAND_OUTPUT_LIMIT = 16 * 1024 * 1024;
    private static final int COMMAND_RESPONSE_RESERVE = 1024;
    private static final long COMMAND_TIMEOUT_MILLIS = 75_000L;
    private static final long TRANSPORT_TIMEOUT_MILLIS = 60_000L;
    private static final long WATCHDOG_TIMEOUT_MILLIS = 180_000L;
    private static final long PARTITION_SIGNAL_TIMEOUT_MILLIS = 1_800_000L;
    private static final String IDENTITY_COMMAND = "__LP3_IDENTITY__";
    private static final String RESUKISU_PROBE_COMMAND =
            "__LP3_RESUKISU_PROBE__:";
    private static final String RESUKISU_ACTIVATE_COMMAND =
            "__LP3_RESUKISU_ACTIVATE__:";
    private static final String RESUKISU_PATH =
            "/data/local/tmp/lp3-resukisu-ksud";
    private static final String RESUKISU_SHA256 =
            "7765acff69651e31629433fa6095a41b7ca034b62e17f9180c2a820b1f177483";
    private static final long RESUKISU_SIZE = 4_214_888L;
    private static final String RESUKISU_LOADER_PATH =
            "/data/local/tmp/lp3-resukisu-loader.so";
    private static final String RESUKISU_LOADER_SHA256 =
            "1fe42682ad736f43eb5acb42dc0ebba79828a6090f61e47970277b12fdb61275";
    private static final long RESUKISU_LOADER_SIZE = 1_301_464L;
    private static FileDescriptor reSukiFd;
    private static final String COMMAND_TOKEN =
            "/data/local/tmp/light-side-su.token";
    private static final String COMMAND_ARM =
            "/data/local/tmp/light-side-su.arm";
    private static final long PARTITION_LIMIT = 134_217_728L;
    private static final long JOB_STORE_LIMIT = 536_870_912L;
    private static final String BACKUP_RESULT =
            "/data/local/tmp/light-side-partition-backup.result";
    private static final String PARTITION_WATCHDOG_PID =
            "/data/local/tmp/light-side-partition-watchdog.pid";
    private static final String[][] PARTITIONS = {
            {"frp", "/data/local/tmp/frp.img", "/dev/block/sda"},
            {"devinfo", "/data/local/tmp/devinfo.img", "/dev/block/sde"},
            {"deviceinfo", "/data/local/tmp/deviceinfo.img",
                    "/dev/block/sdd"},
            {"abl_a", "/data/local/tmp/abl_a.img", "/dev/block/sde"},
            {"abl_b", "/data/local/tmp/abl_b.img", "/dev/block/sde"},
    };
    private static final String JOB_STORE_DIRECTORY = "/data/system/job";
    private static final String JOB_STORE_RESULT =
            "/data/local/tmp/light-side-jobstore-repair.result";
    private static final String JOB_STORE_COMMIT =
            "/data/local/tmp/light-side-jobstore-repair.commit";
    private static final String[][] JOB_STORE_FILES = {
            {"jobs.xml", "/data/local/tmp/light-side-jobs.xml"},
            {"jobs.xml.bak", "/data/local/tmp/light-side-jobs.xml.bak"},
            {"jobs_1000.xml", "/data/local/tmp/light-side-jobs_1000.xml"},
            {"jobs_1000.xml.bak",
                    "/data/local/tmp/light-side-jobs_1000.xml.bak"},
    };
    private static volatile String runNonce = "";
    private static volatile boolean cleanCommandMode;
    private static volatile int cleanDonorPid = -1;

    private ShellBridgeMain() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length < 2 || arguments.length > 4) {
            throw new IllegalArgumentException(
                    "apk-path security-pid mode run-nonce");
        }
        String apkPath = requireInstalledBaseApkPath(arguments[0]);
        BootCopy.load(apkPath);
        System.setProperty(NativeBridge.SHELL_APK_PATH_PROPERTY, apkPath);
        try {
            NativeBridge.ensureLoaded();
        } finally {
            System.clearProperty(NativeBridge.SHELL_APK_PATH_PROPERTY);
        }
        String mode = arguments.length >= 3 ? arguments[2] : "";
        if (arguments.length >= 4) {
            runNonce = arguments[3];
        }
        int securityPid = Integer.parseInt(arguments[1]);
        boolean cleanCommand = "hold-command-server-clean".equals(mode);
        cleanCommandMode = cleanCommand;
        cleanDonorPid = cleanCommand ? securityPid : -1;
        if (cleanCommand) {
            prepareRescueModuleResources(apkPath);
        }
        String commandToken = ("hold-command-server".equals(mode) ||
                cleanCommand)
                ? readCommandToken() : "";
        marker("START");
        if ("hold-command-server".equals(mode) || cleanCommand) {
            startProcessTeardownWatchdog();
        }
        registerTarget(securityPid, mode);
        if ("hold-partition-backup-hal".equals(mode)) {
            partitionBackupLoop();
            return;
        }
        if ("hold-jobstore-repair".equals(mode)) {
            jobStoreRepairLoop();
            return;
        }
        readyMarker();
        if ("hold-command-server".equals(mode) || cleanCommand) {
            commandServerLoop(commandToken, cleanCommand);
            return;
        }
        if ("auto-copy".equals(mode)) {
            copyBoot();
            return;
        }
        if ("hold".equals(mode) || "hold-system-server".equals(mode)) {
            new CountDownLatch(1).await();
            return;
        }
        commandLoop();
    }

    private static String requireInstalledBaseApkPath(String value)
            throws Exception {
        File apk = new File(value);
        if (!apk.isAbsolute() || !value.equals(apk.getCanonicalPath()) ||
                !apk.isFile() || !value.startsWith("/data/app/") ||
                !value.endsWith("/base.apk") || value.indexOf('!') >= 0) {
            throw new IllegalArgumentException("installed-base-apk-path");
        }
        String directories = value.substring(
                "/data/app/".length(),
                value.length() - "/base.apk".length());
        String[] components = directories.split("/", -1);
        if (components.length < 1 || components.length > 2 ||
                (components.length == 2 &&
                        (!components[0].startsWith("~~") ||
                                components[0].length() == 2)) ||
                !components[components.length - 1].startsWith(
                        "com.vandam.prism-") ||
                components[components.length - 1].length() ==
                        "com.vandam.prism-".length()) {
            throw new IllegalArgumentException("installed-base-apk-path");
        }
        return value;
    }

    private static void commandServerLoop(String token, boolean clean)
            throws Exception {
        waitForCommandArm();
        long partialDeadline = 0;
        RootWatchdogState rootWatchdog = null;
        boolean rootObserved = false;
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), COMMAND_PORT));
            server.setSoTimeout((int) COMMAND_TIMEOUT_MILLIS);
            marker("COMMAND_LISTENING nonce=" + runNonce);
            try (Socket socket = server.accept()) {
                marker("COMMAND_ACCEPTED nonce=" + runNonce);
                socket.setSoTimeout((int) COMMAND_TIMEOUT_MILLIS);
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                String suppliedToken = readLine(input, 128);
                boolean tokenMatches = token.equals(suppliedToken);
                marker("COMMAND_TOKEN_READ nonce=" + runNonce +
                        " length=" + suppliedToken.length() +
                        " match=" + (tokenMatches ? 1 : 0));
                if (!tokenMatches) {
                    throw new SecurityException("token-invalid");
                }
                output.write(("LP3_SU_AUTH_" + token + "=1\n").getBytes(
                        StandardCharsets.US_ASCII));
                output.flush();
                marker("COMMAND_AUTHENTICATED nonce=" + runNonce);
                String command = readCommand(input);
                if (clean && !isCleanCommand(command)) {
                    throw new SecurityException("clean-command-not-identity");
                }
                if (clean && !IDENTITY_COMMAND.equals(command)) {
                    prepareReSukiResource();
                }
                if (clean) {
                    socket.setSoTimeout(
                            (int) PARTITION_SIGNAL_TIMEOUT_MILLIS);
                }
                CommandTransport transport = new CommandTransport(
                        input, output, token, clean, command);
                transport.start();
                startCommandWatchdog();
                marker("COMMAND_BUFFERED nonce=" + runNonce);
                if (clean) {
                    String helperStart = processStartTime(Process.myPid());
                    String bootId = bootId();
                    marker("COMMAND_PRIVATE_CREDENTIAL_WAITING nonce=" +
                            runNonce + " pid=" + Process.myPid() +
                            " start=" + helperStart +
                            " tid=" + Process.myTid() +
                            " boot_id=" + bootId);
                    awaitPrivateCredentialRequest(helperStart, bootId);
                    marker("COMMAND_PRIVATE_CREDENTIAL_NATIVE_CALL");
                    String watchdogPreparation =
                            NativeBridge.prepareCommandRootWatchdog(runNonce);
                    if (!watchdogPreparation.startsWith("status=pass")) {
                        throw new IllegalStateException(
                                "root-watchdog-prepare-" +
                                        watchdogPreparation);
                    }
                    String privateCredential =
                            NativeBridge.createPrivateShellCredential();
                    if (!privateCredential.startsWith("status=pass")) {
                        marker("COMMAND_PRIVATE_CREDENTIAL_INVALID nonce=" +
                                runNonce + " state=[" + privateCredential +
                                "]");
                        throw new IllegalStateException(
                                "private-shell-credential");
                    }
                    marker("COMMAND_PRIVATE_CREDENTIAL nonce=" + runNonce +
                            " state=[" + privateCredential + "]");
                    String normalisation =
                            NativeBridge.awaitCredentialNormalisation(
                                    runNonce);
                    if (!normalisation.startsWith("status=pass")) {
                        marker("COMMAND_NORMALISATION_INVALID nonce=" +
                                runNonce + " state=[" + normalisation + "]");
                        rebootForever("credential-normalisation-invalid");
                    }
                    String finaliseStatus = NativeBridge.ctlbufFinaliseStatus();
                    if (!finaliseStatus.startsWith(
                            "status=pass stage=ctlbuf-finalise ")) {
                        marker("COMMAND_CTLBUF_FINALISED_INVALID nonce=" +
                                runNonce + " state=[" + finaliseStatus + "]");
                        rebootForever("ctlbuf-finalise-invalid");
                    }
                    marker("COMMAND_CTLBUF_FINALISED nonce=" + runNonce +
                            " state=[" + finaliseStatus + "]");
                    marker("COMMAND_NORMALISED nonce=" + runNonce +
                            " state=[" + normalisation + "]");
                    transport.markNormalised();
                    new CountDownLatch(1).await();
                    return;
                }
                while (true) {
                    if (Os.geteuid() == Process.SHELL_UID &&
                            Os.getegid() == Process.SHELL_UID) {
                        Thread.sleep(20);
                        continue;
                    }
                    try {
                        requireRootWindow(
                                "u:r:update_engine:s0", "0", "0", true);
                        rootObserved = true;
                        if (rootWatchdog == null) {
                            transport.awaitRootWatchdogArm();
                            try {
                                rootWatchdog = startRootWatchdog(
                                        "u:r:update_engine:s0");
                                marker("COMMAND_ROOT_WATCHDOG_READY nonce=" +
                                        runNonce + " tid=" +
                                        rootWatchdog.tid + " identity=[" +
                                        rootWatchdog.identity + "]");
                            } catch (Exception exception) {
                                marker("COMMAND_ROOT_WATCHDOG_INVALID nonce=" +
                                        runNonce + " error=" +
                                        errorName(exception));
                                rebootForever("root-watchdog-invalid");
                            }
                        }
                        break;
                    } catch (Exception exception) {
                        if (partialDeadline == 0) {
                            partialDeadline = System.nanoTime() +
                                    30_000_000_000L;
                        }
                        if (System.nanoTime() >= partialDeadline) {
                            marker("COMMAND_ROOT_INVALID nonce=" + runNonce +
                                    " error=" + errorName(exception));
                            rebootForever("root-invalid");
                        }
                        Thread.sleep(20);
                    }
                }

                if (rootWatchdog == null) {
                    throw new IllegalStateException(
                            "root-watchdog-not-started");
                }
                marker("COMMAND_READY nonce=" + runNonce);
                transport.awaitExecute();
                transport.send(executeCommand(command, token));
                rebootForever("command-complete");
            }
        } catch (Throwable exception) {
            marker("COMMAND_ERROR nonce=" + runNonce + " error=" +
                    errorName(exception));
        } finally {
            if (rootObserved ||
                    Os.geteuid() != Process.SHELL_UID ||
                    Os.getegid() != Process.SHELL_UID) {
                rebootForever("command-complete-invalid");
            }
        }
    }

    private static void waitForCommandArm() throws Exception {
        File arm = new File(COMMAND_ARM);
        if (!BootCopy.waitForArmLock(COMMAND_ARM)) {
            throw new IllegalStateException("command-arm-lock");
        }
        arm.delete();
        marker("COMMAND_ARMED nonce=" + runNonce);
    }

    private static void awaitPrivateCredentialRequest(
            String helperStart, String bootId) throws Exception {
        int pid = Process.myPid();
        int tid = Process.myTid();
        if (pid != tid || !runNonce.matches("[0-9a-f]{32}") ||
                !helperStart.matches("[0-9]+") ||
                !bootId.matches(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                        "[0-9a-f]{4}-[0-9a-f]{12}")) {
            throw new IllegalStateException("private-credential-identity");
        }
        if (!PRIVATE_CREDENTIAL_REQUESTED.await(
                60_000, TimeUnit.MILLISECONDS)) {
            throw new IllegalStateException(
                    "private-credential-request-timeout");
        }
        if (!PRIVATE_CREDENTIAL_PREPARED.get() ||
                !helperStart.equals(processStartTime(pid)) ||
                !bootId.equals(bootId()) || Process.myTid() != pid) {
            throw new IllegalStateException(
                    "private-credential-request-binding");
        }
    }

    private static String preparePrivateCredentialRequest(
            Parcel data, Parcel reply, int flags) {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();
        try {
            if (!cleanCommandMode || reply == null ||
                    callingUid < Process.FIRST_APPLICATION_UID ||
                    callingPid <= 0 ||
                    !isExpectedAppCaller(callingPid, callingUid)) {
                return "status=fail stage=private-credential-request " +
                        "reason=caller";
            }
            if ((flags & IBinder.FLAG_ONEWAY) != 0) {
                return "status=fail stage=private-credential-request " +
                        "reason=flags";
            }
            data.enforceInterface(TARGET_DESCRIPTOR);
            String nonce = data.readString();
            int helperPid = data.readInt();
            String helperStart = data.readString();
            int mainTid = data.readInt();
            String requestedBootId = data.readString();
            boolean exact = data.dataAvail() == 0 &&
                    nonce != null && nonce.equals(runNonce) &&
                    nonce.matches("[0-9a-f]{32}") &&
                    helperPid == Process.myPid() &&
                    mainTid == helperPid &&
                    helperStart != null &&
                    helperStart.equals(processStartTime(helperPid)) &&
                    requestedBootId != null &&
                    requestedBootId.equals(bootId()) &&
                    PRIVATE_CREDENTIAL_PREPARED.compareAndSet(false, true);
            if (exact) {
                privateCredentialCallerPid = callingPid;
            }
            return "status=" + (exact ? "pass" : "fail") +
                    " stage=private-credential-request caller_uid=" +
                    callingUid + " caller_pid=" + callingPid;
        } catch (Exception exception) {
            return "status=fail stage=private-credential-request reason=" +
                    errorName(exception);
        }
    }

    private static void prepareRescueModuleResources(String apkPath)
            throws Exception {
        if (rescueModuleFd != null || rescueVendorFd != null) {
            throw new IllegalStateException("rescue-resources-reused");
        }
        byte[] module;
        try (ZipFile apk = new ZipFile(apkPath)) {
            ZipEntry entry = apk.getEntry(RESCUE_MODULE_ENTRY);
            if (entry == null || entry.getSize() != RESCUE_MODULE_SIZE) {
                throw new IllegalStateException("rescue-module-entry");
            }
            try (InputStream input = apk.getInputStream(entry)) {
                module = readBounded(input, RESCUE_MODULE_SIZE);
            }
        }
        if (module.length != RESCUE_MODULE_SIZE ||
                !RESCUE_MODULE_SHA256.equals(sha256(module))) {
            throw new IllegalStateException("rescue-module-digest");
        }
        FileDescriptor moduleFd = null;
        FileDescriptor vendorFd = null;
        try {
            moduleFd = Os.memfd_create("lp3_ctlbuf_rescue", 0);
            int offset = 0;
            while (offset < module.length) {
                int written = Os.write(
                        moduleFd, module, offset, module.length - offset);
                if (written <= 0) {
                    throw new IOException("rescue-module-write");
                }
                offset += written;
            }
            if (Os.lseek(moduleFd, 0, OsConstants.SEEK_SET) != 0) {
                throw new IOException("rescue-module-seek");
            }
            vendorFd = Os.open(
                    "/vendor",
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC,
                    0);
            rescueModuleFd = moduleFd;
            rescueVendorFd = vendorFd;
        } catch (Exception exception) {
            closeDescriptor(moduleFd);
            closeDescriptor(vendorFd);
            throw exception;
        }
    }

    private static byte[] readBounded(InputStream input, int expected)
            throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(expected);
        byte[] buffer = new byte[16 * 1024];
        int total = 0;
        while (true) {
            int count = input.read(buffer);
            if (count < 0) {
                break;
            }
            total += count;
            if (total > expected) {
                throw new IOException("rescue-module-size");
            }
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder text = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            text.append(String.format("%02x", item & 0xff));
        }
        return text.toString();
    }

    private static void closeDescriptor(FileDescriptor descriptor) {
        if (descriptor == null) {
            return;
        }
        try {
            Os.close(descriptor);
        } catch (Exception ignored) {
        }
    }

    private static boolean isExpectedAppCaller(int pid, int uid) {
        boolean uidValid = false;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/" + pid + "/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    uidValid = allIdsEqual(line, uid);
                    break;
                }
            }
        } catch (Exception exception) {
            return false;
        }
        try {
            String commandLine = new String(
                    java.nio.file.Files.readAllBytes(
                            new File("/proc/" + pid + "/cmdline").toPath()),
                    StandardCharsets.UTF_8);
            int end = commandLine.indexOf('\0');
            if (end >= 0) {
                commandLine = commandLine.substring(0, end);
            }
            return uidValid && "com.vandam.prism".equals(commandLine);
        } catch (Exception exception) {
            return false;
        }
    }

    private static String processStartTime(int pid) throws Exception {
        String stat = new String(java.nio.file.Files.readAllBytes(
                new File("/proc/" + pid + "/stat").toPath()),
                StandardCharsets.US_ASCII).trim();
        int close = stat.lastIndexOf(')');
        if (close < 0) {
            return "";
        }
        String[] fields = stat.substring(close + 1).trim().split("\\s+");
        return fields.length > 19 && fields[19].matches("[0-9]+")
                ? fields[19] : "";
    }

    private static String bootId() throws Exception {
        return new String(java.nio.file.Files.readAllBytes(
                new File("/proc/sys/kernel/random/boot_id").toPath()),
                StandardCharsets.US_ASCII).trim();
    }

    private static String readCommand(InputStream input) throws Exception {
        int commandLength = readInt(input);
        if (commandLength < 1 || commandLength > COMMAND_LIMIT) {
            throw new IllegalArgumentException("command-size");
        }
        byte[] commandBytes = readExact(input, commandLength);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(commandBytes))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("command-utf8", exception);
        }
    }

    private static boolean isCleanCommand(String command) {
        if (IDENTITY_COMMAND.equals(command)) {
            return true;
        }
        String prefix = command.startsWith(RESUKISU_PROBE_COMMAND)
                ? RESUKISU_PROBE_COMMAND
                : command.startsWith(RESUKISU_ACTIVATE_COMMAND)
                ? RESUKISU_ACTIVATE_COMMAND : "";
        if (prefix.isEmpty()) {
            return false;
        }
        String uid = command.substring(prefix.length());
        if (!uid.matches("[0-9]{5}")) {
            return false;
        }
        int value = Integer.parseInt(uid);
        return value >= 10_000 && value < 20_000;
    }

    private static int reSukiManagerUid(String command) {
        int separator = command.lastIndexOf(':');
        if (!isCleanCommand(command) || separator < 0) {
            throw new IllegalArgumentException("resukisu-command");
        }
        return Integer.parseInt(command.substring(separator + 1));
    }

    private static void prepareReSukiResource() throws Exception {
        if (reSukiFd != null) {
            throw new IllegalStateException("resukisu-resource-reused");
        }
        FileDescriptor descriptor = openVerifiedReSukiFile(
                RESUKISU_PATH, RESUKISU_SIZE, RESUKISU_SHA256);
        try {
            FileDescriptor loader = openVerifiedReSukiFile(
                    RESUKISU_LOADER_PATH, RESUKISU_LOADER_SIZE,
                    RESUKISU_LOADER_SHA256);
            try {
                String loaded = NativeBridge.prepareReSukiLoader(loader);
                if (!loaded.startsWith(
                        "status=pass stage=resukisu-loader-prepare ")) {
                    throw new SecurityException(
                            "resukisu-loader-invalid-" + loaded);
                }
            } finally {
                closeDescriptor(loader);
            }
            reSukiFd = descriptor;
        } catch (Exception exception) {
            closeDescriptor(descriptor);
            throw exception;
        }
    }

    private static FileDescriptor openVerifiedReSukiFile(
            String path, long expectedSize, String expectedHash)
            throws Exception {
        FileDescriptor descriptor = Os.open(
                path, OsConstants.O_RDONLY | OsConstants.O_CLOEXEC, 0);
        try {
            StructStat stat = Os.fstat(descriptor);
            if ((stat.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG ||
                    stat.st_size != expectedSize ||
                    stat.st_uid != Process.SHELL_UID ||
                    stat.st_gid != Process.SHELL_UID ||
                    (stat.st_mode & 0777) != 0755) {
                throw new SecurityException("resukisu-resource-stat");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileDescriptor verification = Os.dup(descriptor);
            try (FileInputStream input = new FileInputStream(verification)) {
                byte[] buffer = new byte[64 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, count);
                }
            }
            if (Os.lseek(descriptor, 0, OsConstants.SEEK_SET) != 0) {
                throw new IOException("resukisu-resource-seek");
            }
            StringBuilder observed = new StringBuilder(64);
            for (byte value : digest.digest()) {
                observed.append(String.format("%02x", value & 0xff));
            }
            if (!expectedHash.equals(observed.toString())) {
                throw new SecurityException("resukisu-resource-digest");
            }
            return descriptor;
        } catch (Exception exception) {
            closeDescriptor(descriptor);
            throw exception;
        }
    }

    private static byte[] executeCommand(String command, String token) {
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        java.lang.Process child = null;
        try {
            response.write(identity().getBytes(StandardCharsets.UTF_8));
            if (IDENTITY_COMMAND.equals(command)) {
                appendExit(response, token, 0);
                return response.toByteArray();
            }
            child = new ProcessBuilder(
                    "/system/bin/sh", "-c", command)
                    .redirectInput(new File("/dev/null"))
                    .redirectErrorStream(true)
                    .start();
            java.lang.Process commandChild = child;
            final Exception[] copyError = new Exception[1];
            Thread copy = new Thread(() -> {
                try (InputStream childOutput = commandChild.getInputStream()) {
                    byte[] buffer = new byte[16_384];
                    int count;
                    while ((count = childOutput.read(buffer)) != -1) {
                        if (response.size() + count > COMMAND_OUTPUT_LIMIT -
                                COMMAND_RESPONSE_RESERVE) {
                            throw new IllegalStateException(
                                    "command-output-limit");
                        }
                        response.write(buffer, 0, count);
                    }
                } catch (Exception exception) {
                    copyError[0] = exception;
                }
            }, "lp3-su-output");
            copy.start();
            if (!child.waitFor(COMMAND_TIMEOUT_MILLIS,
                    TimeUnit.MILLISECONDS)) {
                child.destroyForcibly();
                child.waitFor(5000, TimeUnit.MILLISECONDS);
                throw new IllegalStateException("command-timeout");
            }
            copy.join(5000);
            if (copy.isAlive()) {
                throw new IllegalStateException("command-output-timeout");
            }
            if (copyError[0] != null) {
                throw copyError[0];
            }
            appendExit(response, token, child.exitValue());
        } catch (Exception exception) {
            if (child != null && child.isAlive()) {
                child.destroyForcibly();
            }
            ByteArrayOutputStream errorResponse = new ByteArrayOutputStream();
            appendError(errorResponse, token, exception);
            return errorResponse.toByteArray();
        }
        return response.toByteArray();
    }

    private static void appendExit(ByteArrayOutputStream output, String token,
            int status) {
        byte[] value = ("\nLP3_SU_EXIT_" + token + "=" + status + "\n")
                .getBytes(StandardCharsets.UTF_8);
        output.write(value, 0, value.length);
    }

    private static void appendError(ByteArrayOutputStream output, String token,
            Exception exception) {
        byte[] value = ("\nLP3_SU_ERROR_" + token + "=" +
                errorName(exception) + "\n")
                .getBytes(StandardCharsets.UTF_8);
        output.write(value, 0, value.length);
    }

    private static String identity() throws Exception {
        StringBuilder identity = new StringBuilder("LP3_SU_IDENTITY");
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:") || line.startsWith("Gid:") ||
                        line.startsWith("CapEff:") ||
                        line.startsWith("Seccomp:")) {
                    identity.append(' ').append(line.replace('\t', '='));
                }
            }
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/self/attr/current"))) {
            identity.append(" Context=").append(
                    normaliseContext(reader.readLine()));
        }
        identity.append('\n');
        return identity.toString();
    }

    private static final class CommandTransport {
        private final InputStream input;
        private final OutputStream output;
        private final String token;
        private final CountDownLatch started = new CountDownLatch(1);
        private volatile boolean rootWatchdogArm;
        private final CountDownLatch executeAllowed = new CountDownLatch(1);
        private final CountDownLatch responseReady = new CountDownLatch(1);
        private final CountDownLatch responseSent = new CountDownLatch(1);
        private final CountDownLatch normalised = new CountDownLatch(1);
        private final CountDownLatch complete = new CountDownLatch(1);
        private final boolean clean;
        private final String command;
        private volatile byte[] response;
        private volatile Exception error;
        private volatile boolean shellIdentity;

        CommandTransport(InputStream input, OutputStream output,
                String token, boolean clean, String command) {
            this.input = input;
            this.output = output;
            this.token = token;
            this.clean = clean;
            this.command = command;
        }

        void start() throws Exception {
            Thread thread = new Thread(this::run, "lp3-su-transport");
            thread.setDaemon(true);
            thread.start();
            if (!started.await(5000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("transport-start-timeout");
            }
            if (!shellIdentity) {
                throw new IllegalStateException("transport-not-shell");
            }
        }

        void send(byte[] value) throws Exception {
            response = value;
            responseReady.countDown();
            CountDownLatch sent = clean ? responseSent : complete;
            if (!sent.await(TRANSPORT_TIMEOUT_MILLIS,
                    TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("transport-timeout");
            }
            if (error != null) {
                throw error;
            }
        }

        void markNormalised() {
            normalised.countDown();
        }

        void awaitRootWatchdogArm() throws Exception {
            long deadline = System.nanoTime() +
                    PARTITION_SIGNAL_TIMEOUT_MILLIS * 1_000_000L;
            while (!rootWatchdogArm && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            if (!rootWatchdogArm) {
                throw new IllegalStateException(
                        "root-watchdog-arm-timeout");
            }
        }

        void awaitExecute() throws Exception {
            if (!executeAllowed.await(30_000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("transport-execute-timeout");
            }
            if (error != null) {
                throw error;
            }
        }

        private void run() {
            try {
                shellIdentity = isShellThread();
                started.countDown();
                if (!shellIdentity) {
                    return;
                }
                int request = input.read();
                if (request == 4) {
                    if (clean) {
                        NativeBridge.signalCommandRootWatchdogArm();
                        marker("COMMAND_ROOT_WATCHDOG_ARM_RECEIVED nonce=" +
                                runNonce);
                        String nativeIdentity = "";
                        long watchdogDeadline = System.nanoTime() +
                                10_000_000_000L;
                        while (System.nanoTime() < watchdogDeadline) {
                            nativeIdentity =
                                    NativeBridge.commandRootWatchdogIdentity();
                            if (nativeIdentity.startsWith("status=pass")) {
                                break;
                            }
                            Thread.sleep(1);
                        }
                        int watchdogTid = parsePositiveField(
                                nativeIdentity, "tid=");
                        if (!nativeIdentity.startsWith(
                                    "status=pass stage=" +
                                    "command-root-watchdog") ||
                                watchdogTid <= 0) {
                            marker("COMMAND_ROOT_WATCHDOG_INVALID nonce=" +
                                    runNonce + " state=[" +
                                    nativeIdentity + "]");
                            throw new IllegalStateException(
                                    "root-watchdog-identity");
                        }
                        marker("COMMAND_ROOT_WATCHDOG_READY nonce=" +
                                runNonce + " tid=" + watchdogTid +
                                " identity=[" + nativeIdentity + "]");
                    } else {
                        rootWatchdogArm = true;
                        marker("COMMAND_ROOT_WATCHDOG_ARM_RECEIVED nonce=" +
                                runNonce);
                    }
                    request = input.read();
                }
                if (request != 2) {
                    throw new IllegalStateException("transport-execute");
                }
                if (!isShellThread()) {
                    throw new IllegalStateException(
                            "transport-identity-before-execute");
                }
                if (clean) {
                    String nativeIdentity =
                            NativeBridge.commandRootWatchdogIdentity();
                    if (!nativeIdentity.startsWith(
                            "status=pass stage=command-root-watchdog")) {
                        throw new IllegalStateException(
                                "root-watchdog-identity-" + nativeIdentity);
                    }
                    String actionResult = "";
                    int actionExit = 0;
                    boolean deferredActivate = command.startsWith(
                            RESUKISU_ACTIVATE_COMMAND);
                    if (deferredActivate) {
                        actionResult = "status=ready stage=resukisu-action " +
                                "action=activate";
                    } else if (!IDENTITY_COMMAND.equals(command)) {
                        actionResult = NativeBridge.runReSukiAction(
                                reSukiFd, rescueModuleFd,
                                reSukiManagerUid(command), false);
                        closeDescriptor(reSukiFd);
                        reSukiFd = null;
                        actionExit = actionResult.startsWith(
                                "status=pass stage=resukisu-action ") ? 0 : 1;
                    }
                    byte[] cleanResponse = (
                            "LP3_SU_IDENTITY " + nativeIdentity + "\n" +
                            (actionResult.isEmpty() ? "" :
                                    "LP3_RESUKISU " + actionResult + "\n") +
                            "LP3_SU_EXIT_" + token + "=" + actionExit + "\n")
                            .getBytes(StandardCharsets.UTF_8);
                    output.write(cleanResponse);
                    output.flush();
                    responseSent.countDown();
                    if (deferredActivate) {
                        marker("COMMAND_RESUKISU_STAGE_WAITING nonce=" +
                                runNonce);
                        if (input.read() != 8) {
                            throw new IllegalStateException(
                                    "transport-resukisu-stage-request");
                        }
                        long kernelBase = readLong(input);
                        String stageResult =
                                NativeBridge.stageReSukiModule(
                                        rescueModuleFd, kernelBase);
                        int stageExit = stageResult.startsWith(
                                "status=pass stage=resukisu-stage ") ? 0 : 1;
                        marker("COMMAND_RESUKISU_STAGE_RESULT nonce=" +
                                runNonce + " state=[" + stageResult + "]");
                        byte[] stageResponse = (
                                "LP3_RESUKISU_STAGE " + stageResult + "\n" +
                                "LP3_SU_STAGE_" + token + "=" +
                                stageExit + "\n")
                                .getBytes(StandardCharsets.UTF_8);
                        output.write(stageResponse);
                        output.flush();
                        if (stageExit != 0) {
                            throw new IllegalStateException(
                                    "resukisu-stage-" + stageResult);
                        }
                    }
                    marker("COMMAND_CTLBUF_DONOR_REQUEST_WAITING nonce=" +
                            runNonce + " donor_pid=" + cleanDonorPid);
                    int donorFreezeRequest = input.read();
                    marker("COMMAND_CTLBUF_DONOR_REQUEST_RECEIVED nonce=" +
                            runNonce + " donor_pid=" + cleanDonorPid +
                            " value=" + donorFreezeRequest);
                    if (donorFreezeRequest != 5 || cleanDonorPid <= 0) {
                        throw new IllegalStateException(
                                "transport-donor-freeze-request");
                    }
                    String donorSignalState =
                            NativeBridge.signalCtlbufDonorFreeze(cleanDonorPid);
                    marker("COMMAND_CTLBUF_DONOR_SIGNAL_STATE " +
                            "nonce=" + runNonce + " pid=" + cleanDonorPid +
                            " state=[" + donorSignalState + "]");
                    String expectedDonorSignalState =
                            "status=pass stage=ctlbuf-donor-signal nonce=" +
                            runNonce + " pid=" + cleanDonorPid +
                            " kill_rc=0 kill_errno=0 signal_state=1 " +
                            "leader_stage=60";
                    if (!expectedDonorSignalState.equals(donorSignalState)) {
                        throw new IllegalStateException(
                                "transport-donor-signal-state");
                    }
                    marker("COMMAND_CTLBUF_DONOR_SIGNALLED nonce=" +
                            runNonce + " pid=" + cleanDonorPid);
                    if (input.read() != 6 || !isShellThread()) {
                        throw new IllegalStateException(
                                "transport-donor-frozen-confirmation");
                    }
                    String donorFrozenState =
                            NativeBridge.signalCtlbufDonorFrozen(cleanDonorPid);
                    marker("COMMAND_CTLBUF_DONOR_FROZEN_STATE " +
                            "nonce=" + runNonce + " pid=" + cleanDonorPid +
                            " state=[" + donorFrozenState + "]");
                    String expectedDonorFrozenState =
                            "status=pass stage=ctlbuf-donor-frozen nonce=" +
                            runNonce + " pid=" + cleanDonorPid +
                            " confirmation=1 signal_state=2 frozen=1 " +
                            "leader_stage=70";
                    if (!expectedDonorFrozenState.equals(donorFrozenState)) {
                        throw new IllegalStateException(
                                "transport-donor-frozen-state");
                    }
                    marker("COMMAND_CTLBUF_DONOR_FROZEN nonce=" +
                            runNonce + " pid=" + cleanDonorPid);
                    if (deferredActivate) {
                        if (input.read() != 7) {
                            throw new IllegalStateException(
                                    "transport-resukisu-execute");
                        }
                        actionResult = NativeBridge.runReSukiAction(
                                reSukiFd, rescueModuleFd,
                                reSukiManagerUid(command), true);
                        closeDescriptor(reSukiFd);
                        reSukiFd = null;
                        actionExit = actionResult.startsWith(
                                "status=pass stage=resukisu-action ") ? 0 : 1;
                        byte[] actionResponse = (
                                "LP3_RESUKISU " + actionResult + "\n" +
                                "LP3_SU_FINAL_" + token + "=" +
                                actionExit + "\n")
                                .getBytes(StandardCharsets.UTF_8);
                        output.write(actionResponse);
                        output.flush();
                    }
                    if (input.read() != 3) {
                        throw new IllegalStateException(
                                "transport-normalise-request");
                    }
                    int rescuePlanLength = readInt(input);
                    if (rescuePlanLength < 1 || rescuePlanLength > 3072) {
                        throw new IllegalStateException(
                                "transport-rescue-plan-size");
                    }
                    String rescuePlan = StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(readExact(
                                    input, rescuePlanLength)))
                            .toString();
                    String rescuePlanState =
                            NativeBridge.installCtlbufRescuePlan(
                                    rescuePlan, rescueModuleFd,
                                    privateCredentialCallerPid);
                    if (!rescuePlanState.startsWith("status=pass")) {
                        marker("COMMAND_CTLBUF_RESCUE_PLAN_INVALID nonce=" +
                                runNonce + " state=[" + rescuePlanState +
                                "]");
                        throw new IllegalStateException(
                                "transport-rescue-plan-invalid");
                    }
                    marker("COMMAND_CTLBUF_RESCUE_PLAN_READY nonce=" +
                            runNonce + " state=[" + rescuePlanState + "]");
                    NativeBridge.signalCredentialNormalisation();
                    long rescueDeadline = System.nanoTime() +
                            TRANSPORT_TIMEOUT_MILLIS * 1_000_000L;
                    String lastRescueStatus = "";
                    while (normalised.getCount() != 0 &&
                            System.nanoTime() < rescueDeadline) {
                        String rescueStatus =
                                NativeBridge.ctlbufRescueStatus();
                        if (!rescueStatus.equals(lastRescueStatus)) {
                            marker("COMMAND_CTLBUF_RESCUE_STATUS nonce=" +
                                    runNonce + " state=[" + rescueStatus +
                                    "]");
                            lastRescueStatus = rescueStatus;
                        }
                        Thread.sleep(1);
                    }
                    if (normalised.getCount() != 0) {
                        throw new IllegalStateException(
                                "transport-normalise-timeout");
                    }
                    if (input.read() != 1) {
                        throw new IllegalStateException(
                                "transport-exit-request");
                    }
                    NativeBridge.exitCredentialHelper();
                    throw new IllegalStateException(
                            "transport-exit-returned");
                }
                executeAllowed.countDown();
                if (!responseReady.await(WATCHDOG_TIMEOUT_MILLIS,
                        TimeUnit.MILLISECONDS)) {
                    throw new IllegalStateException(
                            "transport-response-timeout");
                }
                if (!isShellThread()) {
                    throw new IllegalStateException(
                            "transport-identity-before-write");
                }
                output.write(response);
                output.flush();
                responseSent.countDown();
                if (!isShellThread()) {
                    throw new IllegalStateException(
                            "transport-identity-before-ack");
                }
                if (input.read() != 1) {
                    throw new IllegalStateException("transport-terminal-ack");
                }
                if (!isShellThread()) {
                    throw new IllegalStateException(
                            "transport-identity-after-terminal-ack");
                }
            } catch (Exception exception) {
                error = exception;
            } finally {
                started.countDown();
                executeAllowed.countDown();
                responseSent.countDown();
                normalised.countDown();
                complete.countDown();
            }
        }
    }

    private static boolean isShellThread() {
        if (Os.getuid() != Process.SHELL_UID ||
                Os.geteuid() != Process.SHELL_UID ||
                Os.getgid() != Process.SHELL_UID ||
                Os.getegid() != Process.SHELL_UID) {
            return false;
        }
        boolean uidValid = false;
        boolean gidValid = false;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/thread-self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    uidValid = allIdsEqual(line, Process.SHELL_UID);
                } else if (line.startsWith("Gid:")) {
                    gidValid = allIdsEqual(line, Process.SHELL_UID);
                }
            }
        } catch (Exception exception) {
            return false;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/thread-self/attr/current"))) {
            String context = reader.readLine();
            return uidValid && gidValid &&
                    "u:r:shell:s0".equals(normaliseContext(context));
        } catch (Exception exception) {
            return false;
        }
    }

    private static boolean allIdsEqual(String line, int expected) {
        String[] fields = line.substring(line.indexOf(':') + 1)
                .trim().split("\\s+");
        if (fields.length != 4) {
            return false;
        }
        String value = Integer.toString(expected);
        for (String field : fields) {
            if (!value.equals(field)) {
                return false;
            }
        }
        return true;
    }

    private static String normaliseContext(String context) {
        return context == null ? "" : context.replace("\u0000", "").trim();
    }

    private static String readCommandToken() throws Exception {
        File tokenFile = new File(COMMAND_TOKEN);
        try (FileInputStream input = new FileInputStream(tokenFile)) {
            String token = new String(readExact(input, 64),
                    StandardCharsets.US_ASCII);
            if (!token.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("command-token-invalid");
            }
            return token;
        } finally {
            tokenFile.delete();
        }
    }

    private static String readLine(InputStream input, int limit)
            throws Exception {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        while (value.size() < limit) {
            int item = input.read();
            if (item == '\n') {
                return value.toString(StandardCharsets.US_ASCII.name());
            }
            if (item < 0) {
                break;
            }
            value.write(item);
        }
        throw new IllegalArgumentException("line-invalid");
    }

    private static int readInt(InputStream input) throws Exception {
        byte[] value = readExact(input, 4);
        return (value[0] & 0xff) << 24 |
                (value[1] & 0xff) << 16 |
                (value[2] & 0xff) << 8 |
                value[3] & 0xff;
    }

    private static long readLong(InputStream input) throws Exception {
        byte[] value = readExact(input, 8);
        return ByteBuffer.wrap(value).getLong();
    }

    private static byte[] readExact(InputStream input, int size)
            throws Exception {
        byte[] value = new byte[size];
        int offset = 0;
        while (offset < size) {
            int count = input.read(value, offset, size - offset);
            if (count < 0) {
                throw new IllegalArgumentException("request-truncated");
            }
            offset += count;
        }
        return value;
    }

    private static int parsePositiveField(String value, String field) {
        int start = value.indexOf(field);
        if (start < 0) {
            return -1;
        }
        start += field.length();
        int end = start;
        while (end < value.length() && Character.isDigit(
                value.charAt(end))) {
            end++;
        }
        if (end == start) {
            return -1;
        }
        try {
            int parsed = Integer.parseInt(value.substring(start, end));
            return parsed > 0 ? parsed : -1;
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private static void startCommandWatchdog() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        boolean[] valid = new boolean[1];
        Thread watchdog = new Thread(() -> {
            valid[0] = isShellThread();
            ready.countDown();
            if (!valid[0]) {
                return;
            }
            try {
                Thread.sleep(WATCHDOG_TIMEOUT_MILLIS);
            } catch (Exception ignored) {
                // Continue to the reboot request.
            }
            while (true) {
                requestReboot("watchdog");
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException ignored) {
                    // Keep the borrowed credential contained.
                }
            }
        }, "lp3-su-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        if (!ready.await(5000, TimeUnit.MILLISECONDS) || !valid[0]) {
            throw new IllegalStateException("shell-watchdog-identity");
        }
    }

    private static void startProcessTeardownWatchdog() {
        Thread watchdog = new Thread(() -> {
            try {
                PROCESS_TEARDOWN_REQUESTED.await();
                marker("PROC_TEARDOWN_WATCHDOG_ARMED nonce=" + runNonce);
                Thread.sleep(45_000L);
                while (true) {
                    java.lang.Process forceStop = new ProcessBuilder(
                            "/system/bin/am", "force-stop", "--user", "0",
                            "com.vandam.prism").start();
                    if (forceStop.waitFor(10, TimeUnit.SECONDS) &&
                            forceStop.exitValue() == 0) {
                        marker("PROC_TEARDOWN_WATCHDOG_COMPLETE nonce=" +
                                runNonce);
                        System.exit(0);
                    }
                    forceStop.destroyForcibly();
                    Thread.sleep(5000L);
                }
            } catch (Exception exception) {
                marker("PROC_TEARDOWN_WATCHDOG_FAILED nonce=" + runNonce +
                        " type=" + exception.getClass().getSimpleName());
            }
        }, "lp3-proc-teardown-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private static void startIndependentShellWatchdog() throws Exception {
        java.lang.Process watchdog = new ProcessBuilder(
                "/system/bin/sh", "-c",
                "echo $$ > " + PARTITION_WATCHDOG_PID +
                        "; sleep 180; while true; do /system/bin/reboot; " +
                        "sleep 10; done").start();
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadline) {
            if (!watchdog.isAlive()) {
                throw new IllegalStateException(
                        "shell-watchdog-process-exited");
            }
            long pid = readPidFile(PARTITION_WATCHDOG_PID);
            if (pid > 0 && isShellProcess(pid)) {
                return;
            }
            Thread.sleep(20);
        }
        throw new IllegalStateException("shell-watchdog-process-identity");
    }

    private static long readPidFile(String path) {
        try (BufferedReader reader = new BufferedReader(
                new FileReader(path))) {
            return Long.parseLong(reader.readLine());
        } catch (Exception exception) {
            return -1;
        }
    }

    private static boolean isShellProcess(long pid) {
        boolean uidValid = false;
        boolean gidValid = false;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/" + pid + "/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    uidValid = allIdsEqual(line, Process.SHELL_UID);
                } else if (line.startsWith("Gid:")) {
                    gidValid = allIdsEqual(line, Process.SHELL_UID);
                }
            }
        } catch (Exception exception) {
            return false;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/" + pid + "/attr/current"))) {
            return uidValid && gidValid && "u:r:shell:s0".equals(
                    normaliseContext(reader.readLine()));
        } catch (Exception exception) {
            return false;
        }
    }

    private static RootWatchdogState startRootWatchdog(
            String expectedContext)
            throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        int[] tid = new int[1];
        String[] identity = new String[1];
        boolean[] valid = new boolean[1];
        Thread watchdog = new Thread(() -> {
            tid[0] = Process.myTid();
            identity[0] = BootCopy.rootWatchdogIdentity();
            valid[0] = identity[0] != null &&
                    identity[0].startsWith("status=pass") &&
                    isRootWatchdogThread(expectedContext);
            ready.countDown();
            if (!valid[0]) {
                return;
            }
            try {
                Thread.sleep(WATCHDOG_TIMEOUT_MILLIS);
            } catch (Exception ignored) {
                // Continue to the reboot request.
            }
            rebootForever("root-watchdog");
        }, "lp3-su-root-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        if (!ready.await(5000, TimeUnit.MILLISECONDS) || !valid[0] ||
                tid[0] <= 0) {
            throw new IllegalStateException("root-watchdog-identity-" +
                    String.valueOf(identity[0]));
        }
        return new RootWatchdogState(tid[0], identity[0]);
    }

    private static final class RootWatchdogState {
        final int tid;
        final String identity;

        RootWatchdogState(int tid, String identity) {
            this.tid = tid;
            this.identity = identity;
        }
    }

    private static RootWatchdogState startPartitionRootWatchdog()
            throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        int[] tid = new int[1];
        String[] identity = new String[1];
        Thread watchdog = new Thread(() -> {
            tid[0] = Process.myTid();
            identity[0] = BootCopy.rootWatchdogIdentity();
            ready.countDown();
            if (identity[0] == null ||
                    !identity[0].startsWith("status=pass")) {
                return;
            }
            try {
                Thread.sleep(WATCHDOG_TIMEOUT_MILLIS);
            } catch (Exception ignored) {
                // Continue to the reboot request.
            }
            while (true) {
                requestReboot("partition-root-watchdog");
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException ignored) {
                    // Keep the borrowed credential contained.
                }
            }
        }, "lp3-partition-root-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        if (!ready.await(5000, TimeUnit.MILLISECONDS) || tid[0] <= 0 ||
                identity[0] == null ||
                !identity[0].startsWith("status=pass")) {
            throw new IllegalStateException("partition-root-watchdog-" +
                    String.valueOf(identity[0]));
        }
        return new RootWatchdogState(tid[0], identity[0]);
    }

    private static boolean isRootWatchdogThread(String expectedContext) {
        if (Os.getuid() != 0 || Os.geteuid() != 0 ||
                Os.getgid() != 0 || Os.getegid() != 0) {
            return false;
        }
        boolean uidValid = false;
        boolean gidValid = false;
        boolean rebootCapable = false;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/thread-self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    uidValid = allIdsEqual(line, 0);
                } else if (line.startsWith("Gid:")) {
                    gidValid = allIdsEqual(line, 0);
                } else if (line.startsWith("CapEff:")) {
                    String value = line.substring(line.indexOf(':') + 1)
                            .trim();
                    long capabilities = Long.parseUnsignedLong(value, 16);
                    rebootCapable = (capabilities & (1L << 22)) != 0;
                }
            }
        } catch (Exception exception) {
            return false;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/thread-self/attr/current"))) {
            return uidValid && gidValid && rebootCapable &&
                    expectedContext.equals(
                            normaliseContext(reader.readLine()));
        } catch (Exception exception) {
            return false;
        }
    }

    private static void requestReboot(String reason) {
        int nativeStatus = BootCopy.rebootDevice();
        marker("REBOOT_NATIVE reason=" + reason +
                " status=" + nativeStatus);
        try {
            java.lang.Process child = new ProcessBuilder(
                    "/system/bin/reboot").start();
            boolean exited = child.waitFor(5000, TimeUnit.MILLISECONDS);
            int status = exited ? child.exitValue() : -1;
            if (!exited) {
                child.destroyForcibly();
            }
            marker("REBOOT reason=" + reason + " status=" + status);
        } catch (Exception exception) {
            marker("REBOOT reason=" + reason + " error=" +
                    errorName(exception));
        }
    }

    private static void rebootForever(String reason) {
        while (true) {
            requestReboot(reason);
            try {
                Thread.sleep(10_000);
            } catch (InterruptedException ignored) {
                // Keep retrying the root-capable reboot path.
            }
        }
    }

    private static void parkForever() {
        CountDownLatch latch = new CountDownLatch(1);
        while (true) {
            try {
                latch.await();
            } catch (InterruptedException ignored) {
                // Do not exit while the helper has a borrowed credential.
            }
        }
    }

    private static void partitionBackupLoop() throws Exception {
        List<FileOutputStream> outputs = new ArrayList<>();
        PartitionBackupTransport transport = null;
        boolean credentialRunArmed = false;
        boolean rootObserved = false;
        boolean backupComplete = false;
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), PARTITION_SIGNAL_PORT));
            FileOutputStream result = new FileOutputStream(
                    BACKUP_RESULT, false);
            try {
                for (String[] partition : PARTITIONS) {
                    outputs.add(new FileOutputStream(partition[1], false));
                }
            } catch (Exception exception) {
                closeOutputs(outputs);
                writeBackupResult(result, "status=fail stage=partition-backup " +
                        "reason=prepare-" + errorName(exception));
                result.close();
                throw exception;
            }

            readyMarker();
            transport = new PartitionBackupTransport(
                    server.accept(), outputs, result);
            transport.start();
            transport.awaitArm();
            credentialRunArmed = true;
            startCommandWatchdog();
            startIndependentShellWatchdog();
            marker("PARTITION_ARMED nonce=" + runNonce);

            long partialDeadline = 0;
            while (true) {
                if (Os.getuid() == Process.SHELL_UID &&
                        Os.geteuid() == Process.SHELL_UID &&
                        Os.getgid() == Process.SHELL_UID &&
                        Os.getegid() == Process.SHELL_UID) {
                    Thread.sleep(20);
                    continue;
                }
                if (Os.getuid() == 0 && Os.geteuid() == 0 &&
                        Os.getgid() == 0 && Os.getegid() == 0) {
                    rootObserved = true;
                    try {
                        RootWatchdogState watchdog =
                                startPartitionRootWatchdog();
                        transport.rootWatchdogReady(watchdog);
                    } catch (Exception exception) {
                        transport.rootWatchdogFailed(exception);
                        rebootForever("partition-watchdog-invalid");
                    }
                    break;
                }
                if (partialDeadline == 0) {
                    partialDeadline = System.nanoTime() +
                            30_000_000_000L;
                }
                if (System.nanoTime() >= partialDeadline) {
                    rebootForever("partition-root-invalid");
                }
                Thread.sleep(20);
            }

            transport.awaitExecute();
            requireRootWindow(
                    "u:r:hal_bootctl_default:s0", "0", "0", true);
            byte[] buffer = new byte[65_536];
            for (int index = 0; index < PARTITIONS.length; index++) {
                String name = PARTITIONS[index][0];
                try (FileInputStream source = new FileInputStream(
                        PARTITIONS[index][2])) {
                    GptRange range = findGptRange(
                            source.getChannel(), name);
                    source.getChannel().position(range.offset);
                    transport.copyPartition(
                            index, source, buffer, range.length);
                }
            }
            transport.awaitComplete();
            backupComplete = true;
        } catch (Exception exception) {
            if (transport != null) {
                transport.abort(exception);
            }
            marker("PARTITION_ERROR nonce=" + runNonce + " error=" +
                    errorName(exception));
        } finally {
            if (rootObserved || Os.geteuid() != Process.SHELL_UID ||
                    Os.getegid() != Process.SHELL_UID) {
                if (!backupComplete) {
                    rebootForever("partition-failed");
                }
                parkForever();
            }
            if (credentialRunArmed) {
                parkForever();
            }
            closeOutputs(outputs);
        }
    }

    private static final class GptRange {
        final long offset;
        final long length;

        GptRange(long offset, long length) {
            this.offset = offset;
            this.length = length;
        }
    }

    private static GptRange findGptRange(FileChannel channel, String name)
            throws Exception {
        GptRange found = null;
        for (int blockSize : new int[] {512, 4096}) {
            GptRange candidate = readGptRange(channel, name, blockSize);
            if (candidate == null) {
                continue;
            }
            if (found != null) {
                throw new IllegalStateException("gpt-block-size-ambiguous");
            }
            found = candidate;
        }
        if (found == null) {
            throw new IllegalStateException("gpt-partition-missing-" + name);
        }
        return found;
    }

    private static GptRange readGptRange(
            FileChannel channel, String name, int blockSize)
            throws Exception {
        byte[] header = readAt(channel, blockSize, blockSize);
        if (!Arrays.equals(Arrays.copyOfRange(header, 0, 8),
                "EFI PART".getBytes(StandardCharsets.US_ASCII))) {
            return null;
        }
        ByteBuffer fields = ByteBuffer.wrap(header)
                .order(ByteOrder.LITTLE_ENDIAN);
        long headerSize = Integer.toUnsignedLong(fields.getInt(12));
        long currentLba = fields.getLong(24);
        long backupLba = fields.getLong(32);
        long firstUsable = fields.getLong(40);
        long lastUsable = fields.getLong(48);
        long entriesLba = fields.getLong(72);
        long entryCount = Integer.toUnsignedLong(fields.getInt(80));
        long entrySize = Integer.toUnsignedLong(fields.getInt(84));
        long expectedEntriesCrc = Integer.toUnsignedLong(fields.getInt(88));
        if (headerSize < 92 || headerSize > blockSize || currentLba != 1 ||
                backupLba <= currentLba || firstUsable <= currentLba ||
                lastUsable < firstUsable || lastUsable >= backupLba ||
                entriesLba < 2 || entryCount == 0 || entryCount > 4096 ||
                entrySize < 128 || entrySize > 4096 ||
                entrySize % 8 != 0) {
            return null;
        }
        long expectedHeaderCrc = Integer.toUnsignedLong(fields.getInt(16));
        byte[] checkedHeader = Arrays.copyOf(header, (int) headerSize);
        Arrays.fill(checkedHeader, 16, 20, (byte) 0);
        if (crc32(checkedHeader) != expectedHeaderCrc) {
            return null;
        }
        long tableSize = Math.multiplyExact(entryCount, entrySize);
        if (tableSize > 16 * 1024 * 1024) {
            return null;
        }
        long tableOffset = Math.multiplyExact(entriesLba, blockSize);
        byte[] entries = readAt(
                channel, tableOffset, Math.toIntExact(tableSize));
        if (crc32(entries) != expectedEntriesCrc) {
            return null;
        }
        long backupOffset = Math.multiplyExact(backupLba, blockSize);
        byte[] backupHeader = readAt(channel, backupOffset, blockSize);
        if (!Arrays.equals(Arrays.copyOfRange(backupHeader, 0, 8),
                "EFI PART".getBytes(StandardCharsets.US_ASCII))) {
            return null;
        }
        ByteBuffer backupFields = ByteBuffer.wrap(backupHeader)
                .order(ByteOrder.LITTLE_ENDIAN);
        long backupHeaderSize = Integer.toUnsignedLong(
                backupFields.getInt(12));
        long backupHeaderCrc = Integer.toUnsignedLong(
                backupFields.getInt(16));
        long backupCurrentLba = backupFields.getLong(24);
        long backupPrimaryLba = backupFields.getLong(32);
        long backupFirstUsable = backupFields.getLong(40);
        long backupLastUsable = backupFields.getLong(48);
        long backupEntriesLba = backupFields.getLong(72);
        long backupEntryCount = Integer.toUnsignedLong(
                backupFields.getInt(80));
        long backupEntrySize = Integer.toUnsignedLong(
                backupFields.getInt(84));
        long backupEntriesCrc = Integer.toUnsignedLong(
                backupFields.getInt(88));
        if (backupHeaderSize < 92 || backupHeaderSize > blockSize ||
                backupCurrentLba != backupLba || backupPrimaryLba != 1 ||
                backupFirstUsable != firstUsable ||
                backupLastUsable != lastUsable ||
                backupEntriesLba <= lastUsable ||
                backupEntriesLba >= backupLba ||
                backupEntryCount != entryCount ||
                backupEntrySize != entrySize ||
                backupEntriesCrc != expectedEntriesCrc ||
                !Arrays.equals(
                        Arrays.copyOfRange(header, 56, 72),
                        Arrays.copyOfRange(backupHeader, 56, 72))) {
            return null;
        }
        byte[] checkedBackupHeader = Arrays.copyOf(
                backupHeader, (int) backupHeaderSize);
        Arrays.fill(checkedBackupHeader, 16, 20, (byte) 0);
        if (crc32(checkedBackupHeader) != backupHeaderCrc) {
            return null;
        }
        long backupTableOffset = Math.multiplyExact(
                backupEntriesLba, blockSize);
        byte[] backupEntries = readAt(
                channel, backupTableOffset, Math.toIntExact(tableSize));
        if (crc32(backupEntries) != expectedEntriesCrc ||
                !Arrays.equals(entries, backupEntries)) {
            return null;
        }

        GptRange found = null;
        for (int index = 0; index < entryCount; index++) {
            int offset = Math.toIntExact(index * entrySize);
            boolean used = false;
            for (int byteIndex = 0; byteIndex < 16; byteIndex++) {
                used |= entries[offset + byteIndex] != 0;
            }
            if (!used) {
                continue;
            }
            int nameBytes = Math.min((int) entrySize - 56, 72);
            int end = 0;
            while (end + 1 < nameBytes &&
                    (entries[offset + 56 + end] != 0 ||
                            entries[offset + 56 + end + 1] != 0)) {
                end += 2;
            }
            String entryName = new String(
                    entries, offset + 56, end, StandardCharsets.UTF_16LE);
            if (!name.equals(entryName)) {
                continue;
            }
            long first = ByteBuffer.wrap(entries, offset + 32, 8)
                    .order(ByteOrder.LITTLE_ENDIAN).getLong();
            long last = ByteBuffer.wrap(entries, offset + 40, 8)
                    .order(ByteOrder.LITTLE_ENDIAN).getLong();
            if (first < firstUsable || last < first || last > lastUsable) {
                throw new IllegalStateException("gpt-range-invalid-" + name);
            }
            long rangeOffset = Math.multiplyExact(first, blockSize);
            long rangeLength = Math.multiplyExact(
                    Math.addExact(Math.subtractExact(last, first), 1),
                    blockSize);
            if (rangeLength < 1 || rangeLength > PARTITION_LIMIT) {
                throw new IllegalStateException("gpt-size-invalid-" + name);
            }
            if (found != null) {
                throw new IllegalStateException("gpt-name-duplicate-" + name);
            }
            found = new GptRange(rangeOffset, rangeLength);
        }
        return found;
    }

    private static byte[] readAt(FileChannel channel, long offset, int size)
            throws Exception {
        byte[] value = new byte[size];
        ByteBuffer buffer = ByteBuffer.wrap(value);
        long position = offset;
        while (buffer.hasRemaining()) {
            int count = channel.read(buffer, position);
            if (count < 0) {
                throw new IllegalStateException("gpt-read-truncated");
            }
            if (count == 0) {
                throw new IllegalStateException("gpt-read-stalled");
            }
            position += count;
        }
        return value;
    }

    private static long crc32(byte[] value) {
        CRC32 crc = new CRC32();
        crc.update(value);
        return crc.getValue();
    }

    private static final class PartitionChunk {
        final int partition;
        final byte[] data;

        PartitionChunk(int partition, byte[] data) {
            this.partition = partition;
            this.data = data;
        }
    }

    private static final class PartitionBackupTransport {
        private final Socket socket;
        private final List<FileOutputStream> outputs;
        private final FileOutputStream result;
        private final ArrayBlockingQueue<PartitionChunk> chunks =
                new ArrayBlockingQueue<>(4);
        private final CountDownLatch started = new CountDownLatch(1);
        private final CountDownLatch armRequested = new CountDownLatch(1);
        private final CountDownLatch rootWatchdogReady =
                new CountDownLatch(1);
        private final CountDownLatch executeAllowed = new CountDownLatch(1);
        private final CountDownLatch complete = new CountDownLatch(1);
        private volatile Exception error;
        private volatile boolean shellIdentity;
        private volatile RootWatchdogState rootWatchdog;
        private volatile Exception rootWatchdogFailure;

        PartitionBackupTransport(Socket socket,
                List<FileOutputStream> outputs, FileOutputStream result) {
            this.socket = socket;
            this.outputs = outputs;
            this.result = result;
        }

        void start() throws Exception {
            Thread thread = new Thread(this::run, "lp3-partition-writer");
            thread.setDaemon(true);
            thread.start();
            if (!started.await(10_000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("partition-writer-timeout");
            }
            if (!shellIdentity || error != null) {
                throw new IllegalStateException("partition-writer-not-shell");
            }
        }

        void awaitExecute() throws Exception {
            if (!executeAllowed.await(90_000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("partition-execute-timeout");
            }
            if (error != null) {
                throw error;
            }
        }

        void rootWatchdogReady(RootWatchdogState watchdog) {
            rootWatchdog = watchdog;
            rootWatchdogReady.countDown();
        }

        void rootWatchdogFailed(Exception exception) {
            rootWatchdogFailure = exception;
            rootWatchdogReady.countDown();
        }

        void awaitArm() throws Exception {
            if (!armRequested.await(PARTITION_SIGNAL_TIMEOUT_MILLIS,
                    TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("partition-arm-timeout");
            }
            if (error != null) {
                throw error;
            }
        }

        void copyPartition(int index, FileInputStream source, byte[] buffer,
                long expectedLength) throws Exception {
            long total = 0;
            while (total < expectedLength) {
                int wanted = (int) Math.min(
                        buffer.length, expectedLength - total);
                int count = source.read(buffer, 0, wanted);
                if (count < 0) {
                    throw new IllegalStateException(
                            "partition-input-truncated-" +
                                    PARTITIONS[index][0]);
                }
                if (count == 0) {
                    throw new IllegalStateException(
                            "partition-input-stalled-" +
                                    PARTITIONS[index][0]);
                }
                total += count;
                if (total > PARTITION_LIMIT) {
                    throw new IllegalStateException(
                            "partition-too-large-" + PARTITIONS[index][0]);
                }
                put(new PartitionChunk(index, Arrays.copyOf(buffer, count)));
            }
            if (total != expectedLength) {
                throw new IllegalStateException(
                        "partition-length-invalid-" + PARTITIONS[index][0]);
            }
            put(new PartitionChunk(index, null));
        }

        void awaitComplete() throws Exception {
            if (!complete.await(300_000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("partition-copy-timeout");
            }
            if (error != null) {
                throw error;
            }
        }

        void abort(Exception exception) {
            error = exception;
            try {
                chunks.offer(new PartitionChunk(-1, null),
                        1000, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }

        private void put(PartitionChunk chunk) throws Exception {
            if (!chunks.offer(chunk, 30_000, TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("partition-writer-stalled");
            }
            if (error != null) {
                throw error;
            }
        }

        private void run() {
            String status = null;
            try {
                socket.setSoTimeout((int) PARTITION_SIGNAL_TIMEOUT_MILLIS);
                InputStream input = socket.getInputStream();
                shellIdentity = isShellThread();
                String suppliedNonce = readLine(input, 64);
                if (!shellIdentity || !runNonce.equals(suppliedNonce)) {
                    throw new SecurityException("partition-auth-invalid");
                }
                marker("PARTITION_AUTHENTICATED nonce=" + runNonce);
                started.countDown();
                if (input.read() != 0 || !isShellThread()) {
                    throw new IllegalStateException("partition-arm-invalid");
                }
                armRequested.countDown();
                if (!rootWatchdogReady.await(
                        WATCHDOG_TIMEOUT_MILLIS,
                        TimeUnit.MILLISECONDS) || !isShellThread()) {
                    throw new IllegalStateException(
                            "partition-root-watchdog-timeout");
                }
                if (rootWatchdogFailure != null) {
                    marker("PARTITION_ROOT_WATCHDOG_INVALID nonce=" +
                            runNonce + " error=" +
                            errorName(rootWatchdogFailure));
                    throw rootWatchdogFailure;
                }
                if (rootWatchdog == null || rootWatchdog.tid <= 0 ||
                        rootWatchdog.identity == null ||
                        !rootWatchdog.identity.startsWith("status=pass")) {
                    throw new IllegalStateException(
                            "partition-root-watchdog-invalid");
                }
                marker("PARTITION_ROOT_WATCHDOG_READY nonce=" + runNonce +
                        " tid=" + rootWatchdog.tid + " identity=[" +
                        rootWatchdog.identity + "]");
                if (input.read() != 1 || !isShellThread()) {
                    throw new IllegalStateException("partition-execute-invalid");
                }
                executeAllowed.countDown();

                StringBuilder details = new StringBuilder();
                for (int index = 0; index < PARTITIONS.length; index++) {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    long total = 0;
                    while (true) {
                        PartitionChunk chunk = chunks.poll(
                                WATCHDOG_TIMEOUT_MILLIS,
                                TimeUnit.MILLISECONDS);
                        if (chunk == null) {
                            throw new IllegalStateException(
                                    "partition-data-timeout");
                        }
                        if (chunk.partition < 0 && error != null) {
                            throw error;
                        }
                        if (chunk.partition != index) {
                            throw new IllegalStateException(
                                    "partition-data-order");
                        }
                        if (chunk.data == null) {
                            break;
                        }
                        total += chunk.data.length;
                        if (total > PARTITION_LIMIT) {
                            throw new IllegalStateException(
                                    "partition-output-too-large");
                        }
                        outputs.get(index).write(chunk.data);
                        digest.update(chunk.data);
                    }
                    outputs.get(index).getFD().sync();
                    if (total == 0) {
                        throw new IllegalStateException(
                                "partition-output-empty");
                    }
                    details.append(' ').append(PARTITIONS[index][0])
                            .append('=').append(total).append(':')
                            .append(hex(digest.digest()));
                }
                status = "status=pass stage=partition-backup" + details;
            } catch (Exception exception) {
                error = exception;
                status = "status=fail stage=partition-backup reason=" +
                        errorName(exception);
            } finally {
                started.countDown();
                armRequested.countDown();
                rootWatchdogReady.countDown();
                executeAllowed.countDown();
                closeOutputs(outputs);
                try {
                    writeBackupResult(result, status);
                    result.close();
                } catch (Exception exception) {
                    if (error == null) {
                        error = exception;
                    }
                }
                try {
                    socket.close();
                } catch (Exception ignored) {
                    // The helper will reboot after this backup attempt.
                }
                complete.countDown();
            }
        }
    }

    private static void jobStoreRepairLoop() throws Exception {
        List<FileOutputStream> outputs = new ArrayList<>();
        FileOutputStream result = null;
        try (FileInputStream commit = new FileInputStream(JOB_STORE_COMMIT)) {
            result = new FileOutputStream(JOB_STORE_RESULT, false);
            for (String[] item : JOB_STORE_FILES) {
                outputs.add(new FileOutputStream(item[1], false));
            }
            readyMarker();
            long rootDeadline = System.nanoTime() + 300_000_000_000L;
            while ((Os.geteuid() != Process.SYSTEM_UID ||
                    Os.getegid() != Process.SYSTEM_UID) &&
                    System.nanoTime() < rootDeadline) {
                Thread.sleep(20);
            }
            boolean[] present = new boolean[JOB_STORE_FILES.length];
            StringBuilder details = new StringBuilder();
            byte[] buffer = new byte[65_536];
            int copies = 0;
            for (int index = 0; index < JOB_STORE_FILES.length; index++) {
                String name = JOB_STORE_FILES[index][0];
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long size = copyJobStoreFile(name, outputs.get(index),
                        digest, buffer);
                present[index] = size >= 0;
                if (present[index]) {
                    copies++;
                    details.append(' ').append(name).append('=')
                            .append(size).append(':')
                            .append(hex(digest.digest()));
                } else {
                    details.append(' ').append(name).append("=missing");
                }
            }
            closeOutputs(outputs);
            if (copies == 0) {
                throw new IllegalStateException("no-jobstore-files");
            }
            writeBackupResult(result,
                    "status=ready stage=jobstore-backup" + details);
            long commitDeadline = System.nanoTime() + 120_000_000_000L;
            int commitSignal = -1;
            while (System.nanoTime() < commitDeadline) {
                commitSignal = commit.read();
                if (commitSignal >= 0) {
                    break;
                }
                Thread.sleep(20);
            }
            if (commitSignal != '2') {
                throw new IllegalStateException("commit-signal");
            }

            for (int index = 0; index < JOB_STORE_FILES.length; index++) {
                File file = new File(JOB_STORE_DIRECTORY,
                        JOB_STORE_FILES[index][0]);
                if (present[index] && !file.delete() && file.exists()) {
                    throw new IllegalStateException(
                            "delete-" + JOB_STORE_FILES[index][0]);
                }
            }
            syncJobStoreDirectory();
            writeBackupResult(result,
                    "status=pass stage=jobstore-repair files=" + copies);
            new CountDownLatch(1).await();
        } catch (Exception exception) {
            if (result != null) {
                try {
                    writeBackupResult(result,
                            "status=fail stage=jobstore-repair reason=" +
                            errorName(exception));
                } catch (Exception ignored) {
                    // The host will reboot after its bounded action timeout.
                }
            }
            new CountDownLatch(1).await();
        } finally {
            closeOutputs(outputs);
            if (result != null) {
                try {
                    result.close();
                } catch (Exception ignored) {
                    // The durable result was already written.
                }
            }
        }
    }

    private static long copyJobStoreFile(String name, FileOutputStream output,
            MessageDigest digest, byte[] buffer) throws Exception {
        File sourceFile = new File(JOB_STORE_DIRECTORY, name);
        if (!sourceFile.exists()) {
            return -1;
        }
        long total = 0;
        try (FileInputStream source = new FileInputStream(sourceFile)) {
            int count;
            while ((count = source.read(buffer)) != -1) {
                if (total + count > JOB_STORE_LIMIT) {
                    throw new IllegalStateException("jobstore-too-large-" + name);
                }
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                total += count;
            }
        }
        output.getFD().sync();
        if (total == 0) {
            throw new IllegalStateException("jobstore-empty-" + name);
        }
        return total;
    }

    private static void syncJobStoreDirectory() throws Exception {
        FileDescriptor descriptor = Os.open(JOB_STORE_DIRECTORY,
                OsConstants.O_RDONLY, 0);
        try {
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private static void requireRootWindow(String expectedContext,
            String expectedId,
            String expectedFileSystemId,
            boolean requireRealAndSavedIds) throws Exception {
        String[] uid = null;
        String[] gid = null;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    uid = line.substring(4).trim().split("\\s+");
                } else if (line.startsWith("Gid:")) {
                    gid = line.substring(4).trim().split("\\s+");
                }
            }
        }
        String context;
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/self/attr/current"))) {
            context = normaliseContext(reader.readLine());
        }
        boolean idShapeValid = uid != null && gid != null &&
                uid.length == 4 && gid.length == 4;
        boolean realAndSavedIdsValid = idShapeValid &&
                (!requireRealAndSavedIds ||
                expectedId.equals(uid[0]) && expectedId.equals(uid[2]) &&
                expectedId.equals(gid[0]) && expectedId.equals(gid[2]));
        if (!idShapeValid ||
                !expectedId.equals(uid[1]) ||
                !expectedFileSystemId.equals(uid[3]) ||
                !expectedId.equals(gid[1]) ||
                !expectedFileSystemId.equals(gid[3]) ||
                !realAndSavedIdsValid ||
                !expectedContext.equals(context)) {
            throw new IllegalStateException("root-window-invalid");
        }
    }

    private static void closeOutputs(List<FileOutputStream> outputs) {
        for (FileOutputStream output : outputs) {
            try {
                output.close();
            } catch (Exception ignored) {
                // The result reports the first copy error.
            }
        }
    }

    private static void writeBackupResult(FileOutputStream output, String value)
            throws Exception {
        output.getChannel().position(0);
        output.getChannel().truncate(0);
        output.write((value + "\n").getBytes(StandardCharsets.UTF_8));
        output.getFD().sync();
    }

    private static String errorName(Throwable exception) {
        String message = exception.getMessage();
        String value = exception.getClass().getSimpleName() +
                (message == null ? "" : "-" + message);
        return value.replaceAll("[^A-Za-z0-9._/-]", "-");
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static void registerTarget(int securityPid, String mode)
            throws Exception {
        boolean securityPidOnly =
                "hold-partition-backup-hal".equals(mode);
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getSystemService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        getSystemService.setAccessible(true);
        String service = "hold-jobstore-repair".equals(mode) ||
                "hold-system-server".equals(mode)
                ? "jobscheduler" : "android.os.UpdateEngineService";
        IBinder securityTarget = securityPidOnly ? null :
                (IBinder) getSystemService.invoke(null, service);
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(
                "com.vandam.prism",
                "com.vandam.prism.HarnessService"));
        intent.putExtra("stage", "register-shell");
        intent.putExtra("shell_pid", Process.myPid());
        Bundle extras = new Bundle();
        extras.putBinder("shell_target", TARGET);
        if (securityTarget != null) {
            extras.putBinder("security_target", securityTarget);
        }
        extras.putInt("security_pid", securityPid);
        extras.putBoolean("security_pid_only", securityPidOnly);
        intent.putExtras(extras);

        Class<?> activityManager = Class.forName(
                "android.app.ActivityManager");
        Method getService = activityManager.getDeclaredMethod("getService");
        getService.setAccessible(true);
        Object manager = getService.invoke(null);
        Method startService = null;
        for (Method method : manager.getClass().getMethods()) {
            Class<?>[] types = method.getParameterTypes();
            if ("startService".equals(method.getName()) &&
                    types.length == 7 && types[1] == Intent.class) {
                startService = method;
                break;
            }
        }
        if (startService == null) {
            throw new IllegalStateException("start-service-method");
        }
        startService.setAccessible(true);
        Object component = startService.invoke(manager, null, intent, null,
                true, "com.android.shell", null, 0);
        if (!(component instanceof ComponentName)) {
            throw new IllegalStateException("start-service-result=" +
                    String.valueOf(component));
        }
    }

    private static void marker(String value) {
        System.out.println("BRIDGE_" + value);
        System.out.flush();
    }

    private static void readyMarker() {
        marker("READY nonce=" + runNonce + " pid=" + Process.myPid());
    }

    private static void commandLoop() {
        try {
            BufferedReader input = new BufferedReader(new InputStreamReader(
                    System.in, StandardCharsets.UTF_8));
            String command;
            while ((command = input.readLine()) != null) {
                if ("exit".equals(command)) {
                    System.exit(0);
                }
                if ("status".equals(command)) {
                    printStatus();
                } else if ("copy-boot".equals(command)) {
                    copyBoot();
                } else if (!command.isEmpty()) {
                    runCommand(command);
                }
                System.out.println("BRIDGE_DONE");
                System.out.flush();
            }
        } catch (Exception exception) {
            exception.printStackTrace(System.out);
            System.out.flush();
        }
    }

    private static void copyBoot() throws Exception {
        String prepared = BootCopy.prepareDestination(
                "/data/local/tmp/boot.img", 100_663_296L);
        System.out.println(prepared);
        System.out.flush();
        if (!prepared.startsWith("BOOT_COPY status=ready")) {
            return;
        }
        int signal;
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), COPY_SIGNAL_PORT));
            server.setSoTimeout(300_000);
            System.out.println("BOOT_COPY status=ready stage=signal");
            System.out.flush();
            try (Socket socket = server.accept()) {
                signal = socket.getInputStream().read();
            }
        }
        if (signal != 1) {
            BootCopy.closeDestination();
            System.out.println("BOOT_COPY status=miss reason=signal");
            return;
        }
        System.out.println(BootCopy.whenReadable(
                "/dev/block/by-name/boot_a", 300_000));
    }

    private static void printStatus() throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(
                "/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:") || line.startsWith("Gid:") ||
                        line.startsWith("Cap") ||
                        line.startsWith("Seccomp:")) {
                    System.out.println(line);
                }
            }
        }
        File context = new File("/proc/self/attr/current");
        if (context.canRead()) {
            try (BufferedReader reader = new BufferedReader(
                    new FileReader(context))) {
                System.out.println("Context:\t" + reader.readLine());
            }
        }
    }

    private static void runCommand(String command) throws Exception {
        java.lang.Process child = new ProcessBuilder(
                "/system/bin/sh", "-c", command)
                .redirectErrorStream(true)
                .start();
        try (BufferedReader output = new BufferedReader(
                new InputStreamReader(child.getInputStream(),
                        StandardCharsets.UTF_8))) {
            String line;
            while ((line = output.readLine()) != null) {
                System.out.println(line);
            }
        }
        System.out.println("exit=" + child.waitFor());
    }
}
