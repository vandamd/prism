package com.vandam.prism;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class RawTargetService extends Service {
    static final String EXTRA_NONCE = "raw-target-nonce";
    static final String EXTRA_BOOT_ID = "raw-target-boot-id";
    static final String EXTRA_TERMINAL_CLEANUP =
            "raw-target-terminal-cleanup";
    static final int TRANSACTION_BLOCK = 0x4280;
    static final int TRANSACTION_COHORT_SETTLE = 0x42a1;
    static final int TRANSACTION_IDENTITY = 0x42a3;
    static final int TRANSACTION_BOUNDARY_SIGNAL = 0x42a4;
    static final int BLOCKER_COUNT = 16;

    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger blocked = new AtomicInteger();
    private String ownerNonce = "";
    private String ownerBootId = "";
    private boolean ownerTerminalCleanup;
    private boolean ownerMetadataValid;
    private long ownerStartTime;
    private boolean ownerArmed;
    private final Binder target = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == TRANSACTION_IDENTITY) {
                reply.writeNoException();
                reply.writeInt(Process.myPid());
                reply.writeLong(ProcessIdentity.currentStartTime());
                return true;
            }
            if (code == TRANSACTION_BOUNDARY_SIGNAL) {
                ParcelFileDescriptor boundarySignal =
                        data.readFileDescriptor();
                int boundarySignalFd = boundarySignal == null
                        ? -1 : boundarySignal.detachFd();
                boolean armed = false;
                boolean ownershipTransferred = false;
                synchronized (RawTargetService.this) {
                    if (!ownerArmed && ownerMetadataValid &&
                            boundarySignalFd >= 0) {
                        ownershipTransferred = true;
                        armed = NativeBridge.armRawTargetOwner(
                                getFilesDir().getAbsolutePath(),
                                ownerNonce, ownerBootId, ownerStartTime,
                                ownerTerminalCleanup, boundarySignalFd);
                        ownerArmed = armed;
                    }
                }
                if (!ownershipTransferred && boundarySignalFd >= 0) {
                    try {
                        ParcelFileDescriptor.adoptFd(
                                boundarySignalFd).close();
                    } catch (Exception ignored) {
                    }
                }
                reply.writeNoException();
                reply.writeInt(armed ? 1 : 0);
                return true;
            }
            if (code != TRANSACTION_BLOCK) {
                return false;
            }
            int count = blocked.incrementAndGet();
            if (count == BLOCKER_COUNT) {
                write("raw-target.blocked",
                        "status=ready blocked=" + count + " pid=" +
                                Process.myPid() + " start_time=" +
                                ProcessIdentity.currentStartTime());
            }
            try {
                release.await();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            return true;
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public IBinder onBind(Intent intent) {
        String nonce = intent == null ? "" :
                intent.getStringExtra(EXTRA_NONCE);
        String bootId = intent == null ? "" :
                intent.getStringExtra(EXTRA_BOOT_ID);
        boolean terminalCleanup = intent != null &&
                intent.getBooleanExtra(EXTRA_TERMINAL_CLEANUP, false);
        if (nonce == null) {
            nonce = "";
        }
        if (bootId == null) {
            bootId = "";
        }
        long startTime = ProcessIdentity.currentStartTime();
        boolean terminalMetadata = !terminalCleanup ||
                (isValidNonce(nonce) && isValidBootId(bootId) &&
                        bootId.equals(currentBootId()));
        ownerNonce = nonce;
        ownerBootId = bootId;
        ownerTerminalCleanup = terminalCleanup;
        ownerStartTime = startTime;
        ownerMetadataValid = terminalMetadata && startTime > 0;
        ownerArmed = false;
        if (!ownerMetadataValid) {
            write("raw-target.result",
                    "status=fail stage=raw-target reason=arm");
        }
        return target;
    }

    @Override
    public void onDestroy() {
        release.countDown();
        super.onDestroy();
    }

    private static boolean isValidNonce(String value) {
        return value != null && value.matches("[0-9a-f]{32}");
    }

    private static boolean isValidBootId(String value) {
        return value != null && value.matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                "[0-9a-f]{4}-[0-9a-f]{12}");
    }

    private static String currentBootId() {
        try {
            return new String(Files.readAllBytes(new File(
                    "/proc/sys/kernel/random/boot_id").toPath()),
                    StandardCharsets.US_ASCII).trim();
        } catch (Exception exception) {
            return "";
        }
    }

    private void write(String name, String value) {
        File file = new File(getFilesDir(), name);
        try (FileOutputStream stream = new FileOutputStream(file, false)) {
            stream.write((value + "\n").getBytes(StandardCharsets.UTF_8));
            stream.getFD().sync();
        } catch (Exception ignored) {
        }
    }

}
