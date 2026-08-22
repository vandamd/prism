package com.vandam.prism;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AnchorHolderService extends Service {
    static final int TRANSACTION_RETAIN = 0x42a0;
    static final int TRANSACTION_TERMINAL_RETIRE = 0x42a1;
    static final int TRANSACTION_PID = 0x42a2;
    static final int TRANSACTION_IDENTITY = 0x42a3;

    private IBinder retained;
    private final AtomicBoolean terminalArmed = new AtomicBoolean();
    private final Binder controller = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == TRANSACTION_RETAIN) {
                retained = data.readStrongBinder();
                reply.writeNoException();
                reply.writeInt(retained != null ? 1 : 0);
                return true;
            }
            if (code == TRANSACTION_TERMINAL_RETIRE) {
                int expectedPid = data.readInt();
                long expectedStart = data.readLong();
                String nonce = data.readString();
                String bootId = data.readString();
                if ((flags & IBinder.FLAG_ONEWAY) != 0 || reply == null ||
                        Binder.getCallingUid() !=
                                getApplicationInfo().uid ||
                        Binder.getCallingPid() <= 0 ||
                        Binder.getCallingPid() ==
                                android.os.Process.myPid() ||
                        expectedPid != android.os.Process.myPid() ||
                        expectedStart !=
                                ProcessIdentity.currentStartTime() ||
                        nonce == null ||
                        !nonce.matches("[0-9a-f]{32}") ||
                        bootId == null || !bootId.equals(currentBootId()) ||
                        data.dataAvail() != 0 ||
                        !terminalArmed.compareAndSet(false, true)) {
                    return false;
                }
                retained = null;
                String state =
                        "status=pass stage=anchor-terminal-arm" +
                        " nonce=" + nonce +
                        " anchor_pid=" + expectedPid +
                        " anchor_start_time=" + expectedStart +
                        " boot_id=" + bootId + " armed=1";
                write("anchor-terminal-arm.result", state);
                reply.writeNoException();
                reply.writeString(state);
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
            return false;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return controller;
    }

    @Override
    public void onDestroy() {
        retained = null;
        super.onDestroy();
        if (terminalArmed.get()) {
            android.os.Process.killProcess(android.os.Process.myPid());
        }
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
