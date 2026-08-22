package com.vandam.prism;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;

import java.util.ArrayList;
import java.util.List;

public final class IsolatedRefService extends Service {
    static final int TRANSACTION_PIN = 0x4270;
    static final int TRANSACTION_RETAIN = 0x4271;
    static final int TRANSACTION_RETAIN_RAW = 0x4272;
    static final int TRANSACTION_RETAIN_BATCH = 0x4273;
    static final int TRANSACTION_PREPARE = 0x4274;
    static final int TRANSACTION_RETAIN_DEATH = 0x4275;

    private final List<IBinder> retained = new ArrayList<>();
    private final List<IBinder.DeathRecipient> deathRecipients =
            new ArrayList<>();
    private final Binder controller = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == TRANSACTION_PIN) {
                int cpu = NativeBridge.pinCurrentThread(2);
                reply.writeNoException();
                reply.writeInt(Process.myPid());
                reply.writeInt(cpu);
                return true;
            }
            if (code == TRANSACTION_PREPARE) {
                int count = data.readInt();
                for (int index = 0; index < count; index++) {
                    IBinder filler = data.readStrongBinder();
                    if (filler != null) {
                        retained.add(filler);
                    }
                }
                reply.writeNoException();
                reply.writeInt(Process.myPid());
                reply.writeInt(retained.size());
                return true;
            }
            if (code != TRANSACTION_RETAIN &&
                    code != TRANSACTION_RETAIN_RAW &&
                    code != TRANSACTION_RETAIN_BATCH &&
                    code != TRANSACTION_RETAIN_DEATH) {
                return false;
            }
            int positionBefore = data.dataPosition();
            int dataSize = data.dataSize();
            if (code == TRANSACTION_RETAIN_BATCH) {
                int count = data.readInt();
                for (int index = 0; index < count; index++) {
                    IBinder filler = data.readStrongBinder();
                    if (filler != null) {
                        retained.add(filler);
                    }
                }
            }
            IBinder binder = data.readStrongBinder();
            int positionAfter = data.dataPosition();
            if (binder != null) {
                retained.add(binder);
                if (code == TRANSACTION_RETAIN_DEATH) {
                    IBinder.DeathRecipient recipient = () -> { };
                    try {
                        binder.linkToDeath(recipient, 0);
                        deathRecipients.add(recipient);
                    } catch (Exception ignored) {
                    }
                }
            }
            if (code == TRANSACTION_RETAIN ||
                    code == TRANSACTION_RETAIN_BATCH ||
                    code == TRANSACTION_RETAIN_DEATH) {
                reply.writeNoException();
            }
            reply.writeInt(Process.myPid());
            reply.writeInt(retained.size());
            if (code == TRANSACTION_RETAIN_RAW) {
                reply.writeInt(positionBefore);
                reply.writeInt(positionAfter);
                reply.writeInt(dataSize);
            }
            return true;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return controller;
    }
}
