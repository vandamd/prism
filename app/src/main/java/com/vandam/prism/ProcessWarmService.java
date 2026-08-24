package com.vandam.prism;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

abstract class ProcessWarmService extends Service {
    protected abstract String markerName();

    @Override
    public final int onStartCommand(Intent intent, int flags, int startId) {
        String state = "status=pass pid=" + Process.myPid() +
                " start=" + ProcessIdentity.currentStartTime();
        try (FileOutputStream output = new FileOutputStream(
                new File(getFilesDir(), markerName()), false)) {
            output.write(state.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception ignored) {
        }
        stopSelf(startId);
        return START_NOT_STICKY;
    }

    @Override
    public final IBinder onBind(Intent intent) {
        return null;
    }
}
