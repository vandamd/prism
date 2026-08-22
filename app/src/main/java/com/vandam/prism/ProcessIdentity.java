package com.vandam.prism;

import android.os.Process;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

final class ProcessIdentity {
    final int pid;
    final long startTime;

    ProcessIdentity(int pid, long startTime) {
        this.pid = pid;
        this.startTime = startTime;
    }

    static long currentStartTime() {
        return readStartTime(Process.myPid());
    }

    static long readStartTime(int pid) {
        if (pid <= 0) {
            return -1;
        }
        try {
            String stat = new String(Files.readAllBytes(
                    new File("/proc/" + pid + "/stat").toPath()),
                    StandardCharsets.US_ASCII).trim();
            int close = stat.lastIndexOf(')');
            if (close < 0) {
                return -1;
            }
            String[] fields = stat.substring(close + 1).trim()
                    .split("\\s+");
            if (fields.length <= 19 ||
                    !fields[19].matches("[0-9]+")) {
                return -1;
            }
            return Long.parseLong(fields[19]);
        } catch (Exception exception) {
            return -1;
        }
    }
}
