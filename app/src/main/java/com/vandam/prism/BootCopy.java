package com.vandam.prism;

final class BootCopy {
    private BootCopy() {}

    static void load(String apkPath) {
        System.load(apkPath + "!/lib/arm64-v8a/libbootcopy.so");
    }

    static native String prepareDestination(String destination,
                                            long expectedSize);

    static native String whenReadable(String source, int timeoutMillis);

    static native void closeDestination();

    static native boolean waitForArmLock(String path);

    static native int rebootDevice();

    static native String rootWatchdogIdentity();
}
