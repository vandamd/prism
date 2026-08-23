package com.vandam.prism.primitive;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Package-free Binder-reference exchange probe for the native primitive. */
public final class PrimitiveBinderBridge {
    private static final int TRANSACTION_PROOF = IBinder.FIRST_CALL_TRANSACTION;
    private static final String EXTRA_BINDER = "binder";
    private static final String EXTRA_NONCE = "nonce";

    private PrimitiveBinderBridge() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 2 ||
                !("receive".equals(arguments[0]) ||
                  "send".equals(arguments[0]) ||
                  "inspect".equals(arguments[0])) ||
                !arguments[1].matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException("receive|send|inspect nonce");
        }
        if ("inspect".equals(arguments[0])) {
            for (String className : new String[] {
                    "android.app.IActivityManager",
                    "android.content.IIntentReceiver"}) {
                for (Method method : Class.forName(
                        className).getDeclaredMethods()) {
                    if (className.endsWith("IIntentReceiver") ||
                            method.getName().contains("Receiver") ||
                            method.getName().contains("broadcastIntent")) {
                        System.out.println(method.toGenericString());
                    }
                }
            }
            return;
        }
        String action = "com.vandam.prism.primitive.BINDER." + arguments[1];
        if ("receive".equals(arguments[0])) {
            receive(activityManager(), action, arguments[1]);
        } else {
            send(activityManager(), action, arguments[1]);
        }
    }

    private static Object activityManager() throws Exception {
        Class<?> activityManagerClass = Class.forName(
                "android.app.ActivityManager");
        Method getService = activityManagerClass.getDeclaredMethod("getService");
        return getService.invoke(null);
    }

    private static void receive(Object activityManager, String action,
                                String nonce) throws Exception {
        Class<?> receiverInterface = Class.forName(
                "android.content.IIntentReceiver");
        ReceiverEndpoint endpoint = new ReceiverEndpoint(nonce);
        Object receiver = Proxy.newProxyInstance(
                PrimitiveBinderBridge.class.getClassLoader(),
                new Class<?>[] {receiverInterface},
                (proxy, method, arguments) -> {
                    if ("asBinder".equals(method.getName())) {
                        return endpoint;
                    }
                    if ("toString".equals(method.getName())) {
                        return "PrimitiveBinderBridgeReceiver";
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    if ("equals".equals(method.getName())) {
                        return proxy == arguments[0];
                    }
                    return null;
                });
        endpoint.attachInterface((IInterface) receiver,
                ReceiverEndpoint.DESCRIPTOR);
        Method register = findMethod(
                activityManager.getClass(), "registerReceiver", 7);
        register.invoke(activityManager, null, "com.android.shell", receiver,
                new IntentFilter(action), null, 0, Context.RECEIVER_EXPORTED);
        System.out.println("BRIDGE_READY pid=" + android.os.Process.myPid());
        System.out.flush();
        new CountDownLatch(1).await();
    }

    private static void send(Object activityManager, String action, String nonce)
            throws Exception {
        CountDownLatch called = new CountDownLatch(1);
        Binder binder = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply,
                                         int flags) throws RemoteException {
                if (code != TRANSACTION_PROOF ||
                        !nonce.equals(data.readString())) {
                    return false;
                }
                reply.writeInt(android.os.Process.myPid());
                reply.writeString(nonce);
                called.countDown();
                return true;
            }
        };
        Intent intent = new Intent(action);
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
        Bundle extras = new Bundle();
        extras.putBinder(EXTRA_BINDER, binder);
        extras.putString(EXTRA_NONCE, nonce);
        intent.putExtras(extras);
        long started = android.os.SystemClock.elapsedRealtimeNanos();
        Method broadcast = findMethod(
                activityManager.getClass(), "broadcastIntent", 13);
        broadcast.invoke(activityManager, null, intent, null, null, 0, null,
                null, null, -1, null, false, false, 0);
        boolean passed = called.await(5, TimeUnit.SECONDS);
        long duration = android.os.SystemClock.elapsedRealtimeNanos() - started;
        System.out.println("BRIDGE_SEND status=" + (passed ? "pass" : "fail") +
                " pid=" + android.os.Process.myPid() +
                " duration_ns=" + duration);
        System.out.flush();
        System.exit(passed ? 0 : 1);
    }

    private static Method findMethod(Class<?> type, String name,
                                     int parameterCount) {
        for (Method method : type.getMethods()) {
            if (name.equals(method.getName()) &&
                    method.getParameterTypes().length == parameterCount) {
                return method;
            }
        }
        throw new IllegalStateException(name + "-method");
    }

    private static final class ReceiverEndpoint extends Binder {
        static final String DESCRIPTOR = "android.content.IIntentReceiver";
        private final String nonce;

        ReceiverEndpoint(String nonce) {
            this.nonce = nonce;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) throws RemoteException {
            if (code != TRANSACTION_PROOF) {
                return super.onTransact(code, data, reply, flags);
            }
            data.enforceInterface(DESCRIPTOR);
            Intent intent = data.readTypedObject(Intent.CREATOR);
            data.readInt();
            data.readString();
            data.readTypedObject(Bundle.CREATOR);
            data.readBoolean();
            data.readBoolean();
            data.readInt();
            if (intent == null) {
                return true;
            }
            Bundle extras = intent.getExtras();
            IBinder binder = extras == null
                    ? null : extras.getBinder(EXTRA_BINDER);
            String receivedNonce = extras == null
                    ? null : extras.getString(EXTRA_NONCE);
            if (binder == null || !nonce.equals(receivedNonce) ||
                    !binder.isBinderAlive()) {
                return true;
            }
            Parcel proofData = Parcel.obtain();
            Parcel proofReply = Parcel.obtain();
            try {
                proofData.writeString(nonce);
                if (!binder.transact(
                        TRANSACTION_PROOF, proofData, proofReply, 0)) {
                    return true;
                }
                int senderPid = proofReply.readInt();
                String proof = proofReply.readString();
                if (senderPid > 0 && nonce.equals(proof)) {
                    System.out.println("BRIDGE_PASS receiver_pid=" +
                            android.os.Process.myPid() + " sender_pid=" +
                            senderPid + " remote=" +
                            (binder instanceof Binder ? 0 : 1));
                    System.out.flush();
                    System.exit(0);
                }
            } finally {
                proofReply.recycle();
                proofData.recycle();
            }
            return true;
        }
    }
}
