package com.vandam.prism;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/** Shell-side client for the narrow app-UID activation loopback channel. */
final class PrismAppBridgeClient implements AutoCloseable {
    static final int MAGIC = 0x50524953;
    static final int VERSION = 1;
    static final int OP_PROBE = 1;
    static final int OP_OPEN = 2;
    static final int OP_READ = 3;
    static final int OP_WRITE = 4;
    static final int OP_START = 5;
    static final int OP_CLOSE = 6;
    static final int OP_VALIDATE_PROCESS_TEARDOWN = 7;
    static final int OP_COMPLETE_PROCESS_TEARDOWN = 8;
    static final int OP_INSPECT_PROCESS_TEARDOWN_RESIDUE = 9;
    static final int OP_RECORD_STRICT_CLEAN_RECEIPT = 10;
    static final int OP_RECORD_SAFE_MISS_RECEIPT = 11;
    static final int OP_INSPECT_SAFE_RESET = 12;
    static final int OP_COMPLETE_SAFE_RESET = 13;
    static final int OP_ACKNOWLEDGE_SAFE_RESET = 14;
    static final int MAX_RESPONSE = 512 * 1024;

    private static final int MIN_PORT = 49_152;
    private static final int PORT_COUNT = 65_536 - MIN_PORT;

    private final Socket socket;
    private final DataInputStream input;
    private final DataOutputStream output;
    private boolean closed;

    private PrismAppBridgeClient(
            Socket socket,
            DataInputStream input,
            DataOutputStream output) {
        this.socket = socket;
        this.input = input;
        this.output = output;
    }

    static PrismAppBridgeClient connect(
            Context context, String session, String bootId) throws Exception {
        int port = MIN_PORT + new SecureRandom().nextInt(PORT_COUNT);
        String[] startCommand = {
                "/system/bin/am", "start-foreground-service", "--user", "0",
                "-n", context.getPackageName() + "/.PrismAppBridgeService",
                "--es", "session", session,
                "--es", "boot-id", bootId,
                "--ei", "port", Integer.toString(port)
        };
        CommandResult start = command(startCommand);
        if (start.exit != 0) {
            throw new IllegalStateException("app-bridge-start-" + start.output);
        }

        long deadline = android.os.SystemClock.elapsedRealtime() + 10_000;
        long nextStart = android.os.SystemClock.elapsedRealtime() + 500;
        Exception last = null;
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(
                        InetAddress.getLoopbackAddress(), port), 250);
                socket.setSoTimeout(15_000);
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                writeString(output, session);
                writeString(output, bootId);
                output.flush();
                String response = readString(input, 4096);
                if (!response.startsWith("status=pass ")) {
                    socket.close();
                    throw new IllegalStateException(response);
                }
                return new PrismAppBridgeClient(socket, input, output);
            } catch (Exception exception) {
                last = exception;
                try {
                    socket.close();
                } catch (Exception ignored) {}
                long now = android.os.SystemClock.elapsedRealtime();
                if (now >= nextStart) {
                    CommandResult retry = command(startCommand);
                    if (retry.exit != 0) {
                        last = new IllegalStateException(
                                "app-bridge-restart-" + retry.output);
                    }
                    nextStart = now + 500;
                }
                Thread.sleep(50);
            }
        }
        throw new IllegalStateException("app-bridge-connect", last);
    }

    String probe() throws Exception {
        return request(OP_PROBE);
    }

    String openSession() throws Exception {
        return request(OP_OPEN);
    }

    String readSignal(int signal) throws Exception {
        return request(OP_READ, Integer.toString(signal));
    }

    String writeGate(int gate, String value) throws Exception {
        return request(OP_WRITE, Integer.toString(gate), value);
    }

    String startRootChain(
            String bridgeNonce,
            int helperPid,
            String helperStart,
            int donorPid,
            String donorStart,
            int ueventdPid) throws Exception {
        return request(
                OP_START,
                bridgeNonce,
                Integer.toString(helperPid),
                helperStart,
                Integer.toString(donorPid),
                donorStart,
                Integer.toString(ueventdPid));
    }

    String closeSession() throws Exception {
        return request(OP_CLOSE);
    }

    String validateProcessTeardown(String token) throws Exception {
        return request(OP_VALIDATE_PROCESS_TEARDOWN, token);
    }

    String completeProcessTeardown(String token) throws Exception {
        return request(OP_COMPLETE_PROCESS_TEARDOWN, token);
    }

    String inspectProcessTeardownResidue() throws Exception {
        return request(OP_INSPECT_PROCESS_TEARDOWN_RESIDUE);
    }

    String recordStrictCleanReceipt(String receipt) throws Exception {
        return request(OP_RECORD_STRICT_CLEAN_RECEIPT, receipt);
    }

    String recordSafeMissReceipt(
            String result, String progress, String binding) throws Exception {
        return request(OP_RECORD_SAFE_MISS_RECEIPT, result, progress, binding);
    }

    String inspectSafeReset() throws Exception {
        return request(OP_INSPECT_SAFE_RESET);
    }

    String completeSafeReset(String binding, String receipt) throws Exception {
        return request(OP_COMPLETE_SAFE_RESET, binding, receipt);
    }

    String acknowledgeSafeReset(String binding) throws Exception {
        return request(OP_ACKNOWLEDGE_SAFE_RESET, binding);
    }

    private synchronized String request(int operation, String... values)
            throws Exception {
        if (closed) {
            throw new IllegalStateException("app-bridge-closed");
        }
        output.writeInt(operation);
        output.writeInt(values.length);
        for (String value : values) {
            writeString(output, value);
        }
        output.flush();
        return readString(input, MAX_RESPONSE);
    }

    @Override
    public void close() {
        closed = true;
        try {
            socket.close();
        } catch (Exception ignored) {}
    }

    static void writeString(DataOutputStream output, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    static String readString(DataInputStream input, int limit) throws Exception {
        int length = input.readInt();
        if (length < 0 || length > limit) {
            throw new IllegalStateException("app-bridge-frame-size");
        }
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static CommandResult command(String... command) throws Exception {
        java.lang.Process process = new java.lang.ProcessBuilder(command)
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Exception[] readFailure = new Exception[1];
        Thread reader = new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > 64 * 1024) {
                        process.destroyForcibly();
                        throw new IllegalStateException(
                                "app-bridge-command-output");
                    }
                    output.write(buffer, 0, count);
                }
            } catch (Exception exception) {
                readFailure[0] = exception;
            }
        }, "prism-app-bridge-command");
        reader.setDaemon(true);
        reader.start();
        boolean finished = process.waitFor(30, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
        }
        reader.join(5_000);
        if (!finished) {
            throw new IllegalStateException("app-bridge-command-timeout");
        }
        if (reader.isAlive()) {
            process.destroyForcibly();
            throw new IllegalStateException("app-bridge-command-reader");
        }
        if (readFailure[0] != null) {
            throw readFailure[0];
        }
        return new CommandResult(
                process.exitValue(),
                output.toString(StandardCharsets.UTF_8.name()).trim());
    }

    private static final class CommandResult {
        final int exit;
        final String output;

        CommandResult(int exit, String output) {
            this.exit = exit;
            this.output = output;
        }
    }
}
