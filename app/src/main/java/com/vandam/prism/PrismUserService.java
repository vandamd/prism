package com.vandam.prism;

import android.content.Context;
import android.system.Os;

import androidx.annotation.Keep;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class PrismUserService extends IPrismUserService.Stub {
    private static final Path BOOT_ID =
            Path.of("/proc/sys/kernel/random/boot_id");

    private final ReSukiSuActivationController activationController;

    public PrismUserService() {
        activationController = null;
    }

    @Keep
    public PrismUserService(Context context) {
        activationController = new ReSukiSuActivationController(context);
    }

    @Override
    public String preflight(String nonce) {
        if (nonce == null || !nonce.matches("[0-9a-f]{64}")) {
            return "status=fail reason=nonce";
        }
        int uid = Os.getuid();
        if (uid != 2000) {
            return "status=fail reason=uid uid=" + uid;
        }
        try {
            String bootId = new String(
                    Files.readAllBytes(BOOT_ID), StandardCharsets.UTF_8)
                    .trim();
            if (!bootId.matches("[0-9a-f-]{36}")) {
                return "status=fail reason=boot-id";
            }
            return "status=pass uid=2000 boot_id=" + bootId +
                    " resukisu_active=" + (isReSukiSuActive() ? "1" : "0");
        } catch (Exception exception) {
            return "status=fail reason=" +
                    exception.getClass().getSimpleName();
        }
    }

    private static boolean isReSukiSuActive() throws Exception {
        java.lang.Process process = new ProcessBuilder(
                "/data/local/tmp/lp3-resukisu-ksud", "debug", "version")
                .redirectErrorStream(true)
                .start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            byte[] buffer = new byte[1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > 4096) {
                    process.destroyForcibly();
                    return false;
                }
                output.write(buffer, 0, count);
            }
        }
        return process.waitFor() == 0 &&
                "Kernel Version: 35088".equals(
                        output.toString(StandardCharsets.UTF_8.name()).trim());
    }

    @Override
    public String startReSukiSuActivation(String nonce, int managerUid) {
        if (activationController == null) {
            return "status=fail reason=service-context";
        }
        return activationController.start(nonce, managerUid);
    }

    @Override
    public String prepareReSukiSuActivation(String nonce, int managerUid) {
        if (activationController == null) {
            return "status=fail reason=service-context";
        }
        return activationController.prepare(nonce, managerUid);
    }

    @Override
    public String releasePreparedActivation(String nonce) {
        if (activationController == null) {
            return "status=fail reason=service-context";
        }
        return activationController.releasePrepared(nonce);
    }

    @Override
    public String getActivationSnapshot(String nonce) {
        if (activationController == null) {
            return "status=fail reason=service-context";
        }
        return activationController.snapshot(nonce);
    }

    @Override
    public String recoverStaleActivation(String session, String bootId) {
        if (activationController == null) {
            return "status=fail reason=service-context";
        }
        return activationController.recoverStaleActivation(session, bootId);
    }

    @Override
    public void destroy() {
        System.exit(0);
    }
}
